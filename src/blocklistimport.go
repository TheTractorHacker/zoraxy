package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/access/blocklistimport"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	blocklistimport.go

	Admin API for importing IP / CIDR lists into an access rule's blacklist or
	whitelist (issue upstream #512 / #661). See mod/access/blocklistimport.

	POST /api/access/import/preview   dry run, returns the validation report
	POST /api/access/import/apply     import
	GET  /api/access/import/sources   list URL sources
	POST /api/access/import/source/add | update | refresh | remove

	Input of preview / apply: id (access rule, default "default"), list
	(blacklist | whitelist), one of text (pasted), file (multipart upload) or
	url (https only, SSRF protected), optional comment.
*/

var blocklistImporter *blocklistimport.Manager

const blocklistImportMaxUpload = 32 << 20

// RegisterBlocklistImportAPIs creates the source manager (starting the
// scheduler) and registers the admin APIs
func RegisterBlocklistImportAPIs(authRouter *auth.RouterDef) {
	mgr, err := blocklistimport.NewManager(filepath.Join(CONF_FOLDER, "blocklist_sources.json"), accessController.GetAccessRuleByID)
	if err != nil {
		SystemWideLogger.PrintAndLog("access", "Unable to load blocklist import sources, scheduled refresh disabled", err)
		mgr, _ = blocklistimport.NewManager(filepath.Join(CONF_FOLDER, "blocklist_sources.json.invalid"), accessController.GetAccessRuleByID)
	} else {
		mgr.Start()
	}
	blocklistImporter = mgr

	authRouter.HandleFunc("/api/access/import/preview", func(w http.ResponseWriter, r *http.Request) { handleBlocklistImport(w, r, true) })
	authRouter.HandleFunc("/api/access/import/apply", func(w http.ResponseWriter, r *http.Request) { handleBlocklistImport(w, r, false) })
	authRouter.HandleFunc("/api/access/import/sources", handleBlocklistSources)
	authRouter.HandleFunc("/api/access/import/source/add", handleBlocklistSourceAdd)
	authRouter.HandleFunc("/api/access/import/source/update", handleBlocklistSourceUpdate)
	authRouter.HandleFunc("/api/access/import/source/refresh", handleBlocklistSourceRefresh)
	authRouter.HandleFunc("/api/access/import/source/remove", handleBlocklistSourceRemove)
}

func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		sendErr(w, "POST required")
		return false
	}
	return true
}

// sendErr writes a JSON error response with a properly escaped message
// (error texts from the network stack contain quotes)
func sendErr(w http.ResponseWriter, msg string) {
	js, _ := json.Marshal(map[string]string{"error": msg})
	utils.SendJSONResponse(w, string(js))
}

func sendJSON(w http.ResponseWriter, v any) {
	js, _ := json.Marshal(v)
	utils.SendJSONResponse(w, string(js))
}

func handleBlocklistImport(w http.ResponseWriter, r *http.Request, dryRun bool) {
	if !requirePost(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, blocklistImportMaxUpload+(1<<20))
	//The admin UI posts FormData (multipart). utils.PostPara only reads urlencoded bodies, so parse the
	//multipart form first; its fields then show up in r.Form for PostPara as well.
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			sendErr(w, "invalid upload: "+err.Error())
			return
		}
	}
	ruleID, _ := utils.PostPara(r, "id")
	if ruleID == "" {
		ruleID = "default"
	}
	list, _ := utils.PostPara(r, "list")
	if list != "blacklist" && list != "whitelist" {
		sendErr(w, "list must be blacklist or whitelist")
		return
	}
	rule, err := accessController.GetAccessRuleByID(ruleID)
	if err != nil {
		sendErr(w, err.Error())
		return
	}
	comment, _ := utils.PostPara(r, "comment")

	var src io.Reader
	keepLineComments := true
	rawURL, _ := utils.PostPara(r, "url")
	text := r.PostFormValue("text")
	switch {
	case rawURL != "":
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		body, err := blocklistImporter.Fetcher.Fetch(ctx, rawURL)
		if err != nil {
			sendErr(w, "download failed: "+err.Error())
			return
		}
		defer body.Close()
		src = body
		keepLineComments = false //never keep comments from remote content
	case text != "":
		src = strings.NewReader(text)
	default:
		file, _, ferr := r.FormFile("file")
		if ferr != nil {
			sendErr(w, "no text, file or url given")
			return
		}
		defer file.Close()
		src = io.LimitReader(file, blocklistImportMaxUpload)
	}

	parsed, err := blocklistimport.Parse(src, 0, comment, keepLineComments)
	if err != nil {
		sendErr(w, "import failed: "+err.Error())
		return
	}
	var rep *blocklistimport.Report
	if dryRun {
		rep, err = blocklistimport.Preview(rule, list, parsed, "")
	} else {
		rep, err = blocklistimport.Apply(rule, list, parsed, "")
	}
	if err != nil {
		sendErr(w, err.Error())
		return
	}
	if !dryRun {
		SystemWideLogger.Println("[access] imported " + rep.String() + " into " + list + " of rule " + ruleID)
	}
	sendJSON(w, rep)
}

func handleBlocklistSources(w http.ResponseWriter, r *http.Request) {
	ruleID, _ := utils.GetPara(r, "id")
	sendJSON(w, blocklistImporter.List(ruleID))
}

func handleBlocklistSourceAdd(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	ruleID, _ := utils.PostPara(r, "id")
	if ruleID == "" {
		ruleID = "default"
	}
	list, _ := utils.PostPara(r, "list")
	rawURL, _ := utils.PostPara(r, "url")
	name, _ := utils.PostPara(r, "name")
	interval, _ := utils.PostInt(r, "interval")
	enabled, _ := utils.PostBool(r, "enabled")
	src, err := blocklistImporter.Add(blocklistimport.Source{
		Name: name, RuleID: ruleID, List: list, URL: rawURL, IntervalMinutes: interval, Enabled: enabled,
	})
	if err != nil {
		sendErr(w, err.Error())
		return
	}
	//First download right away so the admin sees the result (and any error)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	rep, rerr := blocklistImporter.Refresh(ctx, src.ID)
	cur, _ := blocklistImporter.Get(src.ID)
	out := map[string]any{"source": cur, "report": rep}
	if rerr != nil {
		out["refreshError"] = rerr.Error()
	}
	sendJSON(w, out)
}

func handleBlocklistSourceUpdate(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	id, err := utils.PostPara(r, "sid")
	if err != nil {
		sendErr(w, "source id missing")
		return
	}
	interval, _ := utils.PostInt(r, "interval")
	enabled, _ := utils.PostBool(r, "enabled")
	name, _ := utils.PostPara(r, "name")
	if err := blocklistImporter.Update(id, interval, enabled, name); err != nil {
		sendErr(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func handleBlocklistSourceRefresh(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	id, err := utils.PostPara(r, "sid")
	if err != nil {
		sendErr(w, "source id missing")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	rep, err := blocklistImporter.Refresh(ctx, id)
	if err != nil {
		sendErr(w, err.Error())
		return
	}
	sendJSON(w, rep)
}

func handleBlocklistSourceRemove(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	id, err := utils.PostPara(r, "sid")
	if err != nil {
		sendErr(w, "source id missing")
		return
	}
	removeEntries, _ := utils.PostBool(r, "removeEntries")
	n, err := blocklistImporter.Remove(id, removeEntries)
	if err != nil {
		sendErr(w, err.Error())
		return
	}
	sendJSON(w, map[string]int{"removedEntries": n})
}
