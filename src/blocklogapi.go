package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Blocked requests API (what Zoraxy rejected, and why)

	GET  /api/blocked/overview   filters + before,limit   summary + one page of entries (one request for the page)
	GET  /api/blocked/summary    filters                  counts by reason, top IPs / hosts / paths, hourly series
	GET  /api/blocked/list       filters + before,limit   entries, newest first (before = seq of the last entry seen)
	GET  /api/blocked/settings
	POST /api/blocked/settings   JSON {Enabled:bool}
	POST /api/blocked/clear      confirm=yes

	GET  /api/blocked/lookup     ref | ip              find by the reference ID the visitor saw, or by address (blocklogfix.go)
	GET  /api/blocked/explain    seq | ref             plain text, rule link and the fixes that can be offered
	POST /api/blocked/fix        seq, fixId, previewId apply one previewed fix (admin only), answers an undo token
	POST /api/blocked/undo       undoToken             put the previous value back (admin only)

	Filters: reason (see blocklog.Reasons), host, ip, ref, q (search), since (hours back, 0 = all)
	The log is bounded (last 2000 entries) and honours the statistics exclusion list, "exclude blocked
	requests" and the per rule "disable statistics collection"; query strings are only kept when the
	visitor list keeps them (Visitors > settings).
*/

const blockLogSettingsTable = "blocklog"

// initBlockLog creates the blocked-request log (conf/blocked.json.gz) and connects it to the statistics filters
func initBlockLog() {
	if sysdb == nil {
		return
	}
	sysdb.NewTable(blockLogSettingsTable)
	s := blocklog.DefaultSettings()
	if sysdb.KeyExists(blockLogSettingsTable, "settings") {
		sysdb.Read(blockLogSettingsTable, "settings", &s)
	}
	blockLog = blocklog.New(CONF_FOLDER+"/blocked.json.gz", blocklog.DefaultCapacity, s)
	if statisticCollector != nil {
		blockLog.SetExcluder(statisticCollector.ExcludesIP)
		blockLog.SetExcludeBlocked(statisticCollector.ExcludesBlocked)
	}
	blockLog.Start()
}

func blockLogReady(w http.ResponseWriter) bool {
	if blockLog == nil {
		utils.SendErrorResponse(w, "the blocked request log is not available")
		return false
	}
	return true
}

func parseBlockFilter(w http.ResponseWriter, r *http.Request) (blocklog.Filter, bool) {
	q := r.URL.Query()
	f := blocklog.Filter{Q: strings.TrimSpace(q.Get("q"))}
	bad := func(msg string) (blocklog.Filter, bool) {
		utils.SendErrorResponse(w, msg)
		return f, false
	}
	if len(f.Q) > 100 {
		return bad("search text too long")
	}
	if rf := strings.TrimSpace(q.Get("ref")); rf != "" {
		if blocklog.NormalizeRef(rf) == "" {
			return bad("invalid ref")
		}
		f.Ref = rf
	}
	if rs := q.Get("reason"); rs != "" {
		known := false
		for _, ri := range blocklog.Reasons() {
			if ri.Key == rs {
				known = true
			}
		}
		if !known {
			return bad("invalid reason")
		}
		f.Reason = rs
	}
	if h := strings.ToLower(strings.TrimSpace(q.Get("host"))); h != "" {
		if !hostNameRe.MatchString(h) {
			return bad("invalid host")
		}
		f.Host = h
	}
	if ip := strings.TrimSpace(q.Get("ip")); ip != "" {
		n, ok := validIPParam(w, ip)
		if !ok {
			return f, false
		}
		f.IP = n
	}
	hours, err := intParam(r, "since", 0, 0, 24*3650)
	if err != nil {
		return bad("invalid since")
	}
	if hours > 0 {
		f.Since = time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	}
	return f, true
}

func blockPage(w http.ResponseWriter, r *http.Request) (before uint64, limit int, ok bool) {
	limit, err := intParam(r, "limit", 100, 1, 500)
	if err != nil {
		utils.SendErrorResponse(w, "invalid limit")
		return 0, 0, false
	}
	b, err := intParam(r, "before", 0, 0, int(^uint32(0)>>1))
	if err != nil {
		utils.SendErrorResponse(w, "invalid before")
		return 0, 0, false
	}
	return uint64(b), limit, true
}

type blockSummaryOut struct {
	blocklog.Summary
	ReasonInfo []blocklog.ReasonInfo `json:"reasonInfo"`
}

func HandleBlockedSummary(w http.ResponseWriter, r *http.Request) {
	if !blockLogReady(w) {
		return
	}
	f, ok := parseBlockFilter(w, r)
	if !ok {
		return
	}
	visitorJSON(w, blockSummaryOut{blockLog.Summarize(f, time.Now()), blocklog.Reasons()})
}

func HandleBlockedList(w http.ResponseWriter, r *http.Request) {
	if !blockLogReady(w) {
		return
	}
	f, ok := parseBlockFilter(w, r)
	if !ok {
		return
	}
	before, limit, ok := blockPage(w, r)
	if !ok {
		return
	}
	visitorJSON(w, blockLog.List(f, before, limit))
}

// HandleBlockedOverview answers the summary and the first page of entries in one response
func HandleBlockedOverview(w http.ResponseWriter, r *http.Request) {
	if !blockLogReady(w) {
		return
	}
	f, ok := parseBlockFilter(w, r)
	if !ok {
		return
	}
	before, limit, ok := blockPage(w, r)
	if !ok {
		return
	}
	visitorJSON(w, map[string]interface{}{
		"Summary": blockSummaryOut{blockLog.Summarize(f, time.Now()), blocklog.Reasons()},
		"List":    blockLog.List(f, before, limit),
	})
}

func HandleBlockedSettings(w http.ResponseWriter, r *http.Request) {
	if !blockLogReady(w) {
		return
	}
	if r.Method == http.MethodPost {
		var s blocklog.Settings
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			utils.SendErrorResponse(w, "invalid JSON body")
			return
		}
		blockLog.SetEnabled(s.Enabled)
		if err := sysdb.Write(blockLogSettingsTable, "settings", s); err != nil {
			utils.SendErrorResponse(w, "unable to save the settings")
			return
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	visitorJSON(w, blocklog.Settings{Enabled: blockLog.Enabled()})
}

func HandleBlockedClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !blockLogReady(w) {
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		utils.SendErrorResponse(w, "confirmation missing")
		return
	}
	blockLog.Clear()
	utils.SendOK(w)
}

// RegisterBlockedAPIs registers the blocked request endpoints
func RegisterBlockedAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/blocked/overview", HandleBlockedOverview)
	authRouter.HandleFunc("/api/blocked/summary", HandleBlockedSummary)
	authRouter.HandleFunc("/api/blocked/list", HandleBlockedList)
	authRouter.HandleFunc("/api/blocked/settings", HandleBlockedSettings)
	authRouter.HandleFunc("/api/blocked/clear", HandleBlockedClear)
	registerBlockedFixAPIs(authRouter)
}
