package main

/*
	zrokapi.go

	Optional zrok tunnels (fork #63 / upstream #136), the zrok counterpart of the ZeroTier helper of the docker image.
	Logic in mod/zrok: it supervises the external zrok CLI, so everything is refused unless Zoraxy was started with
	-allow_external_tools (same philosophy as -allow_hook_commands).

	GET  /api/zrok/status            flag state, binary, version, settings (token never returned), tunnels with runtime state
	GET  /api/zrok/logs?id=          captured, redacted output of a tunnel
	GET  /api/zrok/targets           suggested backend targets (the proxy listener, proxy rule upstreams)
	POST /api/zrok/settings          binary, flavor, apiendpoint, token (empty = keep), cleartoken=true
	POST /api/zrok/enable            zrok enable with the stored token
	POST /api/zrok/disable           stop all tunnels and zrok disable
	POST /api/zrok/tunnel/save       tunnel (JSON, empty ID = new)
	POST /api/zrok/tunnel/delete|start|stop   id
*/

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/utils"
	"imuslab.com/zoraxy/mod/zrok"
)

var allowExternalTools = flag.Bool("allow_external_tools", false, "Allow Zoraxy to run external helper programs it supervises (currently: the zrok CLI for the Tunnels (zrok) page). Executing a binary is a privilege: off by default")

var zrokMgr *zrok.Manager

// initZrok opens the zrok state and starts the auto start tunnels. It never fails startup.
func initZrok() {
	m, err := zrok.Open(filepath.Join(CONF_FOLDER, "zrok"), *allowExternalTools, func(msg string, err error) {
		SystemWideLogger.PrintAndLog("zrok", msg, err)
	})
	if err != nil {
		SystemWideLogger.PrintAndLog("zrok", "Unable to open the zrok state, tunnels are unavailable", err)
		return
	}
	zrokMgr = m
	if *allowExternalTools {
		go m.StartAuto()
	}
}

func stopZrok() {
	if zrokMgr != nil {
		zrokMgr.Close()
	}
}

func RegisterZrokAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/zrok/status", HandleZrokStatus)
	authRouter.HandleFunc("/api/zrok/logs", HandleZrokLogs)
	authRouter.HandleFunc("/api/zrok/targets", HandleZrokTargets)
	authRouter.HandleFunc("/api/zrok/settings", HandleZrokSettings)
	authRouter.HandleFunc("/api/zrok/enable", HandleZrokEnable)
	authRouter.HandleFunc("/api/zrok/disable", HandleZrokDisable)
	authRouter.HandleFunc("/api/zrok/tunnel/save", HandleZrokTunnelSave)
	authRouter.HandleFunc("/api/zrok/tunnel/delete", HandleZrokTunnelAction)
	authRouter.HandleFunc("/api/zrok/tunnel/start", HandleZrokTunnelAction)
	authRouter.HandleFunc("/api/zrok/tunnel/stop", HandleZrokTunnelAction)
}

func zrokReady(w http.ResponseWriter) bool {
	if zrokMgr == nil {
		utils.SendErrorResponse(w, "zrok state is not available")
		return false
	}
	return true
}

func zrokMutating(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return false
	}
	if !zrokReady(w) {
		return false
	}
	if !zrokMgr.Allowed() {
		utils.SendErrorResponse(w, "Running external tools is disabled. Start Zoraxy with -allow_external_tools to use zrok.")
		return false
	}
	return true
}

func HandleZrokStatus(w http.ResponseWriter, r *http.Request) {
	if !zrokReady(w) {
		return
	}
	s := zrokMgr.Settings()
	out := map[string]interface{}{
		"Allowed":  zrokMgr.Allowed(),
		"Settings": s,
		"TokenSet": zrokMgr.TokenSet(),
		"Tunnels":  zrokMgr.Status(),
	}
	if bin, err := zrokMgr.Binary(); err == nil {
		out["Binary"] = bin
		out["Flavor"] = zrok.FlavorFor(s.Flavor, bin)
		if zrokMgr.Allowed() {
			ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
			out["Version"] = zrokMgr.Version(ctx)
			cancel()
		}
	} else {
		out["BinaryError"] = err.Error()
	}
	js, _ := json.Marshal(out)
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(js))
}

func HandleZrokLogs(w http.ResponseWriter, r *http.Request) {
	if !zrokReady(w) {
		return
	}
	id, _ := utils.GetPara(r, "id")
	js, _ := json.Marshal(zrokMgr.Logs(id))
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(js))
}

func HandleZrokTargets(w http.ResponseWriter, r *http.Request) {
	type target struct{ Label, Value string }
	out := []target{}
	if dynamicProxyRouter != nil {
		scheme := "http"
		if dynamicProxyRouter.Option.UseTls {
			scheme = "https"
		}
		out = append(out, target{"Zoraxy proxy listener (all rules, routed by Host)", scheme + "://127.0.0.1:" + strconv.Itoa(dynamicProxyRouter.Option.Port)})
		for name, ep := range dynamicProxyRouter.GetProxyEndpointsAsMap() {
			for _, o := range ep.ActiveOrigins {
				origin := o.OriginIpOrDomain
				sch := "http://"
				if o.RequireTLS {
					sch = "https://"
				}
				out = append(out, target{"Rule " + name + " upstream", sch + origin})
				break
			}
		}
	}
	js, _ := json.Marshal(out)
	utils.SendJSONResponse(w, string(js))
}

func HandleZrokSettings(w http.ResponseWriter, r *http.Request) {
	if !zrokMutating(w, r) {
		return
	}
	cur := zrokMgr.Settings()
	if v, err := utils.PostPara(r, "binary"); err == nil {
		cur.BinaryPath = v
	}
	if v, err := utils.PostPara(r, "flavor"); err == nil {
		cur.Flavor = v
	}
	if v, err := utils.PostPara(r, "apiendpoint"); err == nil {
		cur.ApiEndpoint = v
	}
	if err := zrokMgr.SetSettings(cur); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if clear, _ := utils.PostBool(r, "cleartoken"); clear {
		if err := zrokMgr.SetToken(""); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
	} else if tok, err := utils.PostPara(r, "token"); err == nil && tok != "" {
		if err := zrokMgr.SetToken(tok); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
	}
	utils.SendOK(w)
}

func HandleZrokEnable(w http.ResponseWriter, r *http.Request) {
	if !zrokMutating(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	out, err := zrokMgr.Enable(ctx)
	if err != nil {
		utils.SendErrorResponse(w, err.Error()+": "+out)
		return
	}
	js, _ := json.Marshal(map[string]string{"Output": out})
	utils.SendJSONResponse(w, string(js))
}

func HandleZrokDisable(w http.ResponseWriter, r *http.Request) {
	if !zrokMutating(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if out, err := zrokMgr.Disable(ctx); err != nil {
		utils.SendErrorResponse(w, err.Error()+": "+out)
		return
	}
	utils.SendOK(w)
}

func HandleZrokTunnelSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !zrokReady(w) {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	raw, err := utils.PostPara(r, "tunnel")
	if err != nil {
		utils.SendErrorResponse(w, "tunnel not given")
		return
	}
	t := zrok.Tunnel{}
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		utils.SendErrorResponse(w, "Invalid tunnel: "+err.Error())
		return
	}
	saved, err := zrokMgr.SaveTunnel(t)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	js, _ := json.Marshal(saved)
	utils.SendJSONResponse(w, string(js))
}

func HandleZrokTunnelAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !zrokReady(w) {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	id, _ := utils.PostPara(r, "id")
	var err error
	switch filepath.Base(r.URL.Path) {
	case "delete":
		err = zrokMgr.DeleteTunnel(id)
	case "start":
		err = zrokMgr.Start(id)
	case "stop":
		zrokMgr.Stop(id)
	}
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
