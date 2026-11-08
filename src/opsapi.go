package main

/*
	opsapi.go

	Admin APIs for the per rule "ops" options (mod/dynamicproxy/ops_config.go):
	error pages, static responses, CORS and the bandwidth limit.

	GET  /api/proxy/ops/get?ep=<rule>              -> OpsConfig ({} when unset) + the global error page default
	POST /api/proxy/ops/set  ep, config (JSON)      -> validate, apply, persist
	GET  /api/proxy/ops/globalerrors                -> global default error pages
	POST /api/proxy/ops/globalerrors  config (JSON) -> set (Mode "on" activates, anything else disables)
	POST /api/proxy/ops/errorpreview template, status -> {"html": "..."} rendered with sample data
*/

import (
	"encoding/json"
	"net/http"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/rewrite"
	"imuslab.com/zoraxy/mod/utils"
)

func RegisterOpsAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/proxy/ops/get", HandleOpsGet)
	authRouter.HandleFunc("/api/proxy/ops/set", HandleOpsSet)
	authRouter.HandleFunc("/api/proxy/ops/globalerrors", HandleOpsGlobalErrors)
	authRouter.HandleFunc("/api/proxy/ops/errorpreview", HandleOpsErrorPreview)
}

// initOpsGlobals loads the global error page default and wires {{external_ip}}
func initOpsGlobals() {
	if sysdb != nil {
		cfg := &dynamicproxy.ErrorPagesConfig{}
		var raw string
		if sysdb.Read("settings", "globalErrorPages", &raw) == nil && raw != "" && json.Unmarshal([]byte(raw), cfg) == nil {
			if err := dynamicproxy.SetGlobalErrorPages(cfg); err != nil {
				SystemWideLogger.Println("Ignoring invalid global error page config: " + err.Error())
			}
		}
	}
	rewrite.SetExternalIPProvider(func() string {
		if dynamicProxyRouter == nil || dynamicProxyRouter.Option.AccessController == nil {
			return ""
		}
		ip := dynamicProxyRouter.Option.AccessController.ServerPublicIP
		if ip == "127.0.0.1" {
			return "" //public IP check disabled or not resolved yet
		}
		return ip
	})
}

func HandleOpsGet(w http.ResponseWriter, r *http.Request) {
	ep, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	target, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	ops := target.Ops
	if ops == nil {
		ops = &dynamicproxy.OpsConfig{}
	}
	js, _ := json.Marshal(map[string]interface{}{"Ops": ops, "GlobalErrorPages": dynamicproxy.GetGlobalErrorPages()})
	utils.SendJSONResponse(w, string(js))
}

func HandleOpsSet(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config not given")
		return
	}
	cfg := &dynamicproxy.OpsConfig{}
	if err := json.Unmarshal([]byte(raw), cfg); err != nil {
		utils.SendErrorResponse(w, "Invalid config: "+err.Error())
		return
	}
	if err := cfg.Validate(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		e.Ops = cfg
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleOpsGlobalErrors(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		raw, err := utils.PostPara(r, "config")
		if err != nil {
			utils.SendErrorResponse(w, "config not given")
			return
		}
		cfg := &dynamicproxy.ErrorPagesConfig{}
		if err := json.Unmarshal([]byte(raw), cfg); err != nil {
			utils.SendErrorResponse(w, "Invalid config: "+err.Error())
			return
		}
		if err := dynamicproxy.SetGlobalErrorPages(cfg); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		sysdb.Write("settings", "globalErrorPages", raw)
		utils.SendOK(w)
		return
	}
	cfg := dynamicproxy.GetGlobalErrorPages()
	if cfg == nil {
		cfg = &dynamicproxy.ErrorPagesConfig{Mode: dynamicproxy.ErrorPagesOff, Statuses: []int{502, 503, 504}}
	}
	js, _ := json.Marshal(cfg)
	utils.SendJSONResponse(w, string(js))
}

func HandleOpsErrorPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	tpl, _ := utils.PostPara(r, "template")
	status, _ := utils.PostInt(r, "status")
	if status < 400 || status > 599 {
		status = 502
	}
	out, err := dynamicproxy.RenderErrorPagePreview(tpl, status)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	js, _ := json.Marshal(map[string]string{"html": out})
	utils.SendJSONResponse(w, string(js))
}
