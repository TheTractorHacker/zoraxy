package main

/*
	scriptapi.go

	Admin APIs for the per rule Lua script handler / hook (mod/dynamicproxy/script_handler.go, sandbox in mod/luascript).
	Admin only: viewers cannot call anything below /api/proxy/script/ (the source may contain secrets).

	GET  /api/proxy/script/get?ep=<rule>                 -> ScriptConfig ({} when unset) + sandbox limits
	POST /api/proxy/script/set  ep, config (JSON)         -> validate (compiles the script), apply, persist
	POST /api/proxy/script/test ep, config (JSON), sample (JSON {Method,Path,Query,Host,ClientIP,Body,Headers})
	                                                      -> run once in the sandbox against the sample request, nothing is saved
*/

import (
	"encoding/json"
	"net/http"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/luascript"
	"imuslab.com/zoraxy/mod/utils"
)

func RegisterScriptAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/proxy/script/get", HandleScriptGet)
	authRouter.HandleFunc("/api/proxy/script/set", HandleScriptSet)
	authRouter.HandleFunc("/api/proxy/script/test", HandleScriptTest)
}

func HandleScriptGet(w http.ResponseWriter, r *http.Request) {
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
	sc := target.Script
	if sc == nil {
		sc = &dynamicproxy.ScriptConfig{Mode: dynamicproxy.ScriptModeHandler}
	}
	js, _ := json.Marshal(map[string]interface{}{
		"Script": sc,
		"Limits": map[string]int{
			"DefaultTimeoutMs": int(luascript.DefaultTimeout.Milliseconds()), "MaxTimeoutMs": int(luascript.MaxTimeout.Milliseconds()),
			"DefaultResponseKB": luascript.DefaultMaxResponse / 1024, "MaxResponseKB": luascript.MaxMaxResponse / 1024,
			"MaxSourceKB": luascript.MaxSourceBytes / 1024, "DefaultConcurrency": luascript.DefaultConcurrency, "MaxConcurrency": luascript.MaxConcurrency,
		},
	})
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(js))
}

func parseScriptConfig(w http.ResponseWriter, r *http.Request) (*dynamicproxy.ScriptConfig, bool) {
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config not given")
		return nil, false
	}
	cfg := &dynamicproxy.ScriptConfig{}
	if err := json.Unmarshal([]byte(raw), cfg); err != nil {
		utils.SendErrorResponse(w, "Invalid config: "+err.Error())
		return nil, false
	}
	if err := cfg.Validate(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return nil, false
	}
	return cfg, true
}

func HandleScriptSet(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	cfg, ok := parseScriptConfig(w, r)
	if !ok {
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		if !cfg.Enabled && cfg.Code == "" {
			e.Script = nil
		} else {
			e.Script = cfg
		}
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleScriptTest(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	cfg, ok := parseScriptConfig(w, r)
	if !ok {
		return
	}
	sample := dynamicproxy.ScriptTestRequest{}
	if raw, err := utils.PostPara(r, "sample"); err == nil && raw != "" {
		if err := json.Unmarshal([]byte(raw), &sample); err != nil {
			utils.SendErrorResponse(w, "Invalid sample request: "+err.Error())
			return
		}
	}
	res := dynamicproxy.RunScriptTest(cfg, ep, sample)
	js, _ := json.Marshal(res)
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(js))
}
