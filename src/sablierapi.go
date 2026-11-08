package main

/*
	sablierapi.go

	Admin APIs for the per rule Sablier (scale-to-zero) gate (mod/sablier, mod/dynamicproxy/sablier_gate.go).

	GET  /api/proxy/sablier/get?ep=<rule>           -> SablierConfig ({} when unset)
	POST /api/proxy/sablier/set  ep, config (JSON)   -> validate, apply, persist
	POST /api/proxy/sablier/test config (JSON)       -> ask the Sablier server once and report ready / waiting page / error.
	                                                   Note: this really requests a session, so it starts the workload.
*/

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/sablier"
	"imuslab.com/zoraxy/mod/utils"
)

func RegisterSablierAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/proxy/sablier/get", HandleSablierGet)
	authRouter.HandleFunc("/api/proxy/sablier/set", HandleSablierSet)
	authRouter.HandleFunc("/api/proxy/sablier/test", HandleSablierTest)
}

func HandleSablierGet(w http.ResponseWriter, r *http.Request) {
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
	sc := target.Sablier
	if sc == nil {
		sc = &dynamicproxy.SablierConfig{}
	}
	js, _ := json.Marshal(sc)
	utils.SendJSONResponse(w, string(js))
}

func parseSablierConfig(w http.ResponseWriter, r *http.Request) (*dynamicproxy.SablierConfig, bool) {
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config not given")
		return nil, false
	}
	cfg := &dynamicproxy.SablierConfig{}
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

func HandleSablierSet(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	cfg, ok := parseSablierConfig(w, r)
	if !ok {
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		if !cfg.Enabled && cfg.URL == "" {
			e.Sablier = nil
		} else {
			e.Sablier = cfg
		}
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleSablierTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	cfg, ok := parseSablierConfig(w, r)
	if !ok {
		return
	}
	g, err := sablier.New(cfg.Config)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	start := time.Now()
	out, err := g.Check(ctx)
	res := map[string]interface{}{"URL": cfg.Config.RequestURL(), "DurationMs": time.Since(start).Milliseconds()}
	switch {
	case err != nil:
		res["Result"] = "error"
		res["Message"] = err.Error()
	case out.Ready:
		res["Result"] = "ready"
	default:
		res["Result"] = "waiting"
		res["Status"] = out.Status
		res["ContentType"] = out.Type
		res["BodyBytes"] = len(out.Body)
	}
	js, _ := json.Marshal(res)
	utils.SendJSONResponse(w, string(js))
}
