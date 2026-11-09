package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	wafapi.go

	Management APIs for the Web Application Firewall (Coraza + OWASP CRS).
	The WAF itself lives in mod/dynamicproxy/waf and is configured per
	proxy endpoint (ProxyEndpoint.WAF).
*/

const WAF_LOG_PREFIX = "zr-waf"

// initWAFAuditLog sends WAF events as JSON lines to <log folder>/zr-waf_YYYY-M.log,
// rotated with the same options as the system wide log.
func initWAFAuditLog() {
	if !*enableLog {
		return
	}
	wl, err := logger.NewLogger(WAF_LOG_PREFIX, *path_logFile)
	if err != nil {
		SystemWideLogger.PrintAndLog("waf", "Unable to open WAF audit log, events are kept in memory only", err)
		return
	}
	if SystemWideLogger != nil && SystemWideLogger.RotateOption != nil {
		wl.SetRotateOption(SystemWideLogger.RotateOption)
	}
	waf.Default.SetAuditSink(wl)
}

func RegisterWAFAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/waf/set", HandleWAFSet)
	authRouter.HandleFunc("/api/waf/validate", HandleWAFValidate)
	authRouter.HandleFunc("/api/waf/events", HandleWAFEvents)
	authRouter.HandleFunc("/api/waf/stats", HandleWAFStats)
	authRouter.HandleFunc("/api/waf/exclude", HandleWAFExclude)
	RegisterWAFCentralAPIs(authRouter)
	RegisterWAFResponseAPIs(authRouter)
}

func parseWAFConfig(r *http.Request) (*waf.Config, error) {
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		return nil, err
	}
	cfg := &waf.Config{}
	if err := json.Unmarshal([]byte(raw), cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// HandleWAFSet sets the WAF config of an endpoint. POST rootname, config (JSON)
func HandleWAFSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	ep, err := utils.PostPara(r, "rootname")
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	cfg, err := parseWAFConfig(r)
	if err != nil {
		utils.SendErrorResponse(w, "Invalid config: "+err.Error())
		return
	}
	err = applyWAFEndpoint(ep, func(e *dynamicproxy.ProxyEndpoint, _ *waf.State) error {
		e.WAF = cfg
		e.WAFSource = waf.SourceCustom
		e.WAFProfile = ""
		return nil
	})
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleWAFValidate compiles a config without applying it. POST config (JSON)
func HandleWAFValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	cfg, err := parseWAFConfig(r)
	if err != nil {
		utils.SendErrorResponse(w, "Invalid config: "+err.Error())
		return
	}
	if err := waf.Default.Validate(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleWAFEvents lists recent events across all endpoints, newest first.
// GET limit, endpoint, rule, action (blocked|detected|stripped), ip, since, kind (request|response), group (unix seconds or RFC3339)
func HandleWAFEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	f := waf.EventFilter{Limit: limit, Endpoint: q.Get("endpoint"), Action: q.Get("action"), ClientIP: q.Get("ip")}
	if rule := strings.TrimSpace(q.Get("rule")); rule != "" {
		id, err := strconv.Atoi(rule)
		if err != nil {
			utils.SendErrorResponse(w, "invalid rule filter")
			return
		}
		f.RuleID = id
	}
	f.Since = parseSince(q.Get("since"))
	f.Kind, f.Group = q.Get("kind"), q.Get("group") // response inspection filters
	js, _ := json.Marshal(waf.Default.QueryEvents(f))
	utils.SendJSONResponse(w, string(js))
}

func parseSince(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0)
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	return time.Time{}
}

// HandleWAFStats returns counters per rule and per endpoint
func HandleWAFStats(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(waf.Default.Stats())
	utils.SendJSONResponse(w, string(js))
}

// HandleWAFExclude adds an exclusion for a rule. POST ruleid, path (optional),
// exact (optional), scope: "endpoint" (default, needs rootname; with a path it is
// a path exclusion) or "global" (policy wide; with a path it is a path exclusion).
func HandleWAFExclude(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	ruleID, err := utils.PostPara(r, "ruleid")
	if err != nil {
		utils.SendErrorResponse(w, "Rule ID not defined")
		return
	}
	scope, _ := utils.PostPara(r, "scope")
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope != "" && scope != "global" && scope != "endpoint" && scope != "path" {
		utils.SendErrorResponse(w, "invalid scope")
		return
	}
	ep, _ := utils.PostPara(r, "rootname")
	if scope != "global" && ep == "" {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	path, _ := utils.PostPara(r, "path")
	path = strings.TrimSpace(path)
	if scope == "path" && path == "" {
		utils.SendErrorResponse(w, "path not defined")
		return
	}
	exact, _ := utils.PostBool(r, "exact")
	if err := addWAFExclusion(scope, ep, ruleID, path, exact); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
