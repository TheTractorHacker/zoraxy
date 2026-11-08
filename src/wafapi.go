package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

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

// applyWAFConfig replaces the WAF config of an endpoint at runtime and persists it.
// Compilation errors (including custom rule syntax errors) reject the change.
func applyWAFConfig(rootNameOrMatchingDomain string, mutate func(old *waf.Config) (*waf.Config, error)) error {
	target, err := dynamicProxyRouter.LoadProxy(rootNameOrMatchingDomain)
	if err != nil {
		return err
	}
	updated := dynamicproxy.CopyEndpoint(target)
	newCfg, err := mutate(updated.WAF)
	if err != nil {
		return err
	}
	updated.WAF = newCfg
	ready, err := dynamicProxyRouter.PrepareProxyRoute(updated)
	if err != nil {
		return err
	}
	target.Remove()
	loadBalancer.ResetSessions()
	dynamicProxyRouter.AddProxyRouteToRuntime(ready)
	SaveReverseProxyConfig(updated)
	return nil
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
	if err := applyWAFConfig(ep, func(*waf.Config) (*waf.Config, error) { return cfg, nil }); err != nil {
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

// HandleWAFEvents lists recent events, newest first. GET limit, endpoint
func HandleWAFEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	js, _ := json.Marshal(waf.Default.RecentEvents(limit, r.URL.Query().Get("endpoint")))
	utils.SendJSONResponse(w, string(js))
}

// HandleWAFStats returns counters per rule and per endpoint
func HandleWAFStats(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(waf.Default.Stats())
	utils.SendJSONResponse(w, string(js))
}

// HandleWAFExclude adds an exclusion for a rule, either for one path or the
// whole endpoint. POST rootname, ruleid, path (optional, empty = whole endpoint)
func HandleWAFExclude(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	ep, err := utils.PostPara(r, "rootname")
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	ruleID, err := utils.PostPara(r, "ruleid")
	if err != nil {
		utils.SendErrorResponse(w, "Rule ID not defined")
		return
	}
	path, _ := utils.PostPara(r, "path")
	path = strings.TrimSpace(path)
	exact, _ := utils.PostBool(r, "exact")

	err = applyWAFConfig(ep, func(old *waf.Config) (*waf.Config, error) {
		var cfg waf.Config
		if old != nil {
			cfg = *old
		}
		if path == "" {
			cfg.ExcludedRuleIDs = append(cfg.ExcludedRuleIDs, ruleID)
		} else {
			cfg.PathExclusions = append(cfg.PathExclusions, waf.PathExclusion{Path: path, Exact: exact, RuleIDs: []string{ruleID}})
		}
		return &cfg, nil
	})
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
