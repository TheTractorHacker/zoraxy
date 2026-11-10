package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/ruleset"
)

/*
	Rules engine API (admin, cookie + CSRF). The engine itself is mod/ruleset; the proxy hook is
	mod/dynamicproxy/ruleset_hook.go. Rules live in conf/ruleset/ (Fleet scope "ruleset").

	site: "" is the global rule set (runs first for every site), "_default_site" is the default site (root
	endpoint), anything else is the key of a proxy rule (its matching domain).

	GET  /api/ruleset/meta                  fields, operators, actions, limits, sites (everything the builder needs)
	GET  /api/ruleset/rules?site=           the rules of one set in evaluation order, with tree, warnings, errors, counters
	GET  /api/ruleset/rule?site=&id=        one rule
	POST /api/ruleset/rule/create           {site, position?, rule:{name, description, enabled?, dry_run?, expression | tree, action}}
	POST /api/ruleset/rule/update           {site, id, rule}
	POST /api/ruleset/rule/delete           {site, id}
	POST /api/ruleset/rule/reorder          {site, order:[id...]}
	POST /api/ruleset/rule/enable|disable   {site, id}
	POST /api/ruleset/rule/dryrun           {site, id, dry_run}
	GET  /api/ruleset/lists                 named lists
	POST /api/ruleset/list/save             {name, type: ip|string|country, description, items:[...]}
	POST /api/ruleset/list/delete           {name}
	POST /api/ruleset/validate              {expression | tree, action?} -> errors with positions, normalised text and tree, used fields, warnings
	POST /api/ruleset/test                  the request tester, performs no action and counts nothing
	GET  /api/ruleset/stats?site=           overview, counters, recent matches
	GET  /api/ruleset/migrate               read-only proposals converting the existing path / header / bot rules and access lists

	New rules start log-only (dry_run) unless the request says dry_run:false.
	validate, test and migrate share one rate limit (10/s, burst 30).
*/

var (
	rulesEngine     *ruleset.Engine
	rulesEngineOnce sync.Once

	rulesetCheckLimiter = ruleset.NewLimiter(10, 30)
)

// getRulesEngine loads conf/ruleset on first use
func getRulesEngine() *ruleset.Engine {
	rulesEngineOnce.Do(func() {
		e, err := ruleset.Open(CONF_FOLDER + "/ruleset")
		if err != nil && SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("ruleset", "Unable to load the rules, starting without them", err)
		}
		if SystemWideLogger != nil {
			for _, le := range e.LoadErrors {
				SystemWideLogger.PrintAndLog("ruleset", "Skipped a rules file: "+le, nil)
			}
		}
		e.Country = func(ip string) string {
			if geodbStore == nil {
				return ""
			}
			ci, err := geodbStore.ResolveCountryCodeFromIP(ip)
			if err != nil || ci == nil {
				return ""
			}
			return ci.CountryIsoCode
		}
		rulesEngine = e
	})
	return rulesEngine
}

func RegisterRulesetAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/ruleset/meta", HandleRulesetMeta)
	authRouter.HandleFunc("/api/ruleset/rules", HandleRulesetRules)
	authRouter.HandleFunc("/api/ruleset/rule", HandleRulesetRule)
	authRouter.HandleFunc("/api/ruleset/rule/create", HandleRulesetCreate)
	authRouter.HandleFunc("/api/ruleset/rule/update", HandleRulesetUpdate)
	authRouter.HandleFunc("/api/ruleset/rule/delete", HandleRulesetDelete)
	authRouter.HandleFunc("/api/ruleset/rule/reorder", HandleRulesetReorder)
	authRouter.HandleFunc("/api/ruleset/rule/enable", HandleRulesetEnable(true))
	authRouter.HandleFunc("/api/ruleset/rule/disable", HandleRulesetEnable(false))
	authRouter.HandleFunc("/api/ruleset/rule/dryrun", HandleRulesetDryRun)
	authRouter.HandleFunc("/api/ruleset/lists", HandleRulesetLists)
	authRouter.HandleFunc("/api/ruleset/list/save", HandleRulesetListSave)
	authRouter.HandleFunc("/api/ruleset/list/delete", HandleRulesetListDelete)
	authRouter.HandleFunc("/api/ruleset/validate", HandleRulesetValidate)
	authRouter.HandleFunc("/api/ruleset/test", HandleRulesetTest)
	authRouter.HandleFunc("/api/ruleset/stats", HandleRulesetStats)
	authRouter.HandleFunc("/api/ruleset/migrate", HandleRulesetMigrate)
}

// ---- helpers

func rsJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func rsErr(w http.ResponseWriter, code int, msg string) {
	rsJSON(w, code, map[string]string{"error": msg})
}

func rsEngine(w http.ResponseWriter) *ruleset.Engine {
	e := getRulesEngine()
	if e == nil {
		rsErr(w, http.StatusServiceUnavailable, "the rules engine is not available")
	}
	return e
}

func rsMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		rsErr(w, http.StatusMethodNotAllowed, "use "+method)
		return false
	}
	return true
}

// rsDecode reads a bounded JSON body; unknown members are errors so typos do not pass silently
func rsDecode(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if !rsMethod(w, r, http.MethodPost) {
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		rsErr(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return false
	}
	return true
}

func rsFail(w http.ResponseWriter, err error) {
	var ve ruleset.ValidationError
	var nf ruleset.ErrNotFound
	switch {
	case errors.As(err, &ve):
		body := map[string]interface{}{"error": ve.Msg}
		if ve.Err != nil {
			body["detail"] = ve.Err
		}
		rsJSON(w, http.StatusBadRequest, body)
	case errors.As(err, &nf):
		rsErr(w, http.StatusNotFound, nf.Error())
	default:
		rsErr(w, http.StatusInternalServerError, "could not save: "+err.Error())
	}
}

// siteKnown reports whether site can carry rules: the global set, the default site or a proxy rule
func siteKnown(site string) bool {
	if site == "" || site == ruleset.DefaultSiteKey {
		return true
	}
	if dynamicProxyRouter == nil {
		return false
	}
	_, ok := dynamicProxyRouter.ProxyEndpoints.Load(site)
	return ok
}

func rsSite(w http.ResponseWriter, site string, mustExist bool) bool {
	if mustExist && !siteKnown(site) {
		rsErr(w, http.StatusNotFound, "unknown site "+strconv.Quote(site))
		return false
	}
	return true
}

func rsCheckLimit(w http.ResponseWriter) bool {
	if !rulesetCheckLimiter.Allow() {
		w.Header().Set("Retry-After", "1")
		rsErr(w, http.StatusTooManyRequests, "too many requests, slow down")
		return false
	}
	return true
}

func proxyRuleKeys() []string {
	var keys []string
	if dynamicProxyRouter != nil {
		dynamicProxyRouter.ProxyEndpoints.Range(func(k, _ interface{}) bool {
			if s, ok := k.(string); ok {
				keys = append(keys, s)
			}
			return true
		})
	}
	sort.Strings(keys)
	return keys
}

// ---- handlers

type actionParam struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Doc  string `json:"doc"`
}

type actionDoc struct {
	Type        string        `json:"type"`
	Terminating bool          `json:"terminating"`
	Doc         string        `json:"doc"`
	Params      []actionParam `json:"params,omitempty"`
}

func actionDocs() []actionDoc {
	hdr := []actionParam{{"name", "string", "Header name (letters, digits and !#$%&'*+-.^_`|~)"}}
	return []actionDoc{
		{ruleset.ActAllow, true, "Stop evaluating the global and site rules for this request (later rules do not run). The WAF, rate limit, CAPTCHA and authentication still apply, use skip for those.", nil},
		{ruleset.ActBlock, true, "Answer with an error status.", []actionParam{{"status", "int 400-599", "default 403"}, {"body", "string", "plain text answer, default the standard 403 page"}, {"report_abuse", "bool", "count the block towards the automatic ban (default no)"}}},
		{ruleset.ActChallenge, true, "Show the site's CAPTCHA; a solved challenge is remembered in a signed cookie. Without a CAPTCHA provider on the site the request is blocked (fail closed).", []actionParam{{"ttl_minutes", "int 1-1440", "default 30; the longest value of all challenge rules applies"}}},
		{ruleset.ActLog, false, "Only count and record the match.", nil},
		{ruleset.ActSkip, false, "Switch protections off for this request.", []actionParam{{"skip", "array", "any of waf, rate_limit (the proxy rule's limiter), auth, captcha, rules (later rules)"}}},
		{ruleset.ActRateLimit, true, "Token bucket per client address and rule; terminates only when over the limit.", []actionParam{{"rate", "int 1-100000", "requests per second"}, {"burst", "int", "bucket size, default = rate"}, {"status", "int 400-599", "default 429"}}},
		{ruleset.ActRedirect, true, "Redirect with a Location built from a template.", []actionParam{{"status", "int", "301, 302 (default), 303, 307 or 308"}, {"url", "string", "http(s):// URL or a path starting with /; placeholders {host} {path} {query} {uri} {scheme}"}}},
		{ruleset.ActSetReqH, false, "Set a request header before it reaches the upstream.", append(append([]actionParam{}, hdr...), actionParam{"value", "string", "printable ASCII"})},
		{ruleset.ActDelReqH, false, "Remove a request header.", hdr},
		{ruleset.ActSetRespH, false, "Set a response header on what the client receives.", append(append([]actionParam{}, hdr...), actionParam{"value", "string", "printable ASCII"})},
		{ruleset.ActDelRespH, false, "Remove a response header.", hdr},
		{ruleset.ActTag, false, "Add a tag to the request; blocked-request log entries carry it.", []actionParam{{"tag", "string", "1-32 characters: a-z 0-9 _ . : -"}}},
	}
}

func HandleRulesetMeta(w http.ResponseWriter, r *http.Request) {
	if !rsMethod(w, r, http.MethodGet) {
		return
	}
	rsJSON(w, http.StatusOK, map[string]interface{}{
		"fields":      ruleset.Fields(),
		"operators":   ruleset.Operators(),
		"actions":     actionDocs(),
		"skip":        ruleset.SkipTargets(),
		"unavailable": map[string]string{"ip.asn": "the bundled GeoIP database has no ASN data", "ip.city": "the bundled GeoIP database has country data only"},
		"limits": map[string]int{
			"expression_bytes": ruleset.MaxExprLen, "nodes": ruleset.MaxNodes, "depth": ruleset.MaxDepth, "regex_bytes": ruleset.MaxRegexLen,
			"inline_list": ruleset.MaxInlineList, "rules_per_set": ruleset.MaxRulesPerSet, "rules_total": ruleset.MaxRulesTotal,
			"lists": ruleset.MaxLists, "list_items": ruleset.MaxListItems,
		},
		"sites":            proxyRuleKeys(),
		"default_site_key": ruleset.DefaultSiteKey,
		"evaluation_order": []string{"access lists (blacklist / whitelist)", "global rules", "rules of the site", "CORS preflight, path / header / bot rules", "plugins pre_auth", "WAF", "exploit detection", "rate limit", "CAPTCHA", "authentication"},
	})
}

func HandleRulesetRules(w http.ResponseWriter, r *http.Request) {
	if !rsMethod(w, r, http.MethodGet) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	site := r.URL.Query().Get("site")
	rsJSON(w, http.StatusOK, e.Rules(site))
}

func HandleRulesetRule(w http.ResponseWriter, r *http.Request) {
	if !rsMethod(w, r, http.MethodGet) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	ri, ok := e.Get(r.URL.Query().Get("site"), r.URL.Query().Get("id"))
	if !ok {
		rsErr(w, http.StatusNotFound, "rule not found")
		return
	}
	rsJSON(w, http.StatusOK, ri)
}

func HandleRulesetCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Site     string            `json:"site"`
		Position *int              `json:"position"`
		Rule     ruleset.RuleInput `json:"rule"`
	}
	if !rsDecode(w, r, &req) {
		return
	}
	e := rsEngine(w)
	if e == nil || !rsSite(w, req.Site, true) {
		return
	}
	pos := -1
	if req.Position != nil {
		pos = *req.Position
	}
	ri, err := e.Create(req.Site, req.Rule, pos)
	if err != nil {
		rsFail(w, err)
		return
	}
	rsJSON(w, http.StatusCreated, ri)
}

func HandleRulesetUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Site string            `json:"site"`
		ID   string            `json:"id"`
		Rule ruleset.RuleInput `json:"rule"`
	}
	if !rsDecode(w, r, &req) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	ri, err := e.Update(req.Site, req.ID, req.Rule)
	if err != nil {
		rsFail(w, err)
		return
	}
	rsJSON(w, http.StatusOK, ri)
}

type siteID struct {
	Site string `json:"site"`
	ID   string `json:"id"`
}

func HandleRulesetDelete(w http.ResponseWriter, r *http.Request) {
	var req siteID
	if !rsDecode(w, r, &req) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	if err := e.Delete(req.Site, req.ID); err != nil {
		rsFail(w, err)
		return
	}
	rsJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func HandleRulesetReorder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Site  string   `json:"site"`
		Order []string `json:"order"`
	}
	if !rsDecode(w, r, &req) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	if err := e.Reorder(req.Site, req.Order); err != nil {
		rsFail(w, err)
		return
	}
	rsJSON(w, http.StatusOK, e.Rules(req.Site))
}

func HandleRulesetEnable(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req siteID
		if !rsDecode(w, r, &req) {
			return
		}
		e := rsEngine(w)
		if e == nil {
			return
		}
		ri, err := e.SetEnabled(req.Site, req.ID, on)
		if err != nil {
			rsFail(w, err)
			return
		}
		rsJSON(w, http.StatusOK, ri)
	}
}

func HandleRulesetDryRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Site   string `json:"site"`
		ID     string `json:"id"`
		DryRun bool   `json:"dry_run"`
	}
	if !rsDecode(w, r, &req) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	ri, err := e.SetDryRun(req.Site, req.ID, req.DryRun)
	if err != nil {
		rsFail(w, err)
		return
	}
	rsJSON(w, http.StatusOK, ri)
}

func HandleRulesetLists(w http.ResponseWriter, r *http.Request) {
	if !rsMethod(w, r, http.MethodGet) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	type view struct {
		*ruleset.List
		UsedBy []string `json:"used_by"`
	}
	out := []view{}
	for _, l := range e.Lists() {
		out = append(out, view{l, e.ListUsers(l.Name)})
	}
	rsJSON(w, http.StatusOK, out)
}

func HandleRulesetListSave(w http.ResponseWriter, r *http.Request) {
	var l ruleset.List
	if !rsDecode(w, r, &l) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	saved, err := e.SaveList(l)
	if err != nil {
		rsFail(w, err)
		return
	}
	rsJSON(w, http.StatusOK, saved)
}

func HandleRulesetListDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !rsDecode(w, r, &req) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	if err := e.DeleteList(req.Name); err != nil {
		rsFail(w, err)
		return
	}
	rsJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func HandleRulesetValidate(w http.ResponseWriter, r *http.Request) {
	var in ruleset.ValidateInput
	if !rsDecode(w, r, &in) || !rsCheckLimit(w) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	rsJSON(w, http.StatusOK, e.Validate(in))
}

func HandleRulesetTest(w http.ResponseWriter, r *http.Request) {
	var in ruleset.TestInput
	if !rsDecode(w, r, &in) || !rsCheckLimit(w) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	rsJSON(w, http.StatusOK, e.Test(in))
}

func HandleRulesetStats(w http.ResponseWriter, r *http.Request) {
	if !rsMethod(w, r, http.MethodGet) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	site := r.URL.Query().Get("site")
	type row struct {
		ID      string        `json:"id"`
		Name    string        `json:"name"`
		Scope   string        `json:"scope"`
		Enabled bool          `json:"enabled"`
		DryRun  bool          `json:"dry_run"`
		Stats   ruleset.Stats `json:"stats"`
	}
	var rows []row
	add := func(s, scope string) {
		for _, ri := range e.Rules(s) {
			rows = append(rows, row{ri.ID, ri.Name, scope, ri.Enabled, ri.DryRun, ri.Stats})
		}
	}
	add("", "global")
	if site != "" {
		add(site, site)
	}
	if rows == nil {
		rows = []row{}
	}
	rsJSON(w, http.StatusOK, map[string]interface{}{
		"overview":    e.Overview(),
		"rules":       rows,
		"recent":      e.RecentHits(),
		"load_errors": e.LoadErrors,
		"note":        "counters are kept in memory and start from zero when Zoraxy starts",
	})
}

// v1 (token) read-only views

func HandleRulesetMigrate(w http.ResponseWriter, r *http.Request) {
	if !rsMethod(w, r, http.MethodGet) || !rsCheckLimit(w) {
		return
	}
	e := rsEngine(w)
	if e == nil {
		return
	}
	rsJSON(w, http.StatusOK, buildRulesetMigration(e))
}

var _ = strings.TrimSpace
