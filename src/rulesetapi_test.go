package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/ruleset"
)

func withTestRulesEngine(t *testing.T) *ruleset.Engine {
	t.Helper()
	e, err := ruleset.Open(filepath.Join(t.TempDir(), "ruleset"))
	if err != nil {
		t.Fatal(err)
	}
	oldE, oldL, oldR := rulesEngine, rulesetCheckLimiter, dynamicProxyRouter
	rulesEngine = e
	rulesEngineOnce = sync.Once{}
	rulesEngineOnce.Do(func() {})
	rulesetCheckLimiter = ruleset.NewLimiter(1000, 1000)
	dynamicProxyRouter = &dynamicproxy.Router{ProxyEndpoints: &sync.Map{}}
	dynamicProxyRouter.ProxyEndpoints.Store("app.example.com", &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "app.example.com"})
	t.Cleanup(func() { rulesEngine, rulesetCheckLimiter, dynamicProxyRouter = oldE, oldL, oldR })
	return e
}

func rsDo(h http.HandlerFunc, method, target, body string) (int, map[string]interface{}, string) {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, r)
	var m map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m, w.Body.String()
}

func TestRulesetAPILifecycle(t *testing.T) {
	withTestRulesEngine(t)
	// create (log-only by default), list, get
	code, m, raw := rsDo(HandleRulesetCreate, "POST", "/api/ruleset/rule/create", `{"site":"","rule":{"name":"admin","expression":"http.path   starts_with \"/admin\"","action":{"type":"block","status":404}}}`)
	if code != 201 || m["dry_run"] != true || m["expression"] != `http.path starts_with "/admin"` || m["tree"] == nil {
		t.Fatalf("create: %d %s", code, raw)
	}
	id := m["id"].(string)
	code, _, raw = rsDo(HandleRulesetRules, "GET", "/api/ruleset/rules", "")
	var list []map[string]interface{}
	json.Unmarshal([]byte(raw), &list)
	if code != 200 || len(list) != 1 || list[0]["id"] != id {
		t.Fatalf("list: %d %s", code, raw)
	}
	if code, _, _ = rsDo(HandleRulesetRule, "GET", "/api/ruleset/rule?id="+id, ""); code != 200 {
		t.Fatalf("get: %d", code)
	}
	if code, _, _ = rsDo(HandleRulesetRule, "GET", "/api/ruleset/rule?id=zzz", ""); code != 404 {
		t.Fatalf("get missing: %d", code)
	}
	// a second rule through the tree form, at position 0
	code, m, raw = rsDo(HandleRulesetCreate, "POST", "/x", `{"site":"app.example.com","position":0,"rule":{"name":"tree","tree":{"type":"and","children":[{"field":"http.method","op":"eq","value":"POST"},{"field":"req.size","op":"gt","value":100}]},"action":{"type":"log"},"dry_run":false}}`)
	if code != 201 || m["expression"] != `http.method == "POST" and req.size > 100` || m["dry_run"] != false {
		t.Fatalf("tree create: %d %s", code, raw)
	}
	// unknown site, unknown member, wrong method, invalid input
	if code, _, _ = rsDo(HandleRulesetCreate, "POST", "/x", `{"site":"nope.example.com","rule":{"name":"x","expression":"req.size > 1","action":{"type":"log"}}}`); code != 404 {
		t.Fatalf("unknown site: %d", code)
	}
	if code, _, _ = rsDo(HandleRulesetCreate, "POST", "/x", `{"site":"","rule":{"name":"x","expression":"req.size > 1","action":{"type":"log"},"bogus":1}}`); code != 400 {
		t.Fatalf("unknown member: %d", code)
	}
	if code, _, _ = rsDo(HandleRulesetCreate, "GET", "/x", ``); code != 405 {
		t.Fatalf("method: %d", code)
	}
	code, m, _ = rsDo(HandleRulesetCreate, "POST", "/x", `{"site":"","rule":{"name":"x","expression":"http.path ==","action":{"type":"log"}}}`)
	if code != 400 || m["error"] == nil || m["detail"] == nil {
		t.Fatalf("invalid expression: %d %v", code, m)
	}
	if code, _, _ = rsDo(HandleRulesetCreate, "POST", "/x", `not json`); code != 400 {
		t.Fatalf("bad json: %d", code)
	}
	// enable / disable / dry run / update / reorder / delete
	code, m, _ = rsDo(HandleRulesetEnable(false), "POST", "/x", `{"id":"`+id+`"}`)
	if code != 200 || m["enabled"] != false {
		t.Fatalf("disable: %d %v", code, m)
	}
	code, m, _ = rsDo(HandleRulesetDryRun, "POST", "/x", `{"id":"`+id+`","dry_run":false}`)
	if code != 200 || m["dry_run"] != false {
		t.Fatalf("dryrun: %d %v", code, m)
	}
	code, m, _ = rsDo(HandleRulesetUpdate, "POST", "/x", `{"id":"`+id+`","rule":{"name":"admin v2","expression":"http.path starts_with \"/admin2\"","action":{"type":"block"}}}`)
	if code != 200 || m["name"] != "admin v2" || m["enabled"] != false {
		t.Fatalf("update: %d %v", code, m)
	}
	rsDo(HandleRulesetCreate, "POST", "/x", `{"site":"","rule":{"name":"second","expression":"req.size > 1","action":{"type":"log"}}}`)
	_, _, raw = rsDo(HandleRulesetRules, "GET", "/x", "")
	json.Unmarshal([]byte(raw), &list)
	if code, _, raw = rsDo(HandleRulesetReorder, "POST", "/x", `{"order":["`+list[1]["id"].(string)+`","`+list[0]["id"].(string)+`"]}`); code != 200 {
		t.Fatalf("reorder: %d %s", code, raw)
	}
	if code, _, _ = rsDo(HandleRulesetReorder, "POST", "/x", `{"order":["a"]}`); code != 400 {
		t.Fatalf("bad reorder: %d", code)
	}
	if code, _, _ = rsDo(HandleRulesetDelete, "POST", "/x", `{"id":"`+id+`"}`); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if code, _, _ = rsDo(HandleRulesetDelete, "POST", "/x", `{"id":"`+id+`"}`); code != 404 {
		t.Fatalf("delete twice: %d", code)
	}
}

func TestRulesetAPIListsValidateTestStatsMeta(t *testing.T) {
	withTestRulesEngine(t)
	if code, _, raw := rsDo(HandleRulesetListSave, "POST", "/x", `{"name":"office","type":"ip","description":"hq","items":["203.0.113.0/24"]}`); code != 200 {
		t.Fatalf("list save: %d %s", code, raw)
	}
	if code, _, _ := rsDo(HandleRulesetListSave, "POST", "/x", `{"name":"bad","type":"ip","items":["nope"]}`); code != 400 {
		t.Fatalf("bad list: %d", code)
	}
	rsDo(HandleRulesetCreate, "POST", "/x", `{"site":"","rule":{"name":"office only","expression":"http.path starts_with \"/in\" and ip.src not in $office","action":{"type":"block"},"dry_run":false}}`)
	_, _, raw := rsDo(HandleRulesetLists, "GET", "/x", "")
	if !strings.Contains(raw, `"used_by":["global: office only"]`) {
		t.Fatalf("lists: %s", raw)
	}
	if code, m, _ := rsDo(HandleRulesetListDelete, "POST", "/x", `{"name":"office"}`); code != 400 || !strings.Contains(m["error"].(string), "office only") {
		t.Fatalf("delete used list: %d %v", code, m)
	}

	code, m, raw := rsDo(HandleRulesetValidate, "POST", "/x", `{"expression":"http.path ==","action":{"type":"block","status":200}}`)
	if code != 200 || m["ok"] != false || m["action_error"] == nil || m["errors"] == nil {
		t.Fatalf("validate bad: %d %s", code, raw)
	}
	code, m, raw = rsDo(HandleRulesetValidate, "POST", "/x", `{"expression":"lower(http.path) == \"/Admin\" and ip.src in $office"}`)
	if code != 200 || m["ok"] != true || m["warnings"] == nil || m["tree"] == nil || m["text"] == nil {
		t.Fatalf("validate ok: %d %s", code, raw)
	}
	code, m, raw = rsDo(HandleRulesetTest, "POST", "/x", `{"method":"GET","url":"http://app.example.com/in/page","client_ip":"198.51.100.4","country":"DE"}`)
	if code != 200 || m["decision"] != "block" {
		t.Fatalf("test: %d %s", code, raw)
	}
	code, m, raw = rsDo(HandleRulesetTest, "POST", "/x", `{"url":"/in/page","client_ip":"203.0.113.5"}`)
	if code != 200 || m["decision"] != "none" {
		t.Fatalf("test office client: %d %s", code, raw)
	}
	code, m, raw = rsDo(HandleRulesetStats, "GET", "/x", "")
	if code != 200 || m["overview"] == nil || m["recent"] == nil {
		t.Fatalf("stats: %d %s", code, raw)
	}
	code, m, raw = rsDo(HandleRulesetMeta, "GET", "/x", "")
	if code != 200 || m["fields"] == nil || m["operators"] == nil || m["actions"] == nil || !strings.Contains(raw, "no ASN data") || m["default_site_key"] != "_default_site" {
		t.Fatalf("meta: %d %s", code, raw)
	}
}

func TestRulesetAPIRateLimitsCheckEndpoints(t *testing.T) {
	withTestRulesEngine(t)
	rulesetCheckLimiter = ruleset.NewLimiter(0.001, 3)
	codes := []int{}
	for i := 0; i < 6; i++ {
		c, _, _ := rsDo(HandleRulesetValidate, "POST", "/x", `{"expression":"req.size > 1"}`)
		codes = append(codes, c)
	}
	if codes[2] != 200 || codes[3] != 429 || codes[5] != 429 {
		t.Fatalf("validate rate limit: %v", codes)
	}
	if c, _, _ := rsDo(HandleRulesetTest, "POST", "/x", `{"url":"/"}`); c != 429 {
		t.Fatalf("test shares the limit: %d", c)
	}
	if c, _, _ := rsDo(HandleRulesetMigrate, "GET", "/x", ``); c != 429 {
		t.Fatalf("migrate shares the limit: %d", c)
	}
}

func TestRulesetMigrationProposals(t *testing.T) {
	e := withTestRulesEngine(t)
	// proxy rule with a path rule, a header rule and a named access rule
	tmp := t.TempDir()
	sysdb, err := database.NewDatabase(filepath.Join(tmp, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer sysdb.Close()
	lg, _ := logger.NewFmtLogger()
	ac, err := access.NewAccessController(&access.Options{Logger: *lg, ConfigFolder: filepath.Join(tmp, "access"), TrustedProxiesFile: filepath.Join(tmp, "tp.json"), Database: sysdb, SkipPublicIPCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	oldAC := accessController
	accessController = ac
	defer func() { accessController = oldAC }()
	def, _ := ac.GetAccessRuleByID("default")
	def.BlacklistEnabled = true
	def.AddIPToBlackList("203.0.113.7", "bad")
	def.AddIPToBlackList("198.51.100.0/24", "bad net")
	def.AddCountryCodeToBlackList("cn", "")
	def.WhitelistEnabled = true

	ep := &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "app.example.com", PathRules: []*dynamicproxy.PathRule{
		{Name: "admin", MatchMode: "prefix", Pattern: "/admin", Action: dynamicproxy.PathRuleDeny, Methods: []string{"post"}, CIDRs: []string{"10.0.0.0/8"}, ScopeInvert: true},
		{Name: "api limit", MatchMode: "regex", Pattern: `/api/v[0-9]+/.*`, Action: dynamicproxy.PathRuleRateLimit, RateLimit: 5, RateBurst: 10},
		{Name: "needs login", MatchMode: "exact", Pattern: "/account", Action: dynamicproxy.PathRuleRequireAuth},
		{Name: "open", MatchMode: "prefix", Pattern: "/public/", Action: dynamicproxy.PathRuleAllow, CaseInsensitive: true},
	}, HeaderRules: []*dynamicproxy.HeaderRule{
		{Name: "X-Edge-Key", Values: []string{"s3cret", "old"}},
		{Name: "X-Token", Match: dynamicproxy.HeaderMatchRegex, Values: []string{"[a-f0-9]{8}"}, Action: dynamicproxy.HeaderActionNotFound, PathPrefix: "/internal"},
		{Name: "X-Present", Match: dynamicproxy.HeaderMatchPresent, Action: dynamicproxy.HeaderActionDrop},
	}}
	dynamicProxyRouter.ProxyEndpoints.Store("app.example.com", ep)

	res := buildRulesetMigration(e)
	if !strings.Contains(res.Statement, "Read-only") {
		t.Fatal("statement missing")
	}
	byRef := map[string]migrationProposal{}
	for _, p := range res.Proposals {
		if !p.Valid {
			t.Errorf("invalid proposal %q: %v\n%s", p.SourceRef, p.Problems, p.Rule.Expression)
		}
		if p.Rule.DryRun == nil || !*p.Rule.DryRun {
			t.Errorf("proposal %q must be log-only", p.SourceRef)
		}
		byRef[p.SourceRef] = p
	}
	adm := byRef["app.example.com, path rule 1 (admin)"]
	if adm.Rule.Expression != `(http.path == "/admin" or http.path starts_with "/admin/") and http.method in ["POST"] and not (ip.src in ["10.0.0.0/8"])` || adm.Rule.Action.Type != "block" || adm.Exact {
		t.Fatalf("admin path rule: %+v", adm)
	}
	if !strings.Contains(strings.Join(adm.Notes, " "), "readings") {
		t.Errorf("notes: %v", adm.Notes)
	}
	api := byRef["app.example.com, path rule 2 (api limit)"]
	if api.Rule.Action.Type != "rate_limit" || api.Rule.Action.Rate != 5 || api.Rule.Action.Burst != 10 || !strings.Contains(api.Rule.Expression, `matches "^(?:/api/v[0-9]+/.*)$"`) {
		t.Fatalf("rate limit rule: %+v", api)
	}
	open := byRef["app.example.com, path rule 4 (open)"]
	if open.Rule.Action.Type != "allow" || open.Exact || !strings.Contains(open.Rule.Expression, "lower(http.path)") {
		t.Fatalf("allow rule: %+v", open)
	}
	hdr := byRef["app.example.com, header rule 1 (X-Edge-Key)"]
	if hdr.Rule.Expression != `not (http.header["X-Edge-Key"] in ["s3cret", "old"])` || hdr.Exact || !strings.Contains(strings.Join(hdr.Notes, " "), "plain text") {
		t.Fatalf("header equals rule: %+v", hdr)
	}
	hdr = byRef["app.example.com, header rule 2 (X-Token)"]
	if hdr.Rule.Action.Status != 404 || !strings.Contains(hdr.Rule.Expression, `http.path starts_with "/internal/"`) {
		t.Fatalf("header regex rule: %+v", hdr)
	}
	hdr = byRef["app.example.com, header rule 3 (X-Present)"]
	if hdr.Rule.Expression != `not (http.header["X-Present"] exists)` || hdr.Exact {
		t.Fatalf("header present/drop rule: %+v", hdr)
	}
	// access lists: default rule blacklist as a list + rule, countries inline
	foundList, foundCountry := false, false
	for _, p := range res.Proposals {
		if p.Source != "access_list" {
			continue
		}
		if len(p.Lists) == 1 && p.Lists[0].Type == "ip" && len(p.Lists[0].Items) == 2 && strings.HasPrefix(p.Rule.Expression, "ip.src in $bl_") {
			foundList = true
		}
		if p.Rule.Expression == `ip.country in ["CN"]` {
			foundCountry = true
		}
		if p.Exact {
			t.Errorf("default access rule proposals are not exact: %+v", p)
		}
	}
	if !foundList || !foundCountry {
		t.Fatalf("access list proposals missing: %+v", res.Proposals)
	}
	// the empty whitelist and require_auth cannot be converted
	var reasons []string
	for _, n := range res.NotConverted {
		reasons = append(reasons, n.SourceRef+": "+n.Reason)
	}
	all := strings.Join(reasons, "\n")
	if !strings.Contains(all, "no equivalent") || !strings.Contains(all, "whitelist is enabled but empty") {
		t.Fatalf("not converted: %s", all)
	}
	// nothing was created
	if len(e.Rules("")) != 0 || len(e.Lists()) != 0 {
		t.Fatal("migration must be read-only")
	}
	// the proposals can be saved as they are
	for _, p := range res.Proposals {
		for _, l := range p.Lists {
			if _, err := e.SaveList(l); err != nil {
				t.Fatalf("list %s: %v", l.Name, err)
			}
		}
		if _, err := e.Create(p.Site, p.Rule, -1); err != nil {
			t.Fatalf("proposal %q cannot be imported: %v", p.SourceRef, err)
		}
	}
	// and an import keeps behaving like the original for a sample request
	r := e.Test(ruleset.TestInput{Site: "app.example.com", Method: "POST", URL: "http://app.example.com/admin/x", ClientIP: "192.0.2.5", Country: "DE"})
	found := false
	for _, tr := range r.Rules {
		if tr.Name == "Path rule: admin" && tr.Matched {
			found = true
		}
	}
	if !found {
		t.Fatalf("converted path rule did not match: %+v", r.Rules)
	}
	_ = botrules.ActionBlock
}

// A per-minute or keyed path limit has no exact engine equivalent (the engine counts per second, per client
// address): it must be skipped, never proposed as a looser per-second rule.
func TestRulesetMigrationSkipsMinuteAndKeyedLimits(t *testing.T) {
	e := withTestRulesEngine(t)
	ep := &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "rl.example.com", PathRules: []*dynamicproxy.PathRule{
		{Name: "login", MatchMode: "prefix", Pattern: "/login", Action: dynamicproxy.PathRuleRateLimit, RateLimit: 5, RateUnit: "minute", RateBurst: 5},
		{Name: "keyed", MatchMode: "prefix", Pattern: "/api", Action: dynamicproxy.PathRuleRateLimit, RateLimit: 5, KeyBy: "authorization"},
		{Name: "plain", MatchMode: "prefix", Pattern: "/x", Action: dynamicproxy.PathRuleRateLimit, RateLimit: 5},
	}}
	dynamicProxyRouter.ProxyEndpoints.Store("rl.example.com", ep)
	defer dynamicProxyRouter.ProxyEndpoints.Delete("rl.example.com")
	res := buildRulesetMigration(e)
	found := false
	for _, p := range res.Proposals {
		if strings.Contains(p.SourceRef, "(login)") || strings.Contains(p.SourceRef, "(keyed)") {
			t.Errorf("%q must not be proposed: %+v", p.SourceRef, p)
		}
		if p.SourceRef == "rl.example.com, path rule 3 (plain)" && p.Rule.Action.Rate == 5 {
			found = true
		}
	}
	if !found {
		t.Error("the plain per-second limit is still proposed")
	}
}
