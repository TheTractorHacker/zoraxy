package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/cluster"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

func setupWAFCentralTest(t *testing.T) *dynamicproxy.Router {
	t.Helper()
	router := setupEditTest(t)
	old := CONF_WAF_CENTRAL
	CONF_WAF_CENTRAL = filepath.Join(t.TempDir(), "waf_central.json")
	t.Cleanup(func() { CONF_WAF_CENTRAL = old })
	return router
}

func wafPost(t *testing.T, h http.HandlerFunc, v url.Values) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return strings.TrimSpace(w.Body.String())
}

func wafGet(t *testing.T, h http.HandlerFunc, target string, out interface{}) {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, target, nil))
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("%s: %v: %s", target, err, w.Body.String())
	}
}

func isOK(s string) bool { return s == "\"OK\"" }

func TestWAFCentralPolicyAPI(t *testing.T) {
	router := setupWAFCentralTest(t)

	// default: off, nothing on disk
	var pol waf.Policy
	wafGet(t, HandleWAFPolicy, "/api/waf/policy", &pol)
	if pol.Enabled {
		t.Fatal("global WAF must be off by default")
	}
	if _, err := os.Stat(CONF_WAF_CENTRAL); err == nil {
		t.Fatal("nothing may be written before the first change")
	}

	good, _ := json.Marshal(waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock, ExcludedRuleIDs: []string{"920420"}, TrustedPaths: []waf.TrustedPath{{Path: "/ping", Exact: true}}})
	if r := wafPost(t, HandleWAFPolicy, url.Values{"policy": {string(good)}}); !isOK(r) {
		t.Fatalf("save policy: %s", r)
	}
	if !router.WAFState().Policy.Enabled {
		t.Fatal("policy not applied to the router")
	}
	st, err := loadWAFCentralState(CONF_WAF_CENTRAL)
	if err != nil || !st.Policy.Enabled || st.Policy.DefaultMode != waf.ModeBlock || len(st.Policy.TrustedPaths) != 1 {
		t.Fatalf("policy not persisted: %v %+v", err, st)
	}

	// invalid inputs are rejected and nothing changes
	for name, p := range map[string]waf.Policy{
		"bad SecLang": {Enabled: true, DefaultMode: waf.ModeBlock, CustomRules: "SecRule BROKEN"},
		"bad mode":    {Enabled: true, DefaultMode: "x"},
		"bad path":    {Enabled: true, DefaultMode: waf.ModeBlock, TrustedPaths: []waf.TrustedPath{{Path: "x"}}},
		"bad ip":      {Enabled: true, DefaultMode: waf.ModeBlock, AllowedIPs: []string{"nope"}},
	} {
		js, _ := json.Marshal(p)
		if r := wafPost(t, HandleWAFPolicy, url.Values{"policy": {string(js)}}); isOK(r) {
			t.Errorf("%s accepted", name)
		}
	}
	if r := wafPost(t, HandleWAFPolicy, url.Values{"policy": {"{not json"}}); isOK(r) {
		t.Error("garbage JSON accepted")
	}
	if got := router.WAFState().Policy; len(got.ExcludedRuleIDs) != 1 || got.CustomRules != "" {
		t.Fatalf("state changed by a rejected request: %+v", got)
	}

	// corrupt file on load -> disabled policy, error reported
	os.WriteFile(CONF_WAF_CENTRAL, []byte("{broken"), 0600)
	st, err = loadWAFCentralState(CONF_WAF_CENTRAL)
	if err == nil || st.Policy.Enabled {
		t.Fatal("corrupt file must yield an error and a disabled policy")
	}
}

func TestWAFCentralProfilesAPI(t *testing.T) {
	setupWAFCentralTest(t)
	prof := func(name, mode string) string {
		js, _ := json.Marshal(waf.Profile{Name: name, Mode: mode, ParanoiaLevel: 1})
		return string(js)
	}
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {prof("Shop", waf.ModeBlock)}, "create": {"true"}}); !isOK(r) {
		t.Fatalf("create: %s", r)
	}
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {prof("shop", waf.ModeBlock)}, "create": {"true"}}); isOK(r) {
		t.Error("duplicate create accepted")
	}
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {prof("WordPress", waf.ModeBlock)}, "create": {"true"}}); isOK(r) {
		t.Error("built-in name accepted")
	}
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {prof("WordPress", waf.ModeBlock)}}); isOK(r) {
		t.Error("built-in profile edit accepted")
	}
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {prof("Ghost", waf.ModeBlock)}}); isOK(r) {
		t.Error("update of a missing profile accepted")
	}
	bad, _ := json.Marshal(waf.Profile{Name: "Shop", Mode: waf.ModeBlock, CustomRules: "SecRule nonsense"})
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {string(bad)}}); isOK(r) {
		t.Error("bad SecLang in a profile accepted")
	}
	if r := wafPost(t, HandleWAFProfileClone, url.Values{"from": {"Strict"}, "name": {"Strict copy"}}); !isOK(r) {
		t.Fatalf("clone builtin: %s", r)
	}
	if r := wafPost(t, HandleWAFProfileClone, url.Values{"from": {"nope"}, "name": {"x"}}); isOK(r) {
		t.Error("clone of a missing profile accepted")
	}

	var list []struct {
		waf.Profile
		UsedBy []string
	}
	wafGet(t, HandleWAFProfiles, "/api/waf/profiles", &list)
	var builtin, custom int
	for _, p := range list {
		if p.BuiltIn {
			builtin++
		} else {
			custom++
		}
	}
	if builtin < 4 || custom != 2 {
		t.Fatalf("profile list wrong: builtin=%d custom=%d", builtin, custom)
	}

	// Use it; deletion must be blocked while in use
	if r := wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {"app.example.com"}, "source": {"profile"}, "profile": {"shop"}}); !isOK(r) {
		t.Fatalf("assign profile: %s", r)
	}
	if r := wafPost(t, HandleWAFProfileDelete, url.Values{"name": {"Shop"}}); isOK(r) || !strings.Contains(r, "in use") {
		t.Errorf("deleting a profile in use must be refused, got %s", r)
	}
	if r := wafPost(t, HandleWAFProfileDelete, url.Values{"name": {"Strict"}}); isOK(r) {
		t.Error("built-in deletion accepted")
	}
	// Edit propagates to the endpoint
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {prof("Shop", waf.ModeDetectionOnly)}}); !isOK(r) {
		t.Fatalf("edit: %s", r)
	}
	var cov []dynamicproxy.WAFCoverageEntry
	wafGet(t, HandleWAFCoverage, "/api/waf/coverage", &cov)
	if len(cov) != 1 || cov[0].Mode != waf.ModeDetectionOnly || cov[0].Source != "profile" || cov[0].Profile != "shop" {
		t.Fatalf("coverage after profile edit: %+v", cov)
	}
	// Move the endpoint away, then deletion works
	if r := wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {"app.example.com"}, "source": {"inherit"}}); !isOK(r) {
		t.Fatalf("inherit: %s", r)
	}
	if r := wafPost(t, HandleWAFProfileDelete, url.Values{"name": {"Shop"}}); !isOK(r) {
		t.Fatalf("delete: %s", r)
	}
	// assigning an unknown profile fails and leaves the endpoint alone
	if r := wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {"app.example.com"}, "source": {"profile"}, "profile": {"Shop"}}); isOK(r) {
		t.Error("unknown profile accepted")
	}
	if r := wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {"app.example.com"}, "source": {"banana"}}); isOK(r) {
		t.Error("unknown source accepted")
	}
	// persisted profiles survive a reload
	st, err := loadWAFCentralState(CONF_WAF_CENTRAL)
	if err != nil || len(st.UserProfiles()) != 1 || st.UserProfiles()[0].Name != "Strict copy" {
		t.Fatalf("reload: %v %+v", err, st.UserProfiles())
	}
}

func TestWAFCentralCoverageAndEndpointSet(t *testing.T) {
	router := setupWAFCentralTest(t)
	get := func() dynamicproxy.WAFCoverageEntry {
		var cov []dynamicproxy.WAFCoverageEntry
		wafGet(t, HandleWAFCoverage, "/api/waf/coverage", &cov)
		if len(cov) != 1 {
			t.Fatalf("coverage: %+v", cov)
		}
		return cov[0]
	}
	if c := get(); c.Source != "inherit" || c.Mode != waf.ModeOff || c.Origin != "global" {
		t.Fatalf("fresh install: %+v", c)
	}
	pol, _ := json.Marshal(waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock})
	wafPost(t, HandleWAFPolicy, url.Values{"policy": {string(pol)}})
	if c := get(); c.Mode != waf.ModeBlock || c.Origin != "global" {
		t.Fatalf("after enabling: %+v", c)
	}
	for source, wantMode := range map[string]string{"off": waf.ModeOff, "detection_only": waf.ModeDetectionOnly, "block": waf.ModeBlock} {
		if r := wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {"app.example.com"}, "source": {source}}); !isOK(r) {
			t.Fatalf("%s: %s", source, r)
		}
		if c := get(); c.Mode != wantMode || c.Source != source {
			t.Fatalf("%s: %+v", source, c)
		}
	}
	// custom starts from the effective config and is persisted
	wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {"app.example.com"}, "source": {"custom"}})
	ep, _ := router.LoadProxy("app.example.com")
	if ep.WAF == nil || ep.WAFSource != "custom" || get().Source != "custom" {
		t.Fatalf("custom: %+v", ep.WAF)
	}
	saved, err := os.ReadFile(filepath.Join(CONF_HTTP_PROXY, "app.example.com.config"))
	if err != nil || !strings.Contains(string(saved), `"WAFSource": "custom"`) {
		t.Fatalf("endpoint config not persisted: %v", err)
	}
	if r := wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {"missing.example.com"}, "source": {"off"}}); isOK(r) {
		t.Error("unknown endpoint accepted")
	}
	// the legacy set API still works and means custom
	cfg, _ := json.Marshal(waf.Config{Mode: waf.ModeDetectionOnly})
	if r := wafPost(t, HandleWAFSet, url.Values{"rootname": {"app.example.com"}, "config": {string(cfg)}}); !isOK(r) {
		t.Fatalf("legacy set: %s", r)
	}
	if c := get(); c.Source != "custom" || c.Mode != waf.ModeDetectionOnly {
		t.Fatalf("legacy set: %+v", c)
	}
}

func TestWAFCentralExcludeAPI(t *testing.T) {
	router := setupWAFCentralTest(t)
	ex := func(v url.Values) string { return wafPost(t, HandleWAFExclude, v) }
	app := "app.example.com"

	// global, whole rule
	if r := ex(url.Values{"scope": {"global"}, "ruleid": {"942100"}}); !isOK(r) {
		t.Fatalf("global: %s", r)
	}
	// global, path scoped; repeated rule IDs on the same path merge
	ex(url.Values{"scope": {"global"}, "ruleid": {"941100"}, "path": {"/editor"}})
	ex(url.Values{"scope": {"global"}, "ruleid": {"941110"}, "path": {"/editor"}})
	ex(url.Values{"scope": {"global"}, "ruleid": {"942100"}}) // duplicate
	p := router.WAFState().Policy
	if len(p.ExcludedRuleIDs) != 1 || len(p.PathExclusions) != 1 || len(p.PathExclusions[0].RuleIDs) != 2 {
		t.Fatalf("global exclusions wrong: %+v", p)
	}
	// endpoint on inherit: additive extra, not a custom WAF
	if r := ex(url.Values{"rootname": {app}, "ruleid": {"920420"}}); !isOK(r) {
		t.Fatalf("endpoint: %s", r)
	}
	if r := ex(url.Values{"scope": {"path"}, "rootname": {app}, "ruleid": {"930100"}, "path": {"/dl"}, "exact": {"true"}}); !isOK(r) {
		t.Fatalf("path: %s", r)
	}
	ep, _ := router.LoadProxy(app)
	if ep.WAF != nil || ep.WAFExtra == nil || len(ep.WAFExtra.ExcludedRuleIDs) != 1 || len(ep.WAFExtra.PathExclusions) != 1 || !ep.WAFExtra.PathExclusions[0].Exact {
		t.Fatalf("endpoint extras wrong: %+v", ep.WAFExtra)
	}
	// legacy call shape (rootname + ruleid + path, no scope) still works
	if r := ex(url.Values{"rootname": {app}, "ruleid": {"920421"}, "path": {"/x"}}); !isOK(r) {
		t.Fatalf("legacy shape: %s", r)
	}
	// invalid input
	for name, v := range map[string]url.Values{
		"bad rule":       {"scope": {"global"}, "ruleid": {"abc"}},
		"bad path":       {"scope": {"global"}, "ruleid": {"1"}, "path": {"nope"}},
		"bad scope":      {"scope": {"galaxy"}, "ruleid": {"1"}, "rootname": {app}},
		"no endpoint":    {"ruleid": {"1"}},
		"unknown ep":     {"rootname": {"nope.example.com"}, "ruleid": {"1"}},
		"path no path":   {"scope": {"path"}, "rootname": {app}, "ruleid": {"1"}},
		"no rule":        {"scope": {"global"}},
		"rule with junk": {"scope": {"global"}, "ruleid": {"942100\"; deny"}},
	} {
		if isOK(ex(v)) {
			t.Errorf("%s accepted", name)
		}
	}
	// off endpoints refuse exclusions; custom endpoints get them in their own config
	wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {app}, "source": {"off"}})
	if isOK(ex(url.Values{"rootname": {app}, "ruleid": {"1"}})) {
		t.Error("exclusion on an endpoint with the WAF off accepted")
	}
	cfg, _ := json.Marshal(waf.Config{Mode: waf.ModeBlock})
	wafPost(t, HandleWAFSet, url.Values{"rootname": {app}, "config": {string(cfg)}})
	ex(url.Values{"rootname": {app}, "ruleid": {"942100"}})
	ep, _ = router.LoadProxy(app)
	if ep.WAF == nil || len(ep.WAF.ExcludedRuleIDs) != 1 || ep.WAFExtra != nil && len(ep.WAFExtra.ExcludedRuleIDs) > 1 {
		t.Fatalf("custom endpoint exclusion went to the wrong place: %+v", ep.WAF)
	}
}

func TestWAFCentralConcurrentMutations(t *testing.T) {
	router := setupWAFCentralTest(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := 100000 + i
			wafPost(t, HandleWAFExclude, url.Values{"scope": {"global"}, "ruleid": {strconv.Itoa(id)}})
			wafPost(t, HandleWAFExclude, url.Values{"rootname": {"app.example.com"}, "ruleid": {strconv.Itoa(id)}})
			wafGet(t, HandleWAFCoverage, "/api/waf/coverage", &[]dynamicproxy.WAFCoverageEntry{})
		}(i)
	}
	wg.Wait()
	if n := len(router.WAFState().Policy.ExcludedRuleIDs); n != 8 {
		t.Fatalf("lost updates: %d of 8 global exclusions", n)
	}
	ep, _ := router.LoadProxy("app.example.com")
	if ep.WAFExtra == nil || len(ep.WAFExtra.ExcludedRuleIDs) != 8 {
		t.Fatalf("lost endpoint updates: %+v", ep.WAFExtra)
	}
}

func TestWAFCentralEventsSummaryAndRulesAPIs(t *testing.T) {
	setupWAFCentralTest(t)
	var rules []waf.RuleInfo
	wafGet(t, HandleWAFRules, "/api/waf/rules", &rules)
	if len(rules) < 100 {
		t.Fatalf("rule reference too small: %d", len(rules))
	}
	var sum map[string]interface{}
	wafGet(t, HandleWAFSummary, "/api/waf/summary?hours=1", &sum)
	if _, ok := sum["summary"]; !ok {
		t.Fatal("summary missing")
	}
	w := httptest.NewRecorder()
	HandleWAFEvents(w, httptest.NewRequest(http.MethodGet, "/api/waf/events?rule=abc", nil))
	if !strings.Contains(w.Body.String(), "error") {
		t.Error("bad rule filter accepted")
	}
	w = httptest.NewRecorder()
	HandleWAFEvents(w, httptest.NewRequest(http.MethodGet, "/api/waf/events?rule=942100&action=blocked&since=2020-01-01T00:00:00Z&endpoint=x&ip=1.2.3.4&limit=5", nil))
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("events: %s", w.Body.String())
	}
}

func TestWAFCentralClusterPayloadValidation(t *testing.T) {
	good := `{"Policy":{"Enabled":true,"DefaultMode":"block"},"Profiles":[{"Name":"Mine","Mode":"block"}]}`
	mk := func(data string) *cluster.Payload {
		return &cluster.Payload{Roots: cluster.ManagedRoots(false), Files: []cluster.FileEntry{{Path: "waf_central.json", Data: []byte(data)}}}
	}
	if err := validateClusterPayload(mk(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`[]`, `{"Policy":{"DefaultMode":"zzz"}}`, `{"Profiles":[{"Name":"../../x"}]}`} {
		if validateClusterPayload(mk(bad)) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	found := false
	for _, r := range cluster.ManagedRoots(false) {
		if r == "waf_central.json" {
			found = true
		}
	}
	if !found {
		t.Fatal("waf_central.json must be replicated by cluster snapshots")
	}
}
