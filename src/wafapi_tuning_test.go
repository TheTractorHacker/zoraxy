package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

const tuningPostHogCookie = `ph_phc_abc123_posthog={"distinct_id":"anonymous_x.example.com","$sesid":[null,null,null],"$epp":true,"$initial_person_info":{"r":"$direct","u":"https://example.com/"}}`

// feedWAF sends a request through a detection-only WAF that records into the process wide event store
func feedWAF(t *testing.T, endpoint, clientIP, target string, hdr map[string]string) {
	t.Helper()
	in, err := waf.Default.Get(&waf.Config{Mode: waf.ModeDetectionOnly})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Host = endpoint
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	in.Inspect(httptest.NewRecorder(), req, waf.RequestInfo{Endpoint: endpoint, ClientIP: clientIP})
}

// passes reports whether the endpoint's effective WAF lets the request through in block mode
func passes(t *testing.T, endpoint, target string, hdr map[string]string) bool {
	t.Helper()
	router := dynamicProxyRouter
	ep, err := router.LoadProxy(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	res := router.WAFState().Resolve(ep.WAFSetting())
	if res.Config == nil {
		t.Fatalf("no effective WAF config for %s", endpoint)
	}
	cfg := *res.Config
	cfg.Mode = waf.ModeBlock
	in, err := waf.NewManager().Get(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Host = endpoint
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return !in.Inspect(httptest.NewRecorder(), req, waf.RequestInfo{Endpoint: endpoint, ClientIP: "198.51.100.1"})
}

func getTuning(t *testing.T, query string) waf.TuningReport {
	t.Helper()
	var rep waf.TuningReport
	wafGet(t, HandleWAFTuning, "/api/waf/tuning?"+query, &rep)
	return rep
}

func findTuning(rep waf.TuningReport, rule int, variablePrefix string) *waf.TuningItem {
	for i := range rep.Items {
		if rep.Items[i].RuleID == rule && strings.HasPrefix(rep.Items[i].Variable, variablePrefix) {
			return &rep.Items[i]
		}
	}
	return nil
}

func applyTuning(t *testing.T, scope, endpoint string, s waf.TuningSuggestion, variable string) string {
	t.Helper()
	js, _ := json.Marshal(s)
	v := url.Values{"scope": {scope}, "suggestion": {string(js)}}
	if endpoint != "" {
		v.Set("rootname", endpoint)
	}
	if variable != "" {
		v.Set("variable", variable)
	}
	return wafPost(t, HandleWAFTuningApply, v)
}

func TestWAFTuningAPIAndApplyScopes(t *testing.T) {
	router := setupWAFCentralTest(t)
	const app = "app.example.com"
	hdr := map[string]string{"Cookie": tuningPostHogCookie}
	// three different visitors, three paths
	feedWAF(t, app, "192.0.2.10", "/", hdr)
	feedWAF(t, app, "192.0.2.11", "/blog", hdr)
	feedWAF(t, app, "192.0.2.11", "/shop", hdr)
	feedWAF(t, "other.example.com", "192.0.2.12", "/", hdr)

	rep := getTuning(t, "hours=1&endpoint="+app)
	it := findTuning(rep, 942290, "REQUEST_COOKIES:")
	if it == nil {
		t.Fatalf("no 942290 suggestion: %+v", rep)
	}
	if it.Endpoint != app || it.Variable != "REQUEST_COOKIES:ph_*_posthog" || it.Count != 3 || it.Clients != 2 || it.PathCount != 3 || it.LooksLikeAttack {
		t.Fatalf("aggregation wrong: %+v", it)
	}
	if s := it.Suggestion; s.Kind != "variable" || s.Target != "REQUEST_COOKIES:/^ph_.+_posthog$/" || s.Path != "" {
		t.Fatalf("suggestion wrong: %+v", s)
	}
	// the endpoint filter really filters, and no filter sees both endpoints
	for _, x := range rep.Items {
		if x.Endpoint != app {
			t.Errorf("foreign endpoint in filtered report: %+v", x)
		}
	}
	all := getTuning(t, "hours=1")
	seen := map[string]bool{}
	for _, x := range all.Items {
		if x.RuleID == 942290 {
			seen[x.Endpoint] = true
		}
	}
	if !seen[app] || !seen["other.example.com"] {
		t.Errorf("unfiltered report misses an endpoint: %v", seen)
	}
	// bad hours fall back to the default instead of failing
	if r := getTuning(t, "hours=abc"); r.Hours != 24 {
		t.Errorf("hours default: %d", r.Hours)
	}

	// the request is blocked before and passes after, for every scope
	enable := func() {
		pol, _ := json.Marshal(waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock})
		if r := wafPost(t, HandleWAFPolicy, url.Values{"policy": {string(pol)}}); !isOK(r) {
			t.Fatalf("policy: %s", r)
		}
	}
	enable()
	if passes(t, app, "/", hdr) {
		t.Fatal("test does not reproduce the false positive")
	}

	// 1. global policy
	if r := applyTuning(t, "global", "", it.Suggestion, ""); !isOK(r) {
		t.Fatalf("global: %s", r)
	}
	if !passes(t, app, "/", hdr) {
		t.Error("global exclusion did not fix the request")
	}
	if passes(t, app, "/?q=%27%20OR%201%3D1--%20-", hdr) {
		t.Error("global variable exclusion opened the arguments")
	}
	// applying twice does not duplicate
	applyTuning(t, "global", "", it.Suggestion, "")
	if n := len(router.WAFState().Policy.TargetExclusions); n != 1 {
		t.Fatalf("expected one global exclusion, have %d", n)
	}
	// persistence round trip through the policy file
	st, err := loadWAFCentralState(CONF_WAF_CENTRAL)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Policy.TargetExclusions; len(got) != 1 || got[0].Target != it.Suggestion.Target || got[0].RuleIDs[0] != "942290" {
		t.Fatalf("not persisted: %+v", got)
	}
	raw, _ := json.Marshal(wafCentralFile{Policy: st.Policy})
	var back wafCentralFile
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Policy.TargetExclusions) != 1 {
		t.Fatalf("policy JSON round trip: %v", err)
	}

	// 2. endpoint overrides (inherit / profile / fixed mode sources)
	pol, _ := json.Marshal(map[string]interface{}{"Enabled": true, "DefaultMode": waf.ModeBlock, "TargetExclusions": []string{}}) // remove the global one again
	wafPost(t, HandleWAFPolicy, url.Values{"policy": {string(pol)}})
	if passes(t, app, "/", hdr) {
		t.Fatal("global exclusion should be gone")
	}
	if r := applyTuning(t, "endpoint", app, it.Suggestion, ""); !isOK(r) {
		t.Fatalf("endpoint overrides: %s", r)
	}
	ep, _ := router.LoadProxy(app)
	if ep.WAF != nil || ep.WAFExtra == nil || len(ep.WAFExtra.TargetExclusions) != 1 {
		t.Fatalf("overrides wrong: waf=%+v extra=%+v", ep.WAF, ep.WAFExtra)
	}
	if !passes(t, app, "/", hdr) {
		t.Error("endpoint override exclusion did not fix the request")
	}
	// scope given as the endpoint name works too, and is idempotent
	if r := applyTuning(t, app, "", it.Suggestion, ""); !isOK(r) {
		t.Fatalf("scope as endpoint name: %s", r)
	}
	if ep, _ = router.LoadProxy(app); len(ep.WAFExtra.TargetExclusions) != 1 {
		t.Fatalf("duplicate added: %+v", ep.WAFExtra)
	}
	// persisted in the endpoint file and restored by a reload
	saved, err := os.ReadFile(filepath.Join(CONF_HTTP_PROXY, app+".config"))
	if err != nil {
		t.Fatal(err)
	}
	var reloaded dynamicproxy.ProxyEndpoint
	if err := json.Unmarshal(saved, &reloaded); err != nil || reloaded.WAFExtra == nil || len(reloaded.WAFExtra.TargetExclusions) != 1 || reloaded.WAFExtra.TargetExclusions[0].Target != it.Suggestion.Target {
		t.Fatalf("endpoint file round trip: %v %+v", err, reloaded.WAFExtra)
	}

	// 3. custom endpoint config
	wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {app}, "source": {"custom"}, "extra": {""}})
	ep, _ = router.LoadProxy(app)
	if ep.WAF == nil {
		t.Fatal("custom WAF not created")
	}
	ep.WAF.TargetExclusions = nil
	cfg, _ := json.Marshal(waf.Config{Mode: waf.ModeBlock})
	wafPost(t, HandleWAFSet, url.Values{"rootname": {app}, "config": {string(cfg)}})
	if passes(t, app, "/", hdr) {
		t.Fatal("custom config without exclusions should block")
	}
	if r := applyTuning(t, "endpoint", app, it.Suggestion, ""); !isOK(r) {
		t.Fatalf("custom: %s", r)
	}
	ep, _ = router.LoadProxy(app)
	if ep.WAF == nil || len(ep.WAF.TargetExclusions) != 1 {
		t.Fatalf("custom config wrong: %+v", ep.WAF)
	}
	if !passes(t, app, "/", hdr) {
		t.Error("custom config exclusion did not fix the request")
	}
}

func TestWAFTuningApplyKindsAndValidation(t *testing.T) {
	router := setupWAFCentralTest(t)
	const app = "app.example.com"
	ok := func(r string) {
		t.Helper()
		if !isOK(r) {
			t.Fatalf("expected OK, got %s", r)
		}
	}
	// path-rule and rule kinds go through the existing quick exclusion
	ok(applyTuning(t, "global", "", waf.TuningSuggestion{Kind: "path-rule", RuleIDs: []string{"920420"}, Path: "/upload", Exact: true}, ""))
	ok(applyTuning(t, "global", "", waf.TuningSuggestion{Kind: "rule", RuleIDs: []string{"920421"}}, ""))
	p := router.WAFState().Policy
	if len(p.PathExclusions) != 1 || p.PathExclusions[0].Path != "/upload" || len(p.ExcludedRuleIDs) != 1 {
		t.Fatalf("kinds wrong: %+v", p)
	}
	// a variable from an event, with the exact (not collapsed) name
	ok(applyTuning(t, "endpoint", app, waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"942100"}}, "ARGS_GET:Q"))
	ep, _ := router.LoadProxy(app)
	if ep.WAFExtra == nil || len(ep.WAFExtra.TargetExclusions) != 1 || ep.WAFExtra.TargetExclusions[0].Target != "ARGS:q" {
		t.Fatalf("variable from event: %+v", ep.WAFExtra)
	}
	// rule IDs merge on the same target
	ok(applyTuning(t, "endpoint", app, waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"942200"}, Target: "ARGS:q"}, ""))
	if ep, _ = router.LoadProxy(app); len(ep.WAFExtra.TargetExclusions) != 1 || len(ep.WAFExtra.TargetExclusions[0].RuleIDs) != 2 {
		t.Fatalf("merge: %+v", ep.WAFExtra.TargetExclusions)
	}

	before := router.WAFState().Policy
	for name, c := range map[string]struct {
		scope, ep string
		s         waf.TuningSuggestion
		variable  string
	}{
		"injection in target":   {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}, Target: `ARGS:x" "id:1,pass`}, ""},
		"newline in target":     {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}, Target: "ARGS:x\nSecRule"}, ""},
		"semicolon in target":   {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}, Target: "ARGS:x;ctl:ruleEngine=Off"}, ""},
		"unknown collection":    {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}, Target: "TX:score"}, ""},
		"junk rule id":          {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1\""}, Target: "ARGS:x"}, ""},
		"no rule id":            {"global", "", waf.TuningSuggestion{Kind: "variable", Target: "ARGS:x"}, ""},
		"bad path":              {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}, Target: "ARGS:x", Path: `/x" "`}, ""},
		"no target no variable": {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}}, ""},
		"unexcludable variable": {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}}, "REQUEST_METHOD"},
		"bad kind":              {"global", "", waf.TuningSuggestion{Kind: "everything", RuleIDs: []string{"1"}}, ""},
		"score rule variable":   {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"949110"}, Target: "ARGS:x"}, ""},
		"score rule path":       {"global", "", waf.TuningSuggestion{Kind: "path-rule", RuleIDs: []string{"980130"}, Path: "/x"}, ""},
		"score rule whole":      {"global", "", waf.TuningSuggestion{Kind: "rule", RuleIDs: []string{"959100"}}, ""},
		"score rule range":      {"global", "", waf.TuningSuggestion{Kind: "rule", RuleIDs: []string{"940000-950000"}}, ""},
		"score rule family":     {"global", "", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"949111"}, Target: "ARGS:x"}, ""},
		"path-rule no path":     {"global", "", waf.TuningSuggestion{Kind: "path-rule", RuleIDs: []string{"1"}}, ""},
		"endpoint missing":      {"endpoint", "", waf.TuningSuggestion{Kind: "rule", RuleIDs: []string{"1"}}, ""},
		"unknown endpoint":      {"endpoint", "nope.example.com", waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}, Target: "ARGS:x"}, ""},
	} {
		if r := applyTuning(t, c.scope, c.ep, c.s, c.variable); isOK(r) {
			t.Errorf("%s accepted", name)
		}
	}
	after := router.WAFState().Policy
	if len(after.TargetExclusions) != len(before.TargetExclusions) || len(after.ExcludedRuleIDs) != len(before.ExcludedRuleIDs) {
		t.Errorf("a rejected request changed the policy: %+v", after)
	}
	// WAF off for the endpoint: refused
	wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {app}, "source": {"off"}})
	if r := applyTuning(t, "endpoint", app, waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"1"}, Target: "ARGS:x"}, ""); isOK(r) {
		t.Error("exclusion on an endpoint with the WAF off accepted")
	}
	// malformed body and wrong method
	if r := wafPost(t, HandleWAFTuningApply, url.Values{"scope": {"global"}, "suggestion": {"{nope"}}); isOK(r) {
		t.Error("bad JSON accepted")
	}
	w := httptest.NewRecorder()
	HandleWAFTuningApply(w, httptest.NewRequest(http.MethodGet, "/api/waf/tuning/apply", nil))
	if !strings.Contains(w.Body.String(), "error") {
		t.Error("GET accepted")
	}
}

func TestWAFTuningRemoveAndPreserve(t *testing.T) {
	router := setupWAFCentralTest(t)
	const app = "app.example.com"
	te := waf.TuningSuggestion{Kind: "variable", RuleIDs: []string{"942100", "942200"}, Target: "ARGS:q", Path: "/s", Exact: true}
	for _, scope := range []string{"global", "endpoint"} {
		if r := applyTuning(t, scope, app, te, ""); !isOK(r) {
			t.Fatalf("%s: %s", scope, r)
		}
	}
	rm := func(scope string, extra url.Values) string {
		v := url.Values{"scope": {scope}, "rootname": {app}, "target": {"ARGS:q"}, "path": {"/s"}, "exact": {"true"}}
		for k, x := range extra {
			v[k] = x
		}
		return wafPost(t, HandleWAFTuningRemove, v)
	}
	// one rule ID out of the entry
	if r := rm("global", url.Values{"ruleid": {"942100"}}); !isOK(r) {
		t.Fatal(r)
	}
	if got := router.WAFState().Policy.TargetExclusions; len(got) != 1 || len(got[0].RuleIDs) != 1 || got[0].RuleIDs[0] != "942200" {
		t.Fatalf("rule id removal: %+v", got)
	}
	// the settings editors that predate the assistant must not wipe the exclusions
	pol := router.WAFState().Policy
	pol.TargetExclusions = nil
	js, _ := json.Marshal(pol)
	var m map[string]interface{}
	json.Unmarshal(js, &m)
	delete(m, "TargetExclusions")
	js, _ = json.Marshal(m)
	if r := wafPost(t, HandleWAFPolicy, url.Values{"policy": {string(js)}}); !isOK(r) {
		t.Fatal(r)
	}
	if len(router.WAFState().Policy.TargetExclusions) != 1 {
		t.Fatal("policy save without the field wiped the variable exclusions")
	}
	cfg, _ := json.Marshal(map[string]interface{}{"Mode": "block"})
	wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {app}, "source": {"custom"}})
	ep, _ := router.LoadProxy(app)
	ep.WAF.TargetExclusions = nil
	applyTuning(t, "endpoint", app, te, "")
	if r := wafPost(t, HandleWAFSet, url.Values{"rootname": {app}, "config": {string(cfg)}}); !isOK(r) {
		t.Fatal(r)
	}
	if ep, _ = router.LoadProxy(app); ep.WAF == nil || len(ep.WAF.TargetExclusions) != 1 {
		t.Fatalf("config save without the field wiped the variable exclusions: %+v", ep.WAF)
	}
	// an explicit empty list clears them
	cfg, _ = json.Marshal(map[string]interface{}{"Mode": "block", "TargetExclusions": []string{}})
	wafPost(t, HandleWAFSet, url.Values{"rootname": {app}, "config": {string(cfg)}})
	if ep, _ = router.LoadProxy(app); len(ep.WAF.TargetExclusions) != 0 {
		t.Fatalf("explicit clear ignored: %+v", ep.WAF)
	}
	// removal in the endpoint scope, whole entry; unknown entries are an error
	applyTuning(t, "endpoint", app, te, "")
	if r := rm("endpoint", nil); !isOK(r) {
		t.Fatal(r)
	}
	if ep, _ = router.LoadProxy(app); len(ep.WAF.TargetExclusions) != 0 {
		t.Fatalf("endpoint removal: %+v", ep.WAF.TargetExclusions)
	}
	if r := rm("endpoint", nil); isOK(r) {
		t.Error("removing a missing exclusion succeeded")
	}
	if r := rm("global", url.Values{"target": {"ARGS:other"}}); isOK(r) {
		t.Error("removing a missing global exclusion succeeded")
	}
}
