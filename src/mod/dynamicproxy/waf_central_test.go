package dynamicproxy

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

const sqliQuery = "?id=1%27%20OR%20%271%27%3D%271"

func mustState(t testing.TB, p waf.Policy, profiles ...waf.Profile) *waf.State {
	t.Helper()
	st, err := waf.NewState(p, profiles)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func serveCode(h *ProxyHandler, target string) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("GET", target, nil, nil))
	return w.Code
}

// Old configs (no central fields) keep their behaviour: a configured WAF is
// "custom" and active even with the global policy off, an endpoint without a
// WAF inherits the (disabled) global policy.
func TestCentralWAFOldConfigCompat(t *testing.T) {
	var old ProxyEndpoint
	if err := json.Unmarshal([]byte(`{"RootOrMatchingDomain":"a.test","WAF":{"Mode":"block"}}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.WAFSetting().EffectiveSource() != waf.SourceCustom || old.WAFSource != "" {
		t.Fatalf("legacy WAF config must be custom, got %q", old.WAFSetting().EffectiveSource())
	}
	var none ProxyEndpoint
	json.Unmarshal([]byte(`{"RootOrMatchingDomain":"b.test"}`), &none)
	if none.WAFSetting().EffectiveSource() != waf.SourceInherit {
		t.Fatal("endpoint without WAF must inherit")
	}
	// saved form of an untouched endpoint does not grow new keys
	js, _ := json.Marshal(&none)
	for _, k := range []string{"WAFSource", "WAFProfile", "WAFExtra"} {
		if strings.Contains(string(js), k) {
			t.Errorf("%s must be omitted when unset", k)
		}
	}

	h, hits, _ := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) { ep.WAF = &waf.Config{Mode: waf.ModeBlock} })
	if code := serveCode(h, "/"+sqliQuery); code != 403 {
		t.Fatalf("legacy custom block with global WAF off: got %d, want 403", code)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatal("blocked request reached upstream")
	}
	h, _, _ = newCentralWAFTestProxy(t, nil, nil)
	if code := serveCode(h, "/"+sqliQuery); code != 200 {
		t.Fatalf("inherit with global WAF off must not inspect, got %d", code)
	}
}

func TestCentralWAFInheritanceThroughProxyHandler(t *testing.T) {
	type tc struct {
		name    string
		enabled bool
		mode    string
		set     func(*ProxyEndpoint)
		want    int
	}
	custom := func(m string) func(*ProxyEndpoint) {
		return func(ep *ProxyEndpoint) { ep.WAF = &waf.Config{Mode: m}; ep.WAFSource = waf.SourceCustom }
	}
	src := func(s string) func(*ProxyEndpoint) { return func(ep *ProxyEndpoint) { ep.WAFSource = s } }
	cases := []tc{
		{"off/inherit", false, waf.ModeBlock, nil, 200},
		{"off/endpoint block", false, waf.ModeBlock, src(waf.ModeBlock), 403},
		{"off/endpoint detect", false, waf.ModeBlock, src(waf.ModeDetectionOnly), 200},
		{"off/custom block", false, waf.ModeBlock, custom(waf.ModeBlock), 403},
		{"on block/inherit", true, waf.ModeBlock, nil, 403},
		{"on block/off", true, waf.ModeBlock, src(waf.SourceOff), 200},
		{"on block/detect", true, waf.ModeBlock, src(waf.ModeDetectionOnly), 200},
		{"on block/block", true, waf.ModeBlock, src(waf.ModeBlock), 403},
		{"on block/custom detect", true, waf.ModeBlock, custom(waf.ModeDetectionOnly), 200},
		{"on detect/inherit", true, waf.ModeDetectionOnly, nil, 200},
		{"on detect/block", true, waf.ModeDetectionOnly, src(waf.ModeBlock), 403},
		{"on off-mode/inherit", true, waf.ModeOff, nil, 200},
		{"on block/custom nil config", true, waf.ModeBlock, src(waf.SourceCustom), 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := mustState(t, waf.Policy{Enabled: c.enabled, DefaultMode: c.mode})
			h, _, _ := newCentralWAFTestProxy(t, st, c.set)
			if got := serveCode(h, "/"+sqliQuery); got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
}

// Same attack through the non-TLS entry point
func TestCentralWAFNonTLSPath(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.ProxyType = ProxyTypeHost
	router.SetWAFState(mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock, TrustedPaths: []waf.TrustedPath{{Path: "/public/"}}}))
	prepared, err := router.PrepareProxyRoute(sep) // inherits
	if err != nil {
		t.Fatal(err)
	}
	prepared.parent = router
	if w := serveNonTLS(router, prepared, "http://app.example.com/"+sqliQuery, "198.51.100.1:1000"); w.Code != 403 {
		t.Fatalf("inherited block on the non-TLS path: %d", w.Code)
	}
	if w := serveNonTLS(router, prepared, "http://app.example.com/public/x"+sqliQuery, "198.51.100.1:1000"); w.Code != 299 {
		t.Fatalf("trusted path on the non-TLS path: %d", w.Code)
	}
	if w := serveNonTLS(router, prepared, "http://app.example.com/ok", "198.51.100.1:1000"); w.Code != 299 {
		t.Fatalf("clean request: %d", w.Code)
	}
}

func TestCentralWAFAdditiveExclusionsAndOverridePermission(t *testing.T) {
	// 942100 is the libinjection SQLi rule: excluding it globally lets the classic payload through
	attack := "/?id=1%27%20OR%20%271%27%3D%271"
	base := waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock}

	h, _, _ := newCentralWAFTestProxy(t, mustState(t, base), nil)
	if serveCode(h, attack) != 403 {
		t.Fatal("baseline must block")
	}

	// Resolve level checks for merge semantics
	pol := base
	pol.ExcludedRuleIDs = []string{"942100"}
	pol.CustomRules = `SecRule ARGS:g "@streq 1" "id:1000001,phase:1,deny,status:403"`
	pol.ParanoiaLevel = 2
	st := mustState(t, pol)
	extra := &waf.Overrides{ExcludedRuleIDs: []string{"942100", "942110"}, CustomRules: `SecRule ARGS:e "@streq 1" "id:1000002,phase:1,deny,status:403"`, ParanoiaLevel: 4}
	res := st.Resolve(waf.Setting{Source: waf.SourceInherit, Extra: extra})
	if got := strings.Join(res.Config.ExcludedRuleIDs, ","); got != "942100,942110" {
		t.Fatalf("exclusions must be additive and de-duplicated, got %s", got)
	}
	if res.Config.ParanoiaLevel != 2 || res.Warning == "" {
		t.Fatalf("paranoia override must be ignored when not allowed (pl=%d warn=%q)", res.Config.ParanoiaLevel, res.Warning)
	}
	if i, j := strings.Index(res.Config.CustomRules, "1000001"), strings.Index(res.Config.CustomRules, "1000002"); i < 0 || j < i {
		t.Fatal("endpoint custom rules must run after the global ones")
	}
	if err := st.ValidateSetting(waf.Setting{Source: waf.SourceInherit, Extra: extra}); err == nil {
		t.Fatal("override must be rejected on save when not allowed")
	}
	pol.AllowEndpointOverride = true
	st = mustState(t, pol)
	if res := st.Resolve(waf.Setting{Source: waf.SourceInherit, Extra: extra}); res.Config.ParanoiaLevel != 4 || res.Warning != "" {
		t.Fatalf("override must apply when allowed, pl=%d", res.Config.ParanoiaLevel)
	}

	// End to end: global exclusion of the SQLi rules in effect
	pol2 := base
	pol2.ExcludedRuleIDs = []string{"942100-942999", "949110"}
	h, _, _ = newCentralWAFTestProxy(t, mustState(t, pol2), nil)
	if serveCode(h, attack) != 200 {
		t.Fatal("global exclusion must apply to inheriting endpoints")
	}
	// Endpoint on custom ignores the global exclusions (standalone)
	h, _, _ = newCentralWAFTestProxy(t, mustState(t, pol2), func(ep *ProxyEndpoint) { ep.WAF = &waf.Config{Mode: waf.ModeBlock} })
	if serveCode(h, attack) != 403 {
		t.Fatal("custom endpoint must not use global exclusions")
	}
}

func TestCentralWAFProfileEditPropagatesAndSharesInstances(t *testing.T) {
	mk := func(mode string) waf.Profile {
		return waf.Profile{Name: "Mine", Mode: mode, ParanoiaLevel: 1}
	}
	st := mustState(t, waf.Policy{}, mk(waf.ModeDetectionOnly))
	h, _, _ := newCentralWAFTestProxy(t, st, func(ep *ProxyEndpoint) { ep.WAFSource = waf.SourceProfile; ep.WAFProfile = "mine" })
	router := h.Parent
	if serveCode(h, "/"+sqliQuery) != 200 {
		t.Fatal("detection profile must not block")
	}
	ep, _ := router.LoadProxy("waf.test")
	inst1 := ep.wafRT.Load().inst
	cache1 := waf.Default.CacheSize()

	// A second endpoint with the same profile shares the compiled instance
	ep2 := CopyEndpoint(ep)
	ep2.RootOrMatchingDomain = "second.test"
	p2, err := router.PrepareProxyRoute(ep2)
	if err != nil {
		t.Fatal(err)
	}
	if p2.wafRT.Load().inst != inst1 {
		t.Fatal("endpoints with the same effective config must share one compiled instance")
	}
	if waf.Default.CacheSize() != cache1 {
		t.Fatal("cache grew for an identical config")
	}

	// Editing the profile applies at once, without re-adding endpoints
	if err := router.ApplyWAFState(mustState(t, waf.Policy{}, mk(waf.ModeBlock))); err != nil {
		t.Fatal(err)
	}
	if serveCode(h, "/"+sqliQuery) != 403 {
		t.Fatal("profile edit must propagate to the endpoint")
	}
	// ... and a no-op re-apply reuses the cached instance
	inst2 := ep.wafRT.Load().inst
	if err := router.ApplyWAFState(mustState(t, waf.Policy{}, mk(waf.ModeBlock))); err != nil {
		t.Fatal(err)
	}
	if ep.wafRT.Load().inst != inst2 {
		t.Fatal("unchanged effective config must reuse the cached instance")
	}
	// Coverage reports the profile
	var found bool
	for _, c := range router.WAFCoverage() {
		if c.Endpoint == "waf.test" && c.Source == waf.SourceProfile && c.Profile == "mine" && c.Mode == waf.ModeBlock && c.Origin == "profile:Mine" {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage missing profile row: %+v", router.WAFCoverage())
	}
}

func TestCentralWAFApplyRejectsBadRulesAndKeepsState(t *testing.T) {
	st := mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock})
	h, _, _ := newCentralWAFTestProxy(t, st, nil)
	router := h.Parent
	bad := mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock, CustomRules: "SecRule THIS IS NOT VALID"})
	if err := router.ApplyWAFState(bad); err == nil {
		t.Fatal("invalid global SecLang must be rejected")
	}
	badProfile := mustState(t, waf.Policy{}, waf.Profile{Name: "Bad", Mode: waf.ModeBlock, CustomRules: "SecRule nope"})
	if err := router.ApplyWAFState(badProfile); err == nil {
		t.Fatal("invalid profile SecLang must be rejected even if unused")
	}
	if router.WAFState() != st {
		t.Fatal("state must be unchanged after a rejected apply")
	}
	if serveCode(h, "/"+sqliQuery) != 403 {
		t.Fatal("running config must be untouched")
	}
}

func TestCentralWAFBypassLists(t *testing.T) {
	st := mustState(t, waf.Policy{
		Enabled: true, DefaultMode: waf.ModeBlock,
		TrustedPaths: []waf.TrustedPath{{Path: "/public/"}, {Path: "/health", Exact: true}, {Host: "only.test", Path: "/hostonly/"}},
		AllowedIPs:   []string{"203.0.113.0/24"},
	})
	h, _, _ := newCentralWAFTestProxy(t, st, nil)

	pass := []string{
		"/public/a.txt" + sqliQuery,
		"/health" + sqliQuery,
		"/.well-known/acme-challenge/abcDEF-123" + sqliQuery,
		"/public/%61.txt" + sqliQuery, // decodes to /public/a.txt, unambiguous
	}
	for _, p := range pass {
		if got := serveCode(h, p); got != 200 {
			t.Errorf("%s should bypass the WAF, got %d", p, got)
		}
	}
	// Path tricks must never bypass
	blocked := []string{
		"//public/a.txt" + sqliQuery,
		"/public//a.txt" + sqliQuery,
		"/./public/a.txt" + sqliQuery,
		"/public/./a.txt" + sqliQuery,
		"/public/../admin" + sqliQuery,
		"/public/%2e%2e/admin" + sqliQuery,
		"/public/%252e%252e/admin" + sqliQuery,
		"/public/..%2fadmin" + sqliQuery,
		"/PUBLIC/a.txt" + sqliQuery,
		"/Public/a.txt" + sqliQuery,
		"/health/" + sqliQuery,
		"/health/extra" + sqliQuery,
		"/healthz" + sqliQuery,
		"/hostonly/x" + sqliQuery, // wrong host (waf.test)
		"/.well-known/acme-challenge/" + sqliQuery,
		"/.well-known/acme-challenge/../../admin" + sqliQuery,
		"/.well-known/acme-challenge/%2e%2e/%2e%2e/admin" + sqliQuery,
		"/.WELL-KNOWN/acme-challenge/x" + sqliQuery,
		"/.well-known//acme-challenge/x" + sqliQuery,
		"/public\\..\\admin" + sqliQuery,
	}
	for _, p := range blocked {
		if got := serveCode(h, p); got != 403 {
			t.Errorf("%s must still be inspected and blocked, got %d", p, got)
		}
	}
	// ACME bypass is for GET / HEAD only
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("POST", "/.well-known/acme-challenge/x"+sqliQuery, nil, nil))
	if w.Code != 403 {
		t.Errorf("POST to the ACME path must be inspected, got %d", w.Code)
	}
	// Host restricted entry
	r := wafReq("GET", "/hostonly/x"+sqliQuery, nil, nil)
	r.Host = "only.test"
	// (host header selects the endpoint; use the matching-domain alias by calling the chain directly)
	if !st.Policy.Enabled || st.BypassReason(r, "198.51.100.9:1") != "trusted-path" {
		t.Error("host restricted trusted path must match its host")
	}
	// IP allow-list: trusted client IP skips the WAF, others do not
	r = wafReq("GET", "/"+sqliQuery, nil, nil)
	r.RemoteAddr = "203.0.113.77:4000"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("allow-listed IP should skip the WAF, got %d", w.Code)
	}
	r = wafReq("GET", "/"+sqliQuery, nil, nil)
	r.RemoteAddr = "203.0.114.1:4000"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("IP outside the allow-list must be inspected, got %d", w.Code)
	}
}

// Legacy custom endpoints see no bypass lists while the global policy is off
// (upgrade is a no-op) and ACME bypass applies once the policy is enabled.
func TestCentralWAFBypassScopeForCustomEndpoints(t *testing.T) {
	custom := func(ep *ProxyEndpoint) { ep.WAF = &waf.Config{Mode: waf.ModeBlock} }
	h, _, _ := newCentralWAFTestProxy(t, mustState(t, waf.Policy{}), custom)
	if got := serveCode(h, "/.well-known/acme-challenge/x"+sqliQuery); got != 403 {
		t.Errorf("global policy off: custom endpoint behaviour must not change, got %d", got)
	}
	h, _, _ = newCentralWAFTestProxy(t, mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeOff}), custom)
	if got := serveCode(h, "/.well-known/acme-challenge/x"+sqliQuery); got != 200 {
		t.Errorf("global policy on: ACME challenge must never be blocked, got %d", got)
	}
}

func TestCentralWAFEventsCarrySourceAndFilter(t *testing.T) {
	st := mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock})
	h, _, _ := newCentralWAFTestProxy(t, st, nil)
	serveCode(h, "/src-check"+sqliQuery)
	evs := waf.Default.QueryEvents(waf.EventFilter{Endpoint: "waf.test", Action: "blocked", Limit: 50})
	var ok bool
	for _, e := range evs {
		if e.Path == "/src-check" && e.Source == "global" {
			ok = true
			if len(e.Rules) == 0 {
				t.Fatal("event without rules")
			}
			if len(waf.Default.QueryEvents(waf.EventFilter{RuleID: e.Rules[0].ID, ClientIP: e.ClientIP, Limit: 5})) == 0 {
				t.Error("rule / ip filter lost the event")
			}
		}
	}
	if !ok {
		t.Fatal("event with source=global not recorded")
	}
	if len(waf.Default.QueryEvents(waf.EventFilter{Endpoint: "nope"})) != 0 {
		t.Error("endpoint filter ignored")
	}
}

// Requests keep flowing while states are swapped. Run with -race.
func TestCentralWAFConcurrentApply(t *testing.T) {
	stA := mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock})
	stB := mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeDetectionOnly}, waf.Profile{Name: "x", Mode: waf.ModeBlock})
	h, _, _ := newCentralWAFTestProxy(t, stA, nil)
	router := h.Parent
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, wafReq("GET", "/"+sqliQuery, nil, nil))
				if w.Code != 403 && w.Code != 200 {
					t.Errorf("unexpected status %d", w.Code)
					return
				}
				router.WAFCoverage()
			}
		}()
	}
	for i := 0; i < 6; i++ {
		st := stA
		if i%2 == 1 {
			st = stB
		}
		if err := router.ApplyWAFState(st); err != nil {
			t.Error(err)
		}
	}
	close(stop)
	wg.Wait()
}
