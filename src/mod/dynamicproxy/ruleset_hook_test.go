package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/ruleset"
)

func newRulesRouter(t *testing.T) (*Router, *ProxyEndpoint, *ruleset.Engine) {
	t.Helper()
	router, sep, _ := newNonTLSTestRouter(t)
	eng := ruleset.NewMemory()
	router.Option.Rules = eng
	return router, sep, eng
}

func fp(b bool) *bool { return &b }

// addRule creates an acting (not log-only) rule
func addRule(t testing.TB, eng *ruleset.Engine, site, name, expr string, act ruleset.Action) ruleset.RuleInfo {
	t.Helper()
	ri, err := eng.Create(site, ruleset.RuleInput{Name: name, Expression: expr, Action: act, DryRun: fp(false)}, -1)
	if err != nil {
		t.Fatalf("create %q: %v", name, err)
	}
	return ri
}

func rsGet(router *Router, sep *ProxyEndpoint, target, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	router.handleNonTLSRequest(w, r, sep)
	return w
}

const (
	okCode = 299 // the test chain ends in the plugin hook which answers 299
	rsIPA  = "198.51.100.1:1000"
	rsIPB  = "198.51.100.2:1000"
)

func TestRulesBlockAndNoRulesNoEffect(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	if w := rsGet(router, sep, "http://app.example.com/admin", rsIPA, nil); w.Code != okCode {
		t.Fatalf("no rules: %d", w.Code)
	}
	addRule(t, eng, "", "no admin from abroad", `http.path starts_with "/admin" and ip.country != "US"`, ruleset.Action{Type: ruleset.ActBlock})
	eng.Country = func(ip string) string {
		if ip == "198.51.100.2" {
			return "US"
		}
		return "DE"
	}
	if w := rsGet(router, sep, "http://app.example.com/admin/x", rsIPA, nil); w.Code != 403 {
		t.Fatalf("block: %d", w.Code)
	}
	if w := rsGet(router, sep, "http://app.example.com/admin/x", rsIPB, nil); w.Code != okCode {
		t.Fatalf("US client blocked: %d", w.Code)
	}
	if w := rsGet(router, sep, "http://app.example.com/public", rsIPA, nil); w.Code != okCode {
		t.Fatalf("other path blocked: %d", w.Code)
	}
	// the path is normalised: dodging with dot segments does not help
	if w := rsGet(router, sep, "http://app.example.com//x/../admin;a=b", rsIPA, nil); w.Code != 403 {
		t.Fatalf("normalisation bypass: %d", w.Code)
	}
	// a nil engine is the same as no rules
	router.Option.Rules = nil
	if w := rsGet(router, sep, "http://app.example.com/admin/x", rsIPA, nil); w.Code != okCode {
		t.Fatalf("nil engine: %d", w.Code)
	}
}

func TestRulesCustomBlockStatusAndBody(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	addRule(t, eng, "", "teapot", `http.path == "/tea"`, ruleset.Action{Type: ruleset.ActBlock, Status: 418, Body: "<b>no</b> tea"})
	addRule(t, eng, "", "gone", `http.path == "/gone"`, ruleset.Action{Type: ruleset.ActBlock, Status: 410})
	w := rsGet(router, sep, "http://app.example.com/tea", rsIPA, nil)
	if w.Code != 418 || w.Body.String() != "<b>no</b> tea" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("custom body: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	if w := rsGet(router, sep, "http://app.example.com/gone", rsIPA, nil); w.Code != 410 || !strings.Contains(w.Body.String(), "410") {
		t.Fatalf("status only: %d %q", w.Code, w.Body.String())
	}
}

func TestRulesAllowSkipsLaterRulesAndPrecedence(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	site := sep.RootOrMatchingDomain
	addRule(t, eng, site, "site blocks health", `http.path == "/health"`, ruleset.Action{Type: ruleset.ActBlock})
	addRule(t, eng, site, "site blocks bad", `http.path == "/bad"`, ruleset.Action{Type: ruleset.ActBlock})
	addRule(t, eng, "", "global allows health", `http.path == "/health"`, ruleset.Action{Type: ruleset.ActAllow})
	// global rules run before the site's, so the global allow wins for /health
	if w := rsGet(router, sep, "http://app.example.com/health", rsIPA, nil); w.Code != okCode {
		t.Fatalf("global allow must stop the site rules: %d", w.Code)
	}
	// but not for /bad
	if w := rsGet(router, sep, "http://app.example.com/bad", rsIPA, nil); w.Code != 403 {
		t.Fatalf("site rule ignored: %d", w.Code)
	}
	// a global block beats a site allow
	addRule(t, eng, "", "global blocks x", `http.path == "/x"`, ruleset.Action{Type: ruleset.ActBlock})
	addRule(t, eng, site, "site allows x", `http.path == "/x"`, ruleset.Action{Type: ruleset.ActAllow})
	if w := rsGet(router, sep, "http://app.example.com/x", rsIPA, nil); w.Code != 403 {
		t.Fatalf("global block overridden by a site allow: %d", w.Code)
	}
	// rules of one site do not apply to another
	other := &ProxyEndpoint{RootOrMatchingDomain: "other.example.com", parent: router, AuthenticationProvider: &AuthenticationProvider{}}
	if w := rsGet(router, other, "http://other.example.com/bad", rsIPA, nil); w.Code != okCode {
		t.Fatalf("site rules leaked to another site: %d", w.Code)
	}
	if w := rsGet(router, other, "http://other.example.com/x", rsIPA, nil); w.Code != 403 {
		t.Fatalf("global rule missing on another site: %d", w.Code)
	}
}

func TestRulesOrderAndReorder(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	a := addRule(t, eng, "", "teapot", `http.path starts_with "/p"`, ruleset.Action{Type: ruleset.ActBlock, Status: 418})
	b := addRule(t, eng, "", "forbidden", `http.path starts_with "/p"`, ruleset.Action{Type: ruleset.ActBlock})
	if w := rsGet(router, sep, "http://app.example.com/p", rsIPA, nil); w.Code != 418 {
		t.Fatalf("first rule must win: %d", w.Code)
	}
	if err := eng.Reorder("", []string{b.ID, a.ID}); err != nil {
		t.Fatal(err)
	}
	if w := rsGet(router, sep, "http://app.example.com/p", rsIPA, nil); w.Code != 403 {
		t.Fatalf("reorder ignored: %d", w.Code)
	}
}

func TestRulesDisabledAndDryRun(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	r := addRule(t, eng, "", "blocker", `http.path == "/b"`, ruleset.Action{Type: ruleset.ActBlock})
	if _, err := eng.SetEnabled("", r.ID, false); err != nil {
		t.Fatal(err)
	}
	if w := rsGet(router, sep, "http://app.example.com/b", rsIPA, nil); w.Code != okCode {
		t.Fatalf("disabled rule acted: %d", w.Code)
	}
	if got := eng.Rules("")[0].Stats; got.Hits+got.DryRun != 0 {
		t.Fatalf("disabled rule counted: %+v", got)
	}
	eng.SetEnabled("", r.ID, true)
	// log-only: counted and recorded, never acts
	if _, err := eng.SetDryRun("", r.ID, true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if w := rsGet(router, sep, "http://app.example.com/b", rsIPA, nil); w.Code != okCode {
			t.Fatalf("dry-run rule acted: %d", w.Code)
		}
	}
	st := eng.Rules("")[0].Stats
	if st.DryRun != 3 || st.Hits != 0 || st.LastHit == 0 || st.Last24h != 3 {
		t.Fatalf("dry-run counters: %+v", st)
	}
	if rec := eng.RecentHits(); len(rec) != 3 || !rec[0].DryRun || rec[0].Path != "/b" || rec[0].Rule != "blocker" {
		t.Fatalf("recent hits: %+v", rec)
	}
	// a dry-run block must not reach the blocked log or the abuse counters either
	eng.SetDryRun("", r.ID, false)
	rsGet(router, sep, "http://app.example.com/b", rsIPA, nil)
	st = eng.Rules("")[0].Stats
	if st.Hits != 1 || st.Last24h != 4 || st.Hourly[23] != 4 {
		t.Fatalf("acting counters: %+v", st)
	}
}

func TestRulesLogDoesNotStopEvaluation(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	addRule(t, eng, "", "watch", `http.path starts_with "/w"`, ruleset.Action{Type: ruleset.ActLog})
	addRule(t, eng, "", "then block", `http.path starts_with "/w"`, ruleset.Action{Type: ruleset.ActBlock})
	if w := rsGet(router, sep, "http://app.example.com/w", rsIPA, nil); w.Code != 403 {
		t.Fatalf("%d", w.Code)
	}
	rs := eng.Rules("")
	if rs[0].Stats.Hits != 1 || rs[1].Stats.Hits != 1 {
		t.Fatalf("both rules must have matched: %+v %+v", rs[0].Stats, rs[1].Stats)
	}
}

func TestRulesRedirect(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	addRule(t, eng, "", "old", `http.path starts_with "/old"`, ruleset.Action{Type: ruleset.ActRedirect, Status: 301, URL: "https://new.example.org{uri}"})
	addRule(t, eng, "", "rel", `http.path == "/rel"`, ruleset.Action{Type: ruleset.ActRedirect, URL: "/landing?from={path}"})
	addRule(t, eng, "", "evil", `http.path starts_with "/evil"`, ruleset.Action{Type: ruleset.ActRedirect, URL: "/{path}"})
	w := rsGet(router, sep, "http://app.example.com/old/page?a=1&b=2", rsIPA, nil)
	if w.Code != 301 || w.Header().Get("Location") != "https://new.example.org/old/page?a=1&b=2" {
		t.Fatalf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = rsGet(router, sep, "http://app.example.com/rel", rsIPA, nil)
	if w.Code != 302 || w.Header().Get("Location") != "/landing?from=/rel" {
		t.Fatalf("relative redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	// a request path cannot turn a relative redirect into another host
	r := httptest.NewRequest("GET", "http://app.example.com/evil", nil)
	r.URL.Path = "//attacker.example/x"
	r.RequestURI = "//attacker.example/x"
	r.RemoteAddr = rsIPA
	rec := httptest.NewRecorder()
	router.handleNonTLSRequest(rec, r, sep)
	loc := rec.Header().Get("Location")
	if rec.Code != okCode && (strings.HasPrefix(loc, "//") || strings.Contains(loc, "\n")) {
		t.Fatalf("open redirect: %q", loc)
	}
	// CR/LF in the query cannot split the header
	w = rsGet(router, sep, "http://app.example.com/old?x=%0d%0aSet-Cookie:%20a=b", rsIPA, nil)
	if strings.ContainsAny(w.Header().Get("Location"), "\r\n") || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("header injection: %v", w.Header())
	}
}

func TestRulesRequestHeaderActions(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	var seen http.Header
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, s *ProxyEndpoint) bool {
		seen = r.Header.Clone()
		w.WriteHeader(okCode)
		return true
	}
	addRule(t, eng, "", "set", `http.path == "/h"`, ruleset.Action{Type: ruleset.ActSetReqH, Name: "X-From-Rules", Value: "yes"})
	addRule(t, eng, "", "del", `http.path == "/h"`, ruleset.Action{Type: ruleset.ActDelReqH, Name: "X-Secret"})
	w := rsGet(router, sep, "http://app.example.com/h", rsIPA, map[string]string{"X-Secret": "s", "X-Keep": "k"})
	if w.Code != okCode || seen.Get("X-From-Rules") != "yes" || seen.Get("X-Secret") != "" || seen.Get("X-Keep") != "k" {
		t.Fatalf("request headers: %d %v", w.Code, seen)
	}
}

func TestRulesResponseHeadersAndRequestHeadersThroughProxy(t *testing.T) {
	var gotUpstream http.Header
	h, _, _ := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) {})
	_ = gotUpstream
	eng := ruleset.NewMemory()
	h.Parent.Option.Rules = eng
	addRule(t, eng, "", "resp set", `http.path == "/r"`, ruleset.Action{Type: ruleset.ActSetRespH, Name: "X-Frame-Options", Value: "DENY"})
	addRule(t, eng, "", "resp del", `http.path == "/r"`, ruleset.Action{Type: ruleset.ActDelRespH, Name: "Server"})
	addRule(t, eng, "", "req set", `http.path == "/r"`, ruleset.Action{Type: ruleset.ActSetReqH, Name: "X-Edge", Value: "1"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("GET", "/r", nil, nil))
	if w.Code != 200 || w.Body.String() != "upstream-ok" {
		t.Fatalf("proxy: %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Server") != "" {
		t.Fatalf("response header actions not applied: %v", w.Header())
	}
	// untouched path: no change
	w = httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("GET", "/other", nil, nil))
	if w.Header().Get("X-Frame-Options") != "" {
		t.Fatal("header leaked to a path the rule does not match")
	}
}

func TestRulesSkipWAFAndOtherProtections(t *testing.T) {
	h, hits, _ := newWAFTestProxy(t, &waf.Config{Mode: waf.ModeBlock})
	eng := ruleset.NewMemory()
	h.Parent.Option.Rules = eng
	attack := "/item?id=1%27%20OR%20%271%27%3D%271"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("GET", attack, nil, nil))
	if w.Code != 403 {
		t.Fatalf("baseline: the WAF must block this: %d", w.Code)
	}
	addRule(t, eng, "", "legacy endpoint", `http.path == "/item"`, ruleset.Action{Type: ruleset.ActSkip, Skip: []string{ruleset.SkipWAF}})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("GET", attack, nil, nil))
	if w.Code != 200 || atomic.LoadInt32(hits) != 1 {
		t.Fatalf("skip waf: %d hits=%d", w.Code, atomic.LoadInt32(hits))
	}
	// the skip only covers the path of the rule
	w = httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("GET", "/other?id=1%27%20OR%20%271%27%3D%271", nil, nil))
	if w.Code != 403 {
		t.Fatalf("skip leaked to another path: %d", w.Code)
	}
}

func TestRulesSkipRateLimitAndCaptchaAndRules(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	sep.RequireRateLimit, sep.RateLimit, sep.RateLimitBurst = true, 1, 1
	hit := func() int { return rsGet(router, sep, "http://app.example.com/rl", rsIPA, nil).Code }
	hit()
	if c := hit(); c != 429 {
		t.Fatalf("baseline rate limit: %d", c)
	}
	addRule(t, eng, "", "no limit for me", `ip.src == "198.51.100.1"`, ruleset.Action{Type: ruleset.ActSkip, Skip: []string{ruleset.SkipRateLimit}})
	for i := 0; i < 5; i++ {
		if c := hit(); c != okCode {
			t.Fatalf("skip rate_limit: %d", c)
		}
	}
	// captcha gate
	router.captchaSessionStore = captcha.NewSessionStore()
	sep.RequireCaptcha = true
	sep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderCloudflare, SiteKey: "k", SecretKey: "s"}
	sep.RequireRateLimit = false
	if c := rsGet(router, sep, "http://app.example.com/c", rsIPA, nil).Code; c == okCode {
		t.Fatal("captcha gate should hold the request")
	}
	addRule(t, eng, "", "no captcha for /c", `http.path == "/c"`, ruleset.Action{Type: ruleset.ActSkip, Skip: []string{ruleset.SkipCaptcha}})
	if c := rsGet(router, sep, "http://app.example.com/c", rsIPA, nil).Code; c != okCode {
		t.Fatalf("skip captcha: %d", c)
	}
	// skip "rules" stops later rules
	sep.RequireCaptcha = false
	addRule(t, eng, "", "stop here", `http.path == "/s"`, ruleset.Action{Type: ruleset.ActSkip, Skip: []string{ruleset.SkipRules}})
	addRule(t, eng, "", "later block", `http.path == "/s"`, ruleset.Action{Type: ruleset.ActBlock})
	if c := rsGet(router, sep, "http://app.example.com/s", rsIPA, nil).Code; c != okCode {
		t.Fatalf("skip rules must stop the later block rule: %d", c)
	}
}

func TestRulesRateLimitAction(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	addRule(t, eng, "", "login limit", `http.path == "/login"`, ruleset.Action{Type: ruleset.ActRateLimit, Rate: 1, Burst: 2})
	codes := []int{}
	for i := 0; i < 4; i++ {
		codes = append(codes, rsGet(router, sep, "http://app.example.com/login", rsIPA, nil).Code)
	}
	if codes[0] != okCode || codes[1] != okCode || codes[3] != 429 {
		t.Fatalf("burst of two then limited: %v", codes)
	}
	// another client has its own bucket
	if c := rsGet(router, sep, "http://app.example.com/login", rsIPB, nil).Code; c != okCode {
		t.Fatalf("buckets are per client: %d", c)
	}
	// other paths are not limited
	if c := rsGet(router, sep, "http://app.example.com/other", rsIPA, nil).Code; c != okCode {
		t.Fatalf("limit leaked: %d", c)
	}
}

func TestRulesChallengeFallbackAndPass(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	addRule(t, eng, "", "challenge scrapers", `http.path starts_with "/data"`, ruleset.Action{Type: ruleset.ActChallenge, TTLMinutes: 5})

	// no CAPTCHA provider on the site: fail closed
	if c := rsGet(router, sep, "http://app.example.com/data", rsIPA, nil).Code; c != 403 {
		t.Fatalf("challenge without provider must block: %d", c)
	}
	items := waitBlocked(t, bl, 1)
	if items[0].Reason != "rule" || items[0].Detail != "challenge scrapers" && !strings.Contains(items[0].Detail, "challenge scrapers") {
		t.Fatalf("blocked log entry: %+v", items[0])
	}

	sep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderCloudflare, SiteKey: "k", SecretKey: "s"}
	w := rsGet(router, sep, "http://app.example.com/data", rsIPA, nil)
	body := strings.ToLower(w.Body.String())
	if w.Code == okCode || !(strings.Contains(body, "captcha") || strings.Contains(body, "turnstile")) {
		t.Fatalf("no challenge page: %d", w.Code)
	}
	// other paths are not challenged
	if c := rsGet(router, sep, "http://app.example.com/home", rsIPA, nil).Code; c != okCode {
		t.Fatalf("%d", c)
	}
	// a valid pass cookie lets the request through; the WAF challenge cookie does not count
	ua := "Mozilla/5.0 test"
	val, _ := router.wafChallengeSigner().Issue(ruleChallengeScope(sep), "198.51.100.1", ua, time.Minute)
	if c := rsGet(router, sep, "http://app.example.com/data", rsIPA, map[string]string{"User-Agent": ua, "Cookie": ruleChallengeCookie + "=" + val}).Code; c != okCode {
		t.Fatalf("valid pass rejected: %d", c)
	}
	if c := rsGet(router, sep, "http://app.example.com/data", rsIPB, map[string]string{"User-Agent": ua, "Cookie": ruleChallengeCookie + "=" + val}).Code; c == okCode {
		t.Fatal("pass cookie accepted for another client address")
	}
	if c := rsGet(router, sep, "http://app.example.com/data", rsIPA, map[string]string{"User-Agent": "other", "Cookie": ruleChallengeCookie + "=" + val}).Code; c == okCode {
		t.Fatal("pass cookie accepted for another User-Agent")
	}
	wafVal, _ := router.wafChallengeSigner().Issue(sep.RootOrMatchingDomain, "198.51.100.1", ua, time.Minute)
	if c := rsGet(router, sep, "http://app.example.com/data", rsIPA, map[string]string{"User-Agent": ua, "Cookie": wafChallengeCookie + "=" + wafVal}).Code; c == okCode {
		t.Fatal("a WAF challenge cookie must not pass a rule challenge")
	}
	// the verification endpoint is answered by the CAPTCHA package, not forwarded
	req := httptest.NewRequest("POST", "http://app.example.com"+captcha.VerifyPath, strings.NewReader(""))
	req.RemoteAddr = rsIPA
	rec := httptest.NewRecorder()
	router.handleNonTLSRequest(rec, req, sep)
	if rec.Code == okCode {
		t.Fatal("verification request was forwarded")
	}
}

func TestRulesBlockedLogCategoryAndTags(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	addRule(t, eng, "", "tag scanners", `lower(http.user_agent) contains "scan"`, ruleset.Action{Type: ruleset.ActTag, Tag: "scanner"})
	addRule(t, eng, "", "block admin", `http.path starts_with "/admin"`, ruleset.Action{Type: ruleset.ActBlock})
	rsGet(router, sep, "http://app.example.com/admin", rsIPA, map[string]string{"User-Agent": "MyScanner/1"})
	rsGet(router, sep, "http://app.example.com/admin", rsIPB, map[string]string{"User-Agent": "firefox"})
	items := waitBlocked(t, bl, 2)
	a, b := findBlocked(items, "198.51.100.1"), findBlocked(items, "198.51.100.2")
	if a == nil || b == nil {
		t.Fatalf("entries: %+v", items)
	}
	if a.Reason != blocklog.ReasonRule || a.Detail != "block admin" || a.Status != 403 || len(a.Tags) != 1 || a.Tags[0] != "scanner" {
		t.Fatalf("entry: %+v", a)
	}
	if b.Reason != "rule" || len(b.Tags) != 0 {
		t.Fatalf("untagged entry: %+v", b)
	}
	if !blocklog.IsBlocked("rule-block") || blocklog.IsBlocked("rule-redirect") || blocklog.IsBlocked("rule-log") {
		t.Fatal("classification")
	}
}

func TestRulesAbuseOnlyWhenOptedIn(t *testing.T) {
	for _, report := range []bool{false, true} {
		router, sep, eng := newRulesRouter(t)
		m := abuse.New("")
		c := abuse.DefaultConfig()
		c.Enabled = true
		c.Detectors[abuse.KindForbidden] = abuse.Detector{Enabled: true, Threshold: 3, WindowSec: 60}
		if err := m.SetConfig(c); err != nil {
			t.Fatal(err)
		}
		router.Option.Abuse = m
		addRule(t, eng, "", "blocker", `http.path == "/no"`, ruleset.Action{Type: ruleset.ActBlock, ReportAbuse: report})
		for i := 0; i < 6; i++ {
			rsGet(router, sep, "http://app.example.com/no", rsIPA, nil)
		}
		_, banned := m.IsBanned("198.51.100.1", sep.RootOrMatchingDomain)
		if banned != report {
			t.Fatalf("report_abuse=%v but banned=%v", report, banned)
		}
	}
	// log-only blocks never report either
	router, sep, eng := newRulesRouter(t)
	m := abuse.New("")
	c := abuse.DefaultConfig()
	c.Enabled = true
	c.Detectors[abuse.KindForbidden] = abuse.Detector{Enabled: true, Threshold: 2, WindowSec: 60}
	m.SetConfig(c)
	router.Option.Abuse = m
	eng.Create("", ruleset.RuleInput{Name: "dry", Expression: `http.path == "/no"`, Action: ruleset.Action{Type: ruleset.ActBlock, ReportAbuse: true}}, -1) //dry-run by default
	for i := 0; i < 6; i++ {
		if c := rsGet(router, sep, "http://app.example.com/no", rsIPA, nil).Code; c != okCode {
			t.Fatalf("dry-run acted: %d", c)
		}
	}
	if _, banned := m.IsBanned("198.51.100.1", sep.RootOrMatchingDomain); banned {
		t.Fatal("a log-only rule fed the ban")
	}
}

func TestRulesLists(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	if _, err := eng.SaveList(ruleset.List{Name: "office", Type: ruleset.ListIP, Items: []string{"198.51.100.0/30"}}); err != nil {
		t.Fatal(err)
	}
	addRule(t, eng, "", "office only", `http.path starts_with "/internal" and ip.src not in $office`, ruleset.Action{Type: ruleset.ActBlock})
	if c := rsGet(router, sep, "http://app.example.com/internal", rsIPA, nil).Code; c != okCode {
		t.Fatalf("office address blocked: %d", c)
	}
	if c := rsGet(router, sep, "http://app.example.com/internal", "203.0.113.50:1", nil).Code; c != 403 {
		t.Fatalf("outsider passed: %d", c)
	}
	// editing the list takes effect at once
	eng.SaveList(ruleset.List{Name: "office", Type: ruleset.ListIP, Items: []string{"203.0.113.0/24"}})
	if c := rsGet(router, sep, "http://app.example.com/internal", rsIPA, nil).Code; c != 403 {
		t.Fatalf("list edit ignored: %d", c)
	}
	// a list in use cannot be deleted
	if err := eng.DeleteList("office"); err == nil {
		t.Fatal("deleting a list in use must fail")
	}
}

func TestRulesDefaultSite(t *testing.T) {
	router, _, eng := newRulesRouter(t)
	addRule(t, eng, ruleset.DefaultSiteKey, "default site rule", `http.path == "/x"`, ruleset.Action{Type: ruleset.ActBlock})
	addRule(t, eng, "", "global", `http.path == "/g"`, ruleset.Action{Type: ruleset.ActBlock})
	root := &ProxyEndpoint{RootOrMatchingDomain: "/", ProxyType: ProxyTypeRoot, parent: router, AuthenticationProvider: &AuthenticationProvider{}}
	router.Root = root
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://unknown.example.com/x", nil)
	r.RemoteAddr = rsIPA
	handled, _ := router.handleRuleset(w, r, root)
	if !handled || w.Code != 403 {
		t.Fatalf("default site rule: handled=%v %d", handled, w.Code)
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "http://unknown.example.com/g", nil)
	r.RemoteAddr = rsIPA
	if handled, _ := router.handleRuleset(w, r, root); !handled {
		t.Fatal("global rule must apply to the default site")
	}
	// the default site key does not apply to a normal site
	sep := &ProxyEndpoint{RootOrMatchingDomain: "app.example.com", parent: router}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "http://app.example.com/x", nil)
	r.RemoteAddr = rsIPA
	if handled, _ := router.handleRuleset(w, r, sep); handled {
		t.Fatal("default site rule leaked")
	}
}

func TestRulesTrustedProxyClientIP(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	rule, _ := router.Option.AccessController.GetAccessRuleByID("default")
	rule.TrustProxyHeadersOnly = true
	addRule(t, eng, "", "block attacker", `ip.src == "203.0.113.66"`, ruleset.Action{Type: ruleset.ActBlock})
	// an untrusted peer cannot make itself look like (or hide as) another address with forwarded headers
	if c := rsGet(router, sep, "http://app.example.com/", "198.51.100.1:1", map[string]string{"X-Forwarded-For": "203.0.113.66"}).Code; c != okCode {
		t.Fatalf("spoofed forwarded header framed a client: %d", c)
	}
	if c := rsGet(router, sep, "http://app.example.com/", "203.0.113.66:1", map[string]string{"X-Forwarded-For": "198.51.100.1"}).Code; c != 403 {
		t.Fatalf("spoofed forwarded header hid the attacker: %d", c)
	}
}

func TestRulesBrokenRuleDoesNotBreakOthers(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	eng.SaveList(ruleset.List{Name: "l", Type: ruleset.ListString, Items: []string{"a"}})
	addRule(t, eng, "", "uses list", `http.host in $l`, ruleset.Action{Type: ruleset.ActBlock})
	addRule(t, eng, "", "plain", `http.path == "/p"`, ruleset.Action{Type: ruleset.ActBlock})
	if c := rsGet(router, sep, "http://app.example.com/p", rsIPA, nil); c.Code != 403 {
		t.Fatalf("%d", c.Code)
	}
}

// ---- benchmarks: the numbers in the PR description

func benchRequest() *http.Request {
	r := httptest.NewRequest("GET", "http://app.example.com/products/list?page=2&sort=asc", nil)
	r.RemoteAddr = "198.51.100.1:1000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36")
	r.Header.Set("Referer", "https://app.example.com/")
	r.Header.Set("Cookie", "session=abc123")
	return r
}

func benchHandle(b *testing.B, eng *ruleset.Engine) {
	router := &Router{Option: &RouterOption{Rules: eng}}
	sep := &ProxyEndpoint{RootOrMatchingDomain: "app.example.com"}
	r := benchRequest()
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.handleRuleset(w, r, sep)
	}
}

func BenchmarkRulesHandleNilEngine(b *testing.B) { benchHandle(b, nil) }

func BenchmarkRulesHandleEmptyEngine(b *testing.B) { benchHandle(b, ruleset.NewMemory()) }

func BenchmarkRulesHandleTwentyRulesNoMatch(b *testing.B) {
	eng := ruleset.NewMemory()
	eng.Country = func(string) string { return "US" }
	eng.SaveList(ruleset.List{Name: "bad", Type: ruleset.ListIP, Items: []string{"203.0.113.0/24", "192.0.2.0/24", "2001:db8::/32"}})
	exprs := []string{
		`http.path starts_with "/admin" and ip.country != "US"`,
		`http.path starts_with "/wp-admin" or http.path starts_with "/phpmyadmin"`,
		`lower(http.user_agent) contains "sqlmap" or lower(http.user_agent) contains "nikto"`,
		`http.user_agent matches "(?i)(curl|wget|python-requests)/"`,
		`ip.src in $bad`,
		`ip.country in ["CN", "RU", "KP"]`,
		`http.method not in ["GET", "HEAD", "POST", "OPTIONS"]`,
		`http.header["x-forwarded-host"] exists`,
		`http.query_arg["debug"] == "1"`,
		`http.cookie["admin"] exists`,
		`req.size > 10485760`,
		`http.path matches "\\.(php|asp|jsp)$"`,
		`http.referer contains "spam.example"`,
		`http.host != "app.example.com" and not ip.is_private`,
		`http.path contains "../" or http.path contains "%00"`,
		`http.version == "HTTP/1.0"`,
		`tls.version in ["TLSv1.0", "TLSv1.1"]`,
		`http.content_type starts_with "multipart/" and req.size > 1048576`,
		`http.query matches "(?i)union\\s+select"`,
		`http.header["user-agent"] not exists`,
	}
	for i, e := range exprs {
		if _, err := eng.Create("", ruleset.RuleInput{Name: "r" + string(rune('a'+i)), Expression: e, Action: ruleset.Action{Type: ruleset.ActBlock}, DryRun: fp(false)}, -1); err != nil {
			b.Fatalf("%s: %v", e, err)
		}
	}
	benchHandle(b, eng)
}
