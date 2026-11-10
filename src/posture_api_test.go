package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
	"imuslab.com/zoraxy/mod/apitoken"
	"imuslab.com/zoraxy/mod/auth"
	db "imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/posture"
)

const postureSentinel = "SENTINEL-SECRET-d41d8cd9"

// postureTestSystem prepares the globals the glue reads: a router with one proxy rule, a WAF file, a system database
func postureTestSystem(t *testing.T) *dynamicproxy.Router {
	t.Helper()
	router := setupWAFCentralTest(t)
	oldDB, oldAuth, oldEngine, oldTabs := sysdb, authAgent, postureEngine, apiTokenManager
	d, err := db.NewDatabase(filepath.Join(t.TempDir(), "sys"), db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	sysdb = d
	sysdb.NewTable(postureTable)
	sysdb.NewTable("fwdproxy")
	postureEngine = nil
	postureEngine = getPostureEngine()
	t.Cleanup(func() {
		d.Close()
		sysdb, authAgent, postureEngine, apiTokenManager = oldDB, oldAuth, oldEngine, oldTabs
	})
	return router
}

func findCheck(t *testing.T, o posture.Overview, id string) posture.CheckResult {
	t.Helper()
	for _, c := range o.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %s", id)
	return posture.CheckResult{}
}

func TestPostureFactsFromTheRealRouter(t *testing.T) {
	router := postureTestSystem(t)
	f := collectPostureFacts()
	if f.Proxy == nil || f.Admin == nil || f.WAF == nil {
		t.Fatalf("sections missing: %+v", f)
	}
	rules := f.Proxy.HostRules()
	if len(rules) != 1 || rules[0].Name != "app.example.com" || !rules[0].RateLimit || rules[0].UptimeMonitor {
		t.Fatalf("%+v", f.Proxy.Rules)
	}
	if rules[0].WAFMode != "off" {
		t.Fatalf("a fresh WAF must read as off, got %q", rules[0].WAFMode)
	}
	// sections whose module is not running are unknown, never invented
	if f.Visitors != nil || f.Tokens != nil || f.Updater != nil {
		t.Fatalf("sections of absent modules must be nil: %+v", f)
	}
	_ = router
}

// Applying an action goes through the real internal functions: the router, the WAF file and the proxy rule change.
func TestPostureApplyWAFEndToEnd(t *testing.T) {
	router := postureTestSystem(t)
	e := postureEngine
	before := e.Overview(true)
	if findCheck(t, before, "waf.active").Status != posture.StatusFail {
		t.Fatalf("waf.active = %+v", findCheck(t, before, "waf.active"))
	}
	ps, err := e.Preview([]string{"waf.baseline"})
	if err != nil || ps[0].Refusal != "" || len(ps[0].Changes) == 0 {
		t.Fatalf("%v %+v", err, ps)
	}
	rs, err := e.Apply([]posture.ApplyRequest{{ID: "waf.baseline", Hash: ps[0].Hash}}, posture.Actor{Name: "root", IP: "192.0.2.1"})
	if err != nil || rs[0].Status != "applied" {
		t.Fatalf("%v %+v", err, rs)
	}
	pol := router.WAFState().Policy
	if !pol.Enabled || pol.DefaultMode != waf.ModeDetectionOnly || pol.ParanoiaLevel != 1 {
		t.Fatalf("%+v", pol)
	}
	st, err := loadWAFCentralState(CONF_WAF_CENTRAL)
	if err != nil || !st.Policy.Enabled {
		t.Fatalf("not persisted: %v %+v", err, st)
	}
	var cov []struct{ Mode string }
	wafGet(t, HandleWAFCoverage, "/api/waf/coverage", &cov)
	if len(cov) == 0 || cov[len(cov)-1].Mode != "detection_only" && cov[0].Mode != "detection_only" {
		t.Fatalf("the WAF page would not show the new mode: %+v", cov)
	}
	after := e.Overview(true)
	if after.Score.Value <= before.Score.Value {
		t.Fatalf("score did not improve: %d -> %d", before.Score.Value, after.Score.Value)
	}
	if findCheck(t, after, "waf.active").Status != posture.StatusOK {
		t.Fatalf("%+v", findCheck(t, after, "waf.active"))
	}
	// idempotent
	ps, _ = e.Preview([]string{"waf.baseline"})
	if !ps[0].NoOp {
		t.Fatalf("%+v", ps[0])
	}
	// undo restores the policy
	if r, err := e.Undo("waf.baseline", posture.Actor{Name: "root"}); err != nil || r.Status != "undone" {
		t.Fatalf("%v %+v", err, r)
	}
	if router.WAFState().Policy.Enabled {
		t.Fatal("undo did not switch the WAF off again")
	}
}

func TestPostureBackendUptimeAndHSTSUseTheAdminHandlers(t *testing.T) {
	router := postureTestSystem(t)
	b := postureBackend{}
	if ep, _ := router.LoadProxy("app.example.com"); ep.HeaderRewriteRules == nil {
		if err := b.Set("hsts.app.example.com", "31536000"); err == nil {
			t.Fatal("HSTS was set on a rule without header settings (the admin handler would panic)")
		}
		ep.HeaderRewriteRules = &dynamicproxy.HeaderRewriteRules{}
	}
	if v, _ := b.Get("uptime.app.example.com"); v != "off" {
		t.Fatalf("uptime = %q", v)
	}
	if err := b.Set("uptime.app.example.com", "on"); err != nil {
		t.Fatal(err)
	}
	ep, _ := router.LoadProxy("app.example.com")
	if ep.DisableUptimeMonitor {
		t.Fatal("uptime monitor still disabled")
	}
	// the other settings of the rule are untouched (partial update)
	if !ep.RequireRateLimit || ep.RateLimit != 50 || ep.UptimeMonitorURI != "/healthz" || !ep.RequireCaptcha {
		t.Fatalf("a field other than the uptime monitor changed: %+v", ep)
	}
	if err := b.Set("hsts.app.example.com", "31536000"); err != nil {
		t.Fatal(err)
	}
	ep, _ = router.LoadProxy("app.example.com")
	if ep.HeaderRewriteRules == nil || ep.HeaderRewriteRules.HSTSMaxAge != 31536000 {
		t.Fatalf("%+v", ep.HeaderRewriteRules)
	}
	if v, _ := b.Get("hsts.app.example.com"); v != "31536000" {
		t.Fatalf("hsts = %q", v)
	}
	if err := b.Set("hsts.app.example.com", "5"); err == nil {
		t.Fatal("the admin handler's validation (max-age >= 1 year or 0) was bypassed")
	}
	if err := b.Set("uptime.nope.example.com", "on"); err == nil {
		t.Fatal("an unknown rule was accepted")
	}
	if err := b.Set("waf.mode", "turbo"); err == nil {
		t.Fatal("an invalid WAF mode was accepted")
	}
	if err := b.Set("nonsense", "x"); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestPostureResponsesContainNoSecrets(t *testing.T) {
	router := postureTestSystem(t)
	ep, _ := router.LoadProxy("app.example.com")
	ep.CaptchaConfig.SecretKey, ep.CaptchaConfig.SiteKey = postureSentinel+"-captcha", postureSentinel+"-site"
	ep.AuthenticationProvider = &dynamicproxy.AuthenticationProvider{
		AuthMethod:           dynamicproxy.AuthMethodForward,
		ForwardAuthURL:       "http://user:" + postureSentinel + "@auth.example.com/verify?token=" + postureSentinel,
		BasicAuthCredentials: []*dynamicproxy.BasicAuthCredentials{{Username: "bob", PasswordHash: postureSentinel + "-hash"}},
	}
	mgr, err := apitoken.NewManager(&v1KV{m: map[string][]byte{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	apiTokenManager = mgr
	secretToken, _, _ := mgr.Create("ci", apitoken.ScopeRead, 0, nil)

	e := postureEngine
	o := e.Overview(true)
	ps, _ := e.Preview([]string{"waf.baseline", "uptime.enable", "hsts.enable", "https.redirect", "autoban.enable"})
	js, _ := json.Marshal(map[string]interface{}{"overview": o, "previews": ps})
	for _, bad := range []string{postureSentinel, secretToken, "PasswordHash", "SecretKey"} {
		if strings.Contains(string(js), bad) {
			t.Fatalf("the response leaks %q:\n%s", bad, js)
		}
	}
	// the forward auth URL is plain http to a hostname: flagged, without printing the URL
	c := findCheck(t, o, "auth.sso_transport")
	if c.Status != posture.StatusWarn || strings.Contains(strings.Join(c.Evidence, " "), "user:") {
		t.Fatalf("%+v", c)
	}
}

/* ---- HTTP: authentication, roles, CSRF ---- */

func postureHTTPSetup(t *testing.T) (http.Handler, *http.Cookie, *http.Cookie) {
	t.Helper()
	postureTestSystem(t)
	lg, _ := logger.NewFmtLogger()
	old := auth.ProfileAdmin
	auth.ProfileAdmin = auth.PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1}
	t.Cleanup(func() { auth.ProfileAdmin = old })
	authAgent = auth.NewAuthenticationAgent("t", []byte("0123456789abcdef0123456789abcdef"), sysdb, false, lg, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "401", http.StatusUnauthorized) })
	authAgent.CreateUserAccount("root", "password-1", "")
	authAgent.CreateUser("view", "password-2", auth.RoleViewer)

	mux := http.NewServeMux()
	rt := auth.NewManagedHTTPRouter(auth.RouterOption{AuthAgent: authAgent, RequireAuth: true, TargetMux: mux,
		DeniedHandler: func(w http.ResponseWriter, r *http.Request) { http.Error(w, "401", http.StatusUnauthorized) }})
	rt.HandleFunc("/api/security/posture", HandlePostureGet)
	rt.HandleFunc("/api/security/posture/preview", HandlePosturePreview)
	rt.HandleFunc("/api/security/posture/apply", HandlePostureApply)
	rt.HandleFunc("/api/security/posture/undo", HandlePostureUndo)
	rt.HandleFunc("/api/security/posture/settings", HandlePostureSettings)
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(csrf.Token(r))) })
	protected := csrf.Protect([]byte("0123456789abcdef0123456789abcdef"), csrf.Secure(false), csrf.Path("/"))(mux)

	login := func(user, pw string) *http.Cookie {
		form := strings.NewReader("username=" + user + "&password=" + pw)
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", form)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		authAgent.HandleLogin(w, r)
		for _, c := range w.Result().Cookies() {
			if c.Name == authAgent.SessionName && c.Value != "" {
				return c
			}
		}
		t.Fatal("login failed for " + user)
		return nil
	}
	return protected, login("root", "password-1"), login("view", "password-2")
}

func postureCall(h http.Handler, method, path, body string, cookies []*http.Cookie, token string, csrfCookies []*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range append(append([]*http.Cookie{}, cookies...), csrfCookies...) {
		r.AddCookie(c)
	}
	if token != "" {
		r.Header.Set("X-CSRF-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPostureAPIAuthRolesAndCSRF(t *testing.T) {
	h, adminC, viewC := postureHTTPSetup(t)

	// 1. no session: nothing is served
	for _, ep := range []string{"/api/security/posture", "/api/security/posture/preview", "/api/security/posture/apply", "/api/security/posture/undo", "/api/security/posture/settings"} {
		if w := postureCall(h, "GET", ep, "", nil, "", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous GET %s = %d", ep, w.Code)
		}
	}

	// a CSRF cookie + token pair, as the admin page gets from the index
	w := postureCall(h, "GET", "/token", "", []*http.Cookie{adminC}, "", nil)
	token, csrfCookies := w.Body.String(), w.Result().Cookies()
	if token == "" || len(csrfCookies) == 0 {
		t.Fatal("no CSRF token issued")
	}

	// 2. admin read works and is read only
	w = postureCall(h, "GET", "/api/security/posture", "", []*http.Cookie{adminC}, "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"checks"`) || !strings.Contains(w.Body.String(), `"score"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if postureCall(h, "POST", "/api/security/posture", "{}", []*http.Cookie{adminC}, token, csrfCookies).Code != http.StatusMethodNotAllowed {
		t.Error("POST to the read endpoint must be refused")
	}

	// 3. mutating endpoints: POST only
	for _, ep := range []string{"/api/security/posture/preview", "/api/security/posture/apply", "/api/security/posture/undo", "/api/security/posture/settings"} {
		if w := postureCall(h, "GET", ep, "", []*http.Cookie{adminC}, "", nil); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", ep, w.Code)
		}
	}

	// 4. without a CSRF token a mutation is refused before it reaches the handler
	body := `{"actions":[{"id":"waf.baseline","hash":"x"}]}`
	if w := postureCall(h, "POST", "/api/security/posture/apply", body, []*http.Cookie{adminC}, "", csrfCookies); w.Code != http.StatusForbidden {
		t.Errorf("apply without CSRF token = %d", w.Code)
	}
	if w := postureCall(h, "POST", "/api/security/posture/apply", body, []*http.Cookie{adminC}, "wrong-token", csrfCookies); w.Code != http.StatusForbidden {
		t.Errorf("apply with a wrong CSRF token = %d", w.Code)
	}
	if router := dynamicProxyRouter; router.WAFState().Policy.Enabled {
		t.Fatal("a refused request changed the WAF")
	}

	// 5. a viewer may read but never preview, apply, undo or change settings
	if w := postureCall(h, "GET", "/api/security/posture", "", []*http.Cookie{viewC}, "", nil); w.Code != 200 {
		t.Errorf("viewer read = %d", w.Code)
	}
	vt := postureCall(h, "GET", "/token", "", []*http.Cookie{viewC}, "", nil)
	for _, ep := range []string{"/api/security/posture/preview", "/api/security/posture/apply", "/api/security/posture/undo", "/api/security/posture/settings"} {
		if w := postureCall(h, "POST", ep, body, []*http.Cookie{viewC}, vt.Body.String(), vt.Result().Cookies()); w.Code != http.StatusForbidden {
			t.Errorf("viewer POST %s = %d", ep, w.Code)
		}
	}

	// 6. the full flow as admin: preview, apply with the hash, audit entry
	w = postureCall(h, "POST", "/api/security/posture/preview", `{"actions":["waf.baseline"]}`, []*http.Cookie{adminC}, token, csrfCookies)
	var pv struct {
		Previews []posture.Preview `json:"previews"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pv) != nil || len(pv.Previews) != 1 || pv.Previews[0].Hash == "" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if dynamicProxyRouter.WAFState().Policy.Enabled {
		t.Fatal("the preview changed the WAF")
	}
	applyBody, _ := json.Marshal(map[string]interface{}{"actions": []posture.ApplyRequest{{ID: "waf.baseline", Hash: pv.Previews[0].Hash}}})
	w = postureCall(h, "POST", "/api/security/posture/apply", string(applyBody), []*http.Cookie{adminC}, token, csrfCookies)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"applied"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if !dynamicProxyRouter.WAFState().Policy.Enabled {
		t.Fatal("apply did not enable the WAF")
	}
	found := false
	for _, a := range authAgent.RecentAudit() {
		if a.Event == "posture.apply" && a.Target == "waf.baseline" && a.Actor == "root" && strings.Contains(a.Detail, "WAF master switch") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit entry: %+v", authAgent.RecentAudit())
	}
	// apply without the hash is refused
	w = postureCall(h, "POST", "/api/security/posture/apply", `{"actions":[{"id":"uptime.enable"}]}`, []*http.Cookie{adminC}, token, csrfCookies)
	if !strings.Contains(w.Body.String(), "hash") {
		t.Fatalf("%s", w.Body.String())
	}
}

func TestPostureV1IsReadOnlyAndTokenProtected(t *testing.T) {
	postureTestSystem(t)
	_, h, _, ro, _ := v1TestSetupWithPosture(t)
	if w := v1Do(h, "GET", "/api/v1/security/posture", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d", w.Code)
	}
	w := v1Do(h, "GET", "/api/v1/security/posture", ro, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"score"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, p := range []string{"/api/v1/security/posture/apply", "/api/v1/security/posture/preview"} {
		if w := v1Do(h, "POST", p, ro, `{}`); w.Code == 200 {
			t.Errorf("%s is reachable with a token", p)
		}
	}
	if v1RoutePatternsContain("POST /api/v1/security/posture") {
		t.Error("a write route to the posture was registered in v1")
	}
}

func v1RoutePatternsContain(p string) bool {
	for _, x := range v1RoutePatterns() {
		if x == p {
			return true
		}
	}
	return false
}

// v1TestSetupWithPosture is v1TestSetup with the posture handler wired to the real one
func v1TestSetupWithPosture(t *testing.T) (*apitoken.Manager, http.Handler, *v1Capture, string, string) {
	t.Helper()
	mgr, err := apitoken.NewManager(&v1KV{m: map[string][]byte{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := v1Backend{Posture: func(w http.ResponseWriter, r *http.Request) { HandlePostureGet(w, r) }}
	h := newAPIv1Handler(mgr, b, func(next http.Handler) http.Handler { return next })
	ro, _, _ := mgr.Create("ro", apitoken.ScopeRead, 0, nil)
	rw, _, _ := mgr.Create("rw", apitoken.ScopeReadWrite, 0, nil)
	return mgr, h, &v1Capture{}, ro, rw
}
