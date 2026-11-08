package captcha

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func render(t *testing.T, cfg *Config, kind PageKind) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/x", nil)
	switch kind {
	case PageFailed:
		RenderFailed(w, r, cfg, "app.example.com", RenderOptions{})
	case PageBlocked:
		RenderBlocked(w, r, cfg, "app.example.com")
	default:
		RenderChallenge(w, r, cfg, "app.example.com", "")
	}
	return w
}

func TestDefaultChallengeMatchesStockWording(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want []string
	}{
		{"turnstile", &Config{Provider: ProviderCloudflare, SiteKey: "SK"}, []string{"<title>Just a moment...</title>", ">app.example.com</h1>", "Verify you are human by completing the action below.", "app.example.com needs to review the security of your connection before proceeding.", "Performance &amp; security by", "challenges.cloudflare.com/turnstile/v0/api.js", `"siteKey":"SK"`, `"verifyPath":"/.zoraxy/captcha/verify"`, "cf-turnstile-response"}},
		{"v2", &Config{Provider: ProviderGoogle, SiteKey: "SK"}, []string{"Verify you are human", "google.com/recaptcha/api.js", "g-recaptcha-response"}},
		{"v3", &Config{Provider: ProviderGoogle, RecaptchaVersion: "v3", SiteKey: "SK"}, []string{"Verifying your connection...", `"action":"access"`, "render=' + encodeURIComponent"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := render(t, tc.cfg, PageChallenge)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (unchanged behaviour)", w.Code)
			}
			body := w.Body.String()
			for _, s := range tc.want {
				if !strings.Contains(body, s) {
					t.Errorf("default page missing %q", s)
				}
			}
			if strings.Contains(body, "<no value>") || strings.Contains(body, "ZgotmplZ") {
				t.Error("template produced a placeholder / filtered value")
			}
		})
	}
}

func TestBrandingIsEscaped(t *testing.T) {
	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "SK", Branding: &Branding{
		Title:      `<script>alert(1)</script>`,
		Heading:    `<img src=x onerror=alert(2)>`,
		Message:    `"><svg onload=alert(3)>`,
		Notice:     `</div><script>alert(4)</script>`,
		FailedText: `</script><script>alert(5)</script>`,
	}}
	body := render(t, cfg, PageChallenge).Body.String()
	for _, bad := range []string{"<script>alert", "<img src=x", "<svg onload", "</script><script>alert"} {
		if strings.Contains(body, bad) {
			t.Errorf("unescaped payload %q found in page", bad)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("title was not HTML-escaped")
	}
	// the JSON blob in the script must not be able to close the script element
	if n := strings.Count(strings.ToLower(body), "</script>"); n != 1 {
		t.Errorf("found %d </script> tags, want exactly the 1 that closes the runtime", n)
	}
}

func TestNonceAndCSP(t *testing.T) {
	for _, cfg := range []*Config{
		{Provider: ProviderCloudflare, SiteKey: "SK"},
		{Provider: ProviderGoogle, SiteKey: "SK"},
	} {
		w := render(t, cfg, PageChallenge)
		csp := w.Header().Get("Content-Security-Policy")
		m := regexp.MustCompile(`'nonce-([a-f0-9]+)'`).FindStringSubmatch(csp)
		if m == nil {
			t.Fatalf("no nonce in CSP: %s", csp)
		}
		body := w.Body.String()
		if !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
			t.Error("inline script does not carry the CSP nonce")
		}
		if cfg.Provider == ProviderCloudflare {
			if !strings.Contains(body, `<style nonce="`+m[1]+`">`) {
				t.Error("inline style does not carry the CSP nonce")
			}
			if !strings.Contains(csp, "https://challenges.cloudflare.com") || strings.Contains(csp, "google") {
				t.Errorf("turnstile CSP wrong: %s", csp)
			}
		} else if !strings.Contains(csp, "https://www.google.com") || !strings.Contains(csp, "https://www.gstatic.com") || strings.Contains(csp, "cloudflare") {
			t.Errorf("recaptcha CSP wrong: %s", csp)
		}
		if strings.Contains(csp, "script-src 'unsafe-inline'") || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP too loose: %s", csp)
		}
		// nonce differs per response
		if m2 := regexp.MustCompile(`'nonce-([a-f0-9]+)'`).FindStringSubmatch(render(t, cfg, PageChallenge).Header().Get("Content-Security-Policy")); m2[1] == m[1] {
			t.Error("nonce was reused between responses")
		}
	}
}

func TestSeparatePages(t *testing.T) {
	failed := render(t, &Config{Provider: ProviderCloudflare, SiteKey: "SK"}, PageFailed)
	if failed.Code != http.StatusUnauthorized {
		t.Errorf("failed page status = %d", failed.Code)
	}
	body := failed.Body.String()
	if !strings.Contains(body, `id="retry-link"`) || !strings.Contains(body, `href="/"`) || strings.Contains(body, "turnstile") {
		t.Errorf("failed page should offer a retry link and no widget:\n%s", body)
	}
	blocked := render(t, nil, PageBlocked)
	if blocked.Code != http.StatusForbidden || !strings.Contains(blocked.Body.String(), "Access blocked") {
		t.Errorf("blocked page: %d %s", blocked.Code, blocked.Body.String())
	}
	if strings.Contains(blocked.Body.String(), "<script") {
		t.Error("blocked page must not need script")
	}
}

func TestBrandingApplied(t *testing.T) {
	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "SK", Branding: &Branding{
		Title: "Hold on", Heading: "Welcome to {domain}", Message: "One moment", AccentColor: "#ff0000",
		BackgroundColor: "#101010", Theme: ThemeDark, HideFooter: true,
		LogoURL: "https://cdn.example.com/logo.png", SuccessText: "OK!",
	}}
	body := render(t, cfg, PageChallenge).Body.String()
	for _, s := range []string{"<title>Hold on</title>", "Welcome to app.example.com", "One moment", "--accent: #ff0000", "background-color: #101010", `data-theme="dark"`, `src="https://cdn.example.com/logo.png"`, `"success":"OK!"`} {
		if !strings.Contains(body, s) {
			t.Errorf("missing %q", s)
		}
	}
	if strings.Contains(body, "Performance &amp; security") {
		t.Error("footer should be hidden")
	}
}

func tinyPNG() []byte {
	b, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
	return b
}

func TestLogoValidation(t *testing.T) {
	png := "data:image/png;base64," + base64.StdEncoding.EncodeToString(tinyPNG())
	if err := ValidateLogo(png); err != nil {
		t.Errorf("valid png rejected: %v", err)
	}
	bad := map[string]string{
		"svg":        "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<svg onload=alert(1)>")),
		"html":       "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte("<script>")),
		"lying mime": "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("<html><script>x</script></html>")),
		"http":       "http://example.com/logo.png",
		"javascript": "javascript:alert(1)",
		"creds":      "https://user:pw@example.com/a.png",
		"oversize":   "data:image/png;base64," + base64.StdEncoding.EncodeToString(append(tinyPNG(), make([]byte, MaxLogoBytes)...)),
		"not base64": "data:image/png;base64,@@@",
	}
	for name, v := range bad {
		if ValidateLogo(v) == nil {
			t.Errorf("%s logo accepted", name)
		}
	}
	// data URI survives html/template (not rewritten to #ZgotmplZ)
	body := render(t, &Config{Provider: ProviderCloudflare, SiteKey: "k", Branding: &Branding{LogoURL: png}}, PageChallenge).Body.String()
	if !strings.Contains(body, `src="`+png+`"`) {
		t.Error("data URI logo missing from page")
	}
	// An invalid stored logo is dropped at render time, never emitted
	body = render(t, &Config{Provider: ProviderCloudflare, SiteKey: "k", Branding: &Branding{LogoURL: "javascript:alert(1)"}}, PageChallenge).Body.String()
	if strings.Contains(body, "javascript:") || strings.Contains(body, `class="logo"`) {
		t.Error("invalid logo was rendered")
	}
}

func TestBrandingValidation(t *testing.T) {
	bad := []*Branding{
		{AccentColor: "red"}, {AccentColor: "#12"}, {BackgroundColor: "url(x)"}, {Theme: "neon"},
		{Title: strings.Repeat("a", 500)}, {Message: strings.Repeat("a", 5000)},
	}
	for i, b := range bad {
		if b.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, b)
		}
	}
	if (&Branding{AccentColor: "#abc", BackgroundColor: "#11223344", Theme: "light"}).Validate() != nil {
		t.Error("valid branding rejected")
	}
	for _, o := range []*TurnstileOptions{{Mode: "x"}, {Appearance: "x"}, {Theme: "x"}, {Size: "x"}, {Action: "bad action!"}, {CData: "a b"}} {
		if o.Validate() == nil {
			t.Errorf("turnstile options accepted: %+v", o)
		}
	}
	if (&Config{RecaptchaAction: "no spaces"}).ValidatePageSettings() == nil {
		t.Error("bad recaptcha action accepted")
	}
}

func TestCustomTemplateValidation(t *testing.T) {
	good := `<!doctype html><html><head><title>{{.Title}}</title><style nonce="{{.Nonce}}">body{background:{{.Accent}}}</style></head>
<body><h1>{{.Heading}}</h1>{{template "zx_widget" .}}{{template "zx_runtime" .}}</body></html>`
	if err := ValidateCustomTemplate(good); err != nil {
		t.Fatalf("good template rejected: %v", err)
	}
	bad := map[string]string{
		"syntax":          `<h1>{{.Title</h1>`,
		"unknown field":   `<h1>{{.NoSuchField}}</h1>`,
		"unknown func":    `{{nosuchfunc .Title}}`,
		"unknown tmpl":    `{{template "does_not_exist" .}}`,
		"unclosed if":     `{{if .Preview}}x`,
		"empty":           `   `,
		"too big":         strings.Repeat("a", MaxCustomTemplateBytes+1),
		"field on string": `{{.Title.Foo}}`,
		"bad js context":  `<script>var x = {{.Client.Nope}};</script>`,
	}
	for name, src := range bad {
		if err := ValidateCustomTemplate(src); err == nil {
			t.Errorf("%s: bad template accepted", name)
		}
	}
	// the config level check reports it too
	cfg := &Config{Branding: &Branding{CustomTemplate: `{{.Nope}}`}}
	if err := cfg.ValidatePageSettings(); err == nil {
		t.Error("ValidatePageSettings accepted a bad template")
	}
}

func TestCustomTemplateRendersWithNonceAndCSP(t *testing.T) {
	custom := `<html><body><h1>Custom {{.Heading}}</h1><p>{{.Title}}</p>{{template "zx_widget" .}}{{template "zx_runtime" .}}</body></html>`
	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "SK", Branding: &Branding{CustomTemplate: custom, Title: "<b>t</b>"}}
	w := render(t, cfg, PageChallenge)
	body := w.Body.String()
	if !strings.Contains(body, "Custom app.example.com") || !strings.Contains(body, "&lt;b&gt;t&lt;/b&gt;") {
		t.Errorf("custom template not used / not escaped:\n%s", body)
	}
	if w.Header().Get("Content-Security-Policy") == "" || !strings.Contains(body, `<script nonce="`) {
		t.Error("custom template page lacks CSP / nonce")
	}
}

func TestBrokenStoredTemplateFallsBackToStockPage(t *testing.T) {
	// Bypasses save-time validation, as a hand-edited config file could.
	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "SK", Branding: &Branding{CustomTemplate: `{{.Nope}}`}}
	w := render(t, cfg, PageChallenge)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Just a moment...") {
		t.Errorf("expected stock fallback, got %d", w.Code)
	}
	cfg.Branding.CustomTemplate = `{{if`
	if w := render(t, cfg, PageChallenge); !strings.Contains(w.Body.String(), "Just a moment...") {
		t.Error("syntax error template did not fall back")
	}
}

func TestLegacyWebrootOverrideStillWorks(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "templates"), 0o755)
	os.WriteFile(filepath.Join(dir, "templates", "captcha_cloudflare.html"), []byte(`LEGACY {{.Domain}} {{.SiteKey}} {{.VerifyPath}}`), 0o644)
	w := httptest.NewRecorder()
	RenderChallenge(w, httptest.NewRequest("GET", "/", nil), &Config{Provider: ProviderCloudflare, SiteKey: "SK"}, "h.example", dir)
	if w.Body.String() != "LEGACY h.example SK /.zoraxy/captcha/verify" {
		t.Errorf("legacy override output: %q", w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'unsafe-inline'") {
		t.Error("legacy templates have no nonce and need the relaxed CSP")
	}
}

func TestPreviewUsesDummyKeysAndOK(t *testing.T) {
	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "REAL-SITE-KEY", SecretKey: "REAL-SECRET"}
	w := httptest.NewRecorder()
	RenderPreview(w, httptest.NewRequest("POST", "/api/x", nil), cfg, PageChallenge, "example.com")
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, PreviewTurnstileSiteKey) || strings.Contains(body, "REAL-SITE-KEY") || strings.Contains(body, "REAL-SECRET") {
		t.Errorf("preview leaks real keys or wrong status: %d", w.Code)
	}
	if !strings.Contains(body, `"preview":true`) || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Error("preview flag / frame-ancestors missing")
	}
}

func TestTurnstileOptionsReachThePage(t *testing.T) {
	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "SK", Turnstile: &TurnstileOptions{Mode: "invisible", Appearance: "interaction-only", Theme: "dark", Size: "flexible", Action: "login", CData: "abc_1"}}
	body := render(t, cfg, PageChallenge).Body.String()
	for _, s := range []string{`"mode":"invisible"`, `"appearance":"interaction-only"`, `"theme":"dark"`, `"size":"flexible"`, `"action":"login"`, `"cdata":"abc_1"`, `class="loader" id="zx-loader">`} {
		if !strings.Contains(body, s) {
			t.Errorf("missing %q", s)
		}
	}
	for _, s := range []string{"expired-callback", "timeout-callback", "error-callback", "refresh-expired"} {
		if !strings.Contains(body, s) {
			t.Errorf("runtime lacks %s handling", s)
		}
	}
}

func TestRecaptchaOptionsReachThePage(t *testing.T) {
	body := render(t, &Config{Provider: ProviderGoogle, RecaptchaVersion: "v3", SiteKey: "SK", RecaptchaAction: "checkout"}, PageChallenge).Body.String()
	if !strings.Contains(body, `"action":"checkout"`) {
		t.Error("v3 action missing")
	}
	body = render(t, &Config{Provider: ProviderGoogle, SiteKey: "SK", RecaptchaInvisible: true}, PageChallenge).Body.String()
	if !strings.Contains(body, `"invisible":true`) {
		t.Error("v2 invisible flag missing")
	}
}

func TestOldConfigJSONLoadsWithDefaults(t *testing.T) {
	old := `{"Provider":0,"SiteKey":"a","SecretKey":"b","SessionDuration":3600,"RecaptchaVersion":"v2","RecaptchaScore":0.5,"ProtectedPathPrefixes":["/x"],"ExceptionRules":null}`
	var cfg Config
	if err := json.Unmarshal([]byte(old), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Branding != nil || cfg.Turnstile != nil || cfg.RecaptchaInvisible || cfg.VerifyHostname {
		t.Error("new fields should default to zero values")
	}
	if err := cfg.ValidatePageSettings(); err != nil {
		t.Errorf("old config invalid: %v", err)
	}
	if !cfg.IsConfigured() {
		t.Error("old config no longer configured")
	}
	// and an unconfigured new config serialises without the new keys
	out, _ := json.Marshal(cfg)
	for _, k := range []string{"Branding", "Turnstile", "RecaptchaInvisible", "RecaptchaAction", "VerifyHostname"} {
		if strings.Contains(string(out), k) {
			t.Errorf("zero value %s should be omitted from JSON", k)
		}
	}
	w := render(t, &cfg, PageChallenge)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "Just a moment...") {
		t.Error("old config does not render the stock page")
	}
}

// ---- siteverify against a stand-in provider ----

func fakeProvider(t *testing.T, answer string) (*httptest.Server, *url.Values) {
	t.Helper()
	got := &url.Values{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		*got = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestTurnstileSiteverifyBindings(t *testing.T) {
	srv, got := fakeProvider(t, `{"success":true,"action":"login","cdata":"c1","hostname":"app.example.com"}`)
	old := TurnstileVerifyURL
	TurnstileVerifyURL = srv.URL
	t.Cleanup(func() { TurnstileVerifyURL = old })

	cases := []struct {
		name string
		exp  VerifyExpect
		ok   bool
	}{
		{"nothing expected", VerifyExpect{}, true},
		{"action match", VerifyExpect{Action: "login"}, true},
		{"action mismatch", VerifyExpect{Action: "signup"}, false},
		{"cdata match", VerifyExpect{CData: "c1"}, true},
		{"cdata mismatch", VerifyExpect{CData: "zzz"}, false},
		{"hostname match with port", VerifyExpect{Hostname: "APP.example.com:8443"}, true},
		{"hostname mismatch", VerifyExpect{Hostname: "evil.example.net"}, false},
	}
	for _, tc := range cases {
		err := VerifyTurnstile("tok", "secret", "203.0.113.9", tc.exp)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	if got.Get("secret") != "secret" || got.Get("response") != "tok" || got.Get("remoteip") != "203.0.113.9" {
		t.Errorf("provider got %v", *got)
	}

	// a response that lacks the action entirely must not satisfy a configured action
	srv2, _ := fakeProvider(t, `{"success":true}`)
	TurnstileVerifyURL = srv2.URL
	if VerifyTurnstile("tok", "secret", "", VerifyExpect{Action: "login"}) == nil {
		t.Error("missing action accepted")
	}
	srv3, _ := fakeProvider(t, `{"success":false,"error-codes":["invalid-input-response"]}`)
	TurnstileVerifyURL = srv3.URL
	if VerifyTurnstile("tok", "secret", "", VerifyExpect{}) == nil {
		t.Error("provider failure accepted")
	}
}

func TestRecaptchaSiteverifyV3ActionScoreHostname(t *testing.T) {
	srv, _ := fakeProvider(t, `{"success":true,"score":0.7,"action":"access","hostname":"app.example.com"}`)
	old := RecaptchaVerifyURL
	RecaptchaVerifyURL = srv.URL
	t.Cleanup(func() { RecaptchaVerifyURL = old })

	if err := VerifyRecaptcha("t", "s", "", VerifyExpect{Version: "v3", MinScore: 0.5, Action: "access"}); err != nil {
		t.Errorf("good v3 rejected: %v", err)
	}
	if VerifyRecaptcha("t", "s", "", VerifyExpect{Version: "v3", MinScore: 0.9, Action: "access"}) == nil {
		t.Error("low score accepted")
	}
	if VerifyRecaptcha("t", "s", "", VerifyExpect{Version: "v3", MinScore: 0.5, Action: "other"}) == nil {
		t.Error("action mismatch accepted")
	}
	if VerifyRecaptcha("t", "s", "", VerifyExpect{Version: "v3", MinScore: 0.5, Hostname: "x.example.net"}) == nil {
		t.Error("hostname mismatch accepted")
	}
	// v2 ignores action and score
	if err := VerifyRecaptcha("t", "s", "", VerifyExpect{Version: "v2", Action: "zzz", MinScore: 0.99}); err != nil {
		t.Errorf("v2 should not check action/score: %v", err)
	}
}

func postVerify(t *testing.T, cfg *Config, accept string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	form := url.Values{"cf-turnstile-response": {"tok"}}
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com"+VerifyPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	err := HandleVerification(w, r, cfg, NewSessionStoreWithSecret("s"), "203.0.113.9")
	return w, err
}

func TestHandleVerificationEnforcesBindingsAndShowsFailedPage(t *testing.T) {
	srv, _ := fakeProvider(t, `{"success":true,"action":"signup","hostname":"app.example.com"}`)
	old := TurnstileVerifyURL
	TurnstileVerifyURL = srv.URL
	t.Cleanup(func() { TurnstileVerifyURL = old })

	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "k", SecretKey: "s", Turnstile: &TurnstileOptions{Action: "login"}}
	w, _ := postVerify(t, cfg, "application/json")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"success":false`) || w.Header().Get("Set-Cookie") != "" {
		t.Errorf("action mismatch must fail with JSON and no cookie: %d %s", w.Code, w.Body.String())
	}
	w, _ = postVerify(t, cfg, "text/html,application/xhtml+xml")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `id="retry-link"`) {
		t.Errorf("html client should get the failed page: %d", w.Code)
	}

	cfg.Turnstile.Action = "signup"
	w, err := postVerify(t, cfg, "application/json")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Set-Cookie"), CookieName) {
		t.Errorf("matching action should verify: %d err=%v", w.Code, err)
	}

	cfg.VerifyHostname = true
	if w, _ = postVerify(t, cfg, "application/json"); w.Code != 200 {
		t.Errorf("matching hostname rejected: %d", w.Code)
	}
	srvBad, _ := fakeProvider(t, `{"success":true,"action":"signup","hostname":"other.example.net"}`)
	TurnstileVerifyURL = srvBad.URL
	if w, _ = postVerify(t, cfg, "application/json"); w.Code != http.StatusUnauthorized {
		t.Errorf("hostname mismatch should be rejected: %d", w.Code)
	}
	cfg.VerifyHostname = false
	if w, _ = postVerify(t, cfg, "application/json"); w.Code != 200 {
		t.Errorf("hostname not checked unless enabled: %d", w.Code)
	}
}
