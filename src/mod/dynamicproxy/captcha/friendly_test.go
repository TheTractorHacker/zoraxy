package captcha

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type friendlyFake struct {
	*httptest.Server
	mu      sync.Mutex
	status  int
	body    string
	lastKey string
	lastReq map[string]string
	lastCT  string
	hits    int
}

func newFriendlyFake(t *testing.T, status int, body string) *friendlyFake {
	t.Helper()
	f := &friendlyFake{status: status, body: body}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		f.lastKey = r.Header.Get("X-API-Key")
		f.lastCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		f.lastReq = map[string]string{}
		json.Unmarshal(raw, &f.lastReq)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/captcha/siteverify" {
			http.Error(w, `{"success":false,"error":{"error_code":"method_not_allowed"}}`, 405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		w.Write([]byte(f.body))
	}))
	t.Cleanup(f.Close)
	return f
}

func pointFriendlyAt(t *testing.T, global, eu string) {
	og, oe := FriendlyVerifyURLGlobal, FriendlyVerifyURLEU
	FriendlyVerifyURLGlobal, FriendlyVerifyURLEU = global+"/api/v2/captcha/siteverify", eu+"/api/v2/captcha/siteverify"
	t.Cleanup(func() { FriendlyVerifyURLGlobal, FriendlyVerifyURLEU = og, oe })
}

const friendlyOK = `{"success":true,"data":{"event_id":"e1","challenge":{"timestamp":"2026-01-01T00:00:00Z","origin":"https://app.example.com"},"risk_intelligence":null}}`

func TestFriendlyDefaultEndpoints(t *testing.T) {
	if FriendlyVerifyURLGlobal != "https://global.frcapi.com/api/v2/captcha/siteverify" {
		t.Fatal(FriendlyVerifyURLGlobal)
	}
	if FriendlyVerifyURLEU != "https://eu.frcapi.com/api/v2/captcha/siteverify" {
		t.Fatal(FriendlyVerifyURLEU)
	}
}

func TestFriendlySiteverifyRequestAndResults(t *testing.T) {
	f := newFriendlyFake(t, 200, friendlyOK)
	pointFriendlyAt(t, f.URL, f.URL)
	if err := VerifyFriendly("solution", "API-KEY", "FC_SITE", "", VerifyExpect{}); err != nil {
		t.Fatal(err)
	}
	if f.lastKey != "API-KEY" || f.lastReq["response"] != "solution" || f.lastReq["sitekey"] != "FC_SITE" || !strings.HasPrefix(f.lastCT, "application/json") {
		t.Fatalf("request: key=%q body=%v ct=%q", f.lastKey, f.lastReq, f.lastCT)
	}
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"invalid", 200, `{"success":false,"error":{"error_code":"response_invalid","detail":"x"}}`, "response_invalid"},
		{"timeout", 200, `{"success":false,"error":{"error_code":"response_timeout"}}`, "response_timeout"},
		{"duplicate", 200, `{"success":false,"error":{"error_code":"response_duplicate"}}`, "response_duplicate"},
		{"bad api key fails closed", 401, `{"success":false,"error":{"error_code":"auth_invalid"}}`, "auth_invalid"},
		{"bad sitekey fails closed", 400, `{"success":false,"error":{"error_code":"sitekey_invalid"}}`, "sitekey_invalid"},
		{"server error fails closed", 500, `oops`, "HTTP 500"},
		{"200 with success true but wrong status class", 200, `not json`, "parse"},
		{"success false without error", 200, `{"success":false}`, "unknown"},
		{"success missing", 200, `{}`, "unknown"},
	}
	for _, c := range cases {
		f.mu.Lock()
		f.status, f.body = c.status, c.body
		f.mu.Unlock()
		err := VerifyFriendly("solution", "API-KEY", "FC_SITE", "", VerifyExpect{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v want %q", c.name, err, c.want)
		}
	}
	// non-200 never succeeds even with a success body
	f.mu.Lock()
	f.status, f.body = 500, friendlyOK
	f.mu.Unlock()
	if VerifyFriendly("solution", "API-KEY", "FC_SITE", "", VerifyExpect{}) == nil {
		t.Error("HTTP 500 accepted")
	}
	if VerifyFriendly("", "API-KEY", "", "", VerifyExpect{}) == nil || VerifyFriendly("x", "", "", "", VerifyExpect{}) == nil {
		t.Error("empty token / key accepted")
	}
	if VerifyFriendly(strings.Repeat("a", 16*1024+1), "k", "", "", VerifyExpect{}) == nil {
		t.Error("oversized response accepted")
	}
	// unreachable provider fails closed
	pointFriendlyAt(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
	if VerifyFriendly("x", "k", "", "", VerifyExpect{}) == nil {
		t.Error("unreachable service accepted")
	}
}

func TestFriendlyEUEndpointSelection(t *testing.T) {
	g := newFriendlyFake(t, 200, friendlyOK)
	e := newFriendlyFake(t, 200, friendlyOK)
	pointFriendlyAt(t, g.URL, e.URL)
	VerifyFriendly("x", "k", "", "", VerifyExpect{})
	VerifyFriendly("x", "k", "", "global", VerifyExpect{})
	VerifyFriendly("x", "k", "", "bogus", VerifyExpect{})
	if g.hits != 3 || e.hits != 0 {
		t.Fatalf("global hits=%d eu hits=%d", g.hits, e.hits)
	}
	VerifyFriendly("x", "k", "", "eu", VerifyExpect{})
	VerifyFriendly("x", "k", "", " EU ", VerifyExpect{})
	if e.hits != 2 {
		t.Fatalf("eu hits=%d", e.hits)
	}
}

func TestFriendlyOriginBinding(t *testing.T) {
	f := newFriendlyFake(t, 200, friendlyOK)
	pointFriendlyAt(t, f.URL, f.URL)
	if err := VerifyFriendly("x", "k", "", "", VerifyExpect{Hostname: "app.example.com"}); err != nil {
		t.Fatalf("matching origin: %v", err)
	}
	if err := VerifyFriendly("x", "k", "", "", VerifyExpect{Hostname: "other.example.com"}); err == nil {
		t.Fatal("origin mismatch accepted")
	}
	f.mu.Lock()
	f.body = `{"success":true,"data":{"challenge":{"origin":""}}}`
	f.mu.Unlock()
	if err := VerifyFriendly("x", "k", "", "", VerifyExpect{Hostname: "app.example.com"}); err == nil {
		t.Fatal("unknown origin must not satisfy a hostname binding")
	}
	if err := VerifyFriendly("x", "k", "", "", VerifyExpect{}); err != nil {
		t.Fatalf("no binding requested: %v", err)
	}
	f.mu.Lock()
	f.body = `{"success":true,"data":{"challenge":{"origin":"https://app.example.com:8443"}}}`
	f.mu.Unlock()
	if err := VerifyFriendly("x", "k", "", "", VerifyExpect{Hostname: "app.example.com"}); err != nil {
		t.Fatalf("port must be ignored: %v", err)
	}
}

func TestFriendlyHandleVerificationUsesOnlyItsOwnField(t *testing.T) {
	f := newFriendlyFake(t, 200, friendlyOK)
	pointFriendlyAt(t, f.URL, f.URL)
	cfg := &Config{Provider: ProviderFriendly, SiteKey: "FC_SITE", SecretKey: "API"}
	post := func(form url.Values) (*httptest.ResponseRecorder, error) {
		r := httptest.NewRequest(http.MethodPost, "https://app.example.com"+VerifyPath, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		err := HandleVerification(w, r, cfg, NewSessionStoreWithSecret("s"), "203.0.113.9")
		return w, err
	}
	// another provider's field is never interpreted as a Friendly Captcha solution
	if w, _ := post(url.Values{"cf-turnstile-response": {"tok"}, "g-recaptcha-response": {"tok"}}); w.Code != http.StatusBadRequest || f.hits != 0 {
		t.Fatalf("foreign token field: code=%d hits=%d", w.Code, f.hits)
	}
	w, _ := post(url.Values{FriendlyField: {"sol"}})
	if w.Code != 200 || !strings.Contains(w.Header().Get("Set-Cookie"), CookieName) || f.lastReq["response"] != "sol" {
		t.Fatalf("verify: %d %v", w.Code, f.lastReq)
	}
	cfg.VerifyHostname = true
	f.mu.Lock()
	f.body = strings.Replace(friendlyOK, "app.example.com", "evil.example", 1)
	f.mu.Unlock()
	if w, _ := post(url.Values{FriendlyField: {"sol"}}); w.Code != http.StatusUnauthorized || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("origin mismatch must fail without a session: %d", w.Code)
	}
}

func TestFriendlyConfigAndPage(t *testing.T) {
	cfg := &Config{Provider: ProviderFriendly, SiteKey: "FC_SITE", SecretKey: "API", FriendlyEndpoint: "eu"}
	if !cfg.IsConfigured() {
		t.Fatal("site key + API key should be a complete config")
	}
	if (&Config{Provider: ProviderFriendly, SiteKey: "FC_SITE"}).IsConfigured() {
		t.Fatal("API key is required")
	}
	if err := (&Config{FriendlyEndpoint: "mars"}).ValidatePageSettings(); err == nil {
		t.Fatal("bad endpoint accepted")
	}
	// older configs have no endpoint field and load unchanged
	var old Config
	if err := json.Unmarshal([]byte(`{"Provider":3,"SiteKey":"a","SecretKey":"b"}`), &old); err != nil || old.Provider != ProviderFriendly || old.FriendlyEndpoint != "" {
		t.Fatalf("%+v %v", old, err)
	}

	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	w := httptest.NewRecorder()
	RenderChallenge(w, r, cfg, "app.example.com", "")
	body := w.Body.String()
	for _, want := range []string{`"provider":"friendly"`, `"friendlyEndpoint":"eu"`, `"field":"frc-captcha-response"`, `"siteKey":"FC_SITE"`, `"friendlySdk":"` + FriendlySDKVersion + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"https://cdn.jsdelivr.net/npm/@friendlycaptcha/", "https://global.frcapi.com", "https://eu.frcapi.com", "worker-src blob:", "'wasm-unsafe-eval'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %s: %s", want, csp)
		}
	}
	for _, bad := range []string{"challenges.cloudflare.com", "www.google.com", "'unsafe-eval'"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP allows %s: %s", bad, csp)
		}
	}
	// the other pages and providers do not get the Friendly hosts
	w = httptest.NewRecorder()
	RenderChallenge(w, r, &Config{Provider: ProviderCloudflare, SiteKey: "k"}, "app.example.com", "")
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "frcapi") || strings.Contains(w.Header().Get("Content-Security-Policy"), "worker-src") {
		t.Error("turnstile page allows Friendly Captcha hosts")
	}
	w = httptest.NewRecorder()
	RenderBlocked(w, r, cfg, "app.example.com")
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "frcapi") {
		t.Error("blocked page allows widget hosts")
	}
	// custom templates keep rendering for the new provider
	if err := ValidateCustomTemplate(`<html>{{template "zx_widget" .}}{{template "zx_runtime" .}}</html>`); err != nil {
		t.Fatal(err)
	}
}
