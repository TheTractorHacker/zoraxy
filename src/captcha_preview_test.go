package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func postForm(h http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/proxy/captcha/preview", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestCaptchaPreviewUsesTestKeyAndEscapes(t *testing.T) {
	w := postForm(HandleCaptchaPreview, url.Values{
		"captchaProvider":  {"0"},
		"captchaSiteKey":   {"REAL-KEY"},
		"captchaSecretKey": {"REAL-SECRET"},
		"captchaTitle":     {"<script>alert(1)</script>"},
		"captchaAccent":    {"#ff8800"},
		"page":             {"challenge"},
		"domain":           {"app.example.com"},
	})
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if strings.Contains(body, "REAL-KEY") || strings.Contains(body, "REAL-SECRET") || !strings.Contains(body, "1x00000000000000000000AA") {
		t.Error("preview must use the provider test key and never echo real keys")
	}
	if strings.Contains(body, "<script>alert(1)") || !strings.Contains(body, "&lt;script&gt;") {
		t.Error("title not escaped")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Error("preview must be frameable by the admin UI")
	}
}

func TestCaptchaPreviewRejectsBadSettings(t *testing.T) {
	for name, form := range map[string]url.Values{
		"bad colour":    {"captchaAccent": {"red"}},
		"bad template":  {"captchaCustomTemplate": {"{{.DoesNotExist}}"}},
		"bad logo":      {"captchaLogo": {"javascript:alert(1)"}},
		"bad turnstile": {"turnstileMode": {"weird"}},
	} {
		if w := postForm(HandleCaptchaPreview, form); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Cannot preview") {
			t.Errorf("%s: got %d %q", name, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/proxy/captcha/preview", nil)
	w := httptest.NewRecorder()
	HandleCaptchaPreview(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET got %d", w.Code)
	}
}

func TestParseCaptchaConfigPageSettings(t *testing.T) {
	// nothing customised: Branding / Turnstile stay nil so saved JSON is unchanged
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"captcha": {"true"}, "captchaSiteKey": {"a"}, "captchaSecretKey": {"b"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cfg, err := parseCaptchaConfigFromRequest(r)
	if err != nil || cfg == nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Branding != nil || cfg.Turnstile != nil {
		t.Error("expected nil Branding/Turnstile when nothing is customised")
	}

	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{
		"captcha": {"true"}, "captchaSiteKey": {"a"}, "captchaSecretKey": {"b"},
		"captchaHeading": {" Hi "}, "turnstileAction": {"login"}, "captchaHideFooter": {"true"}, "captchaVerifyHostname": {"true"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cfg, err = parseCaptchaConfigFromRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Branding == nil || cfg.Branding.Heading != "Hi" || !cfg.Branding.HideFooter || cfg.Turnstile == nil || cfg.Turnstile.Action != "login" || !cfg.VerifyHostname {
		t.Errorf("fields not parsed: %+v %+v", cfg.Branding, cfg.Turnstile)
	}

	// disabled captcha ignores everything
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"captchaAccent": {"bad"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg, err := parseCaptchaConfigFromRequest(r); cfg != nil || err != nil {
		t.Error("captcha disabled should return nil, nil")
	}
}
