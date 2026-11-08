package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
)

func TestAltchaChallengeEndpointThroughGatingAndCountryChallenge(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	sep.RequireCaptcha = true
	sep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderAltcha, SecretKey: "test-secret-key-for-altcha"}

	get := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com"+captcha.AltchaChallengePath, nil)
		r.RemoteAddr = "198.51.100.1:1"
		router.handleNonTLSRequest(w, r, sep)
		return w
	}
	if w := get(); w.Code != 200 || !strings.Contains(w.Body.String(), `"challenge"`) {
		t.Fatalf("challenge endpoint not served through the gating: %d %s", w.Code, w.Body.String())
	}
	// other requests are challenged with the altcha page
	if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.1:1"); w.Code == 299 || !strings.Contains(w.Body.String(), `"provider":"altcha"`) {
		t.Fatalf("not challenged with altcha: %d", w.Code)
	}
	// the challenge endpoint is not exposed for endpoints on another provider
	sep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderCloudflare, SiteKey: "k", SecretKey: "s"}
	if w := get(); strings.Contains(w.Body.String(), `"challenge"`) {
		t.Fatal("altcha challenge served on a turnstile endpoint")
	}

	// the country challenge path serves it as well, without RequireCaptcha
	sep.RequireCaptcha = false
	sep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderAltcha, SecretKey: "test-secret-key-for-altcha"}
	rule.AddChallengeCountry("xx", "")
	setCountries(router, map[string]string{"198.51.100.9": "XX"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com"+captcha.AltchaChallengePath, nil)
	r.RemoteAddr = "198.51.100.9:1"
	router.handleNonTLSRequest(w, r, sep)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"challenge"`) {
		t.Fatalf("country challenge flow cannot fetch an altcha challenge: %d", w.Code)
	}
}
