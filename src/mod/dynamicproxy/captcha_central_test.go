package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/ruleset"
)

/*
	Every CAPTCHA trigger must see the central provider of a rule that opted in
	(CaptchaConfig.UseCentral). The rule's OWN provider here is Turnstile with
	the keys "own-site" / "own-secret"; the central provider is something else,
	so a trigger that still reads the stored config is caught.
*/

const (
	ownSiteKey     = "own-site"
	centralSiteKey = "central-site"
	altchaSecret   = "central-altcha-secret-0123456789"
)

func setCentralForTest(t *testing.T, c *captcha.Central) {
	t.Helper()
	captcha.SetCentral(c)
	t.Cleanup(func() { captcha.SetCentral(nil) })
}

func centralTurnstile() *captcha.Central {
	return &captcha.Central{Provider: captcha.ProviderCloudflare, SiteKey: centralSiteKey, SecretKey: "central-secret", SessionDuration: 600}
}

func centralAltcha() *captcha.Central {
	return &captcha.Central{Provider: captcha.ProviderAltcha, SecretKey: altchaSecret}
}

// optInConfig is a rule config that stores its own Turnstile keys but uses the central provider
func optInConfig() *captcha.Config {
	return &captcha.Config{
		Provider: captcha.ProviderCloudflare, SiteKey: ownSiteKey, SecretKey: "own-secret",
		UseCentral: true,
	}
}

func assertCentralTurnstilePage(t *testing.T, what string, w *httptest.ResponseRecorder) {
	t.Helper()
	body := w.Body.String()
	if w.Code != http.StatusForbidden || !strings.Contains(body, `"siteKey":"`+centralSiteKey+`"`) {
		t.Fatalf("%s: not the central provider page: %d %.200q", what, w.Code, body)
	}
	if strings.Contains(body, ownSiteKey) {
		t.Fatalf("%s: the rule's own site key leaked into the page", what)
	}
}

// altchaVerifyPost posts an (invalid) Altcha payload to the verify path. With the
// central Altcha provider the payload is read and rejected (401); a trigger that
// still used the rule's own Turnstile config would answer 400 "token missing".
func altchaVerifyPost(remote string) *http.Request {
	form := url.Values{captcha.AltchaField: {"not-a-valid-payload"}}
	r := httptest.NewRequest(http.MethodPost, "http://app.example.com"+captcha.VerifyPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	r.RemoteAddr = remote
	return r
}

func assertCentralVerify(t *testing.T, what string, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("%s: verify handler did not use the central Altcha provider: %d %s", what, w.Code, w.Body.String())
	}
}

func TestCentralPlainGateUsesCentral(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	sep.RequireCaptcha = true
	sep.CaptchaConfig = optInConfig()
	setCentralForTest(t, centralTurnstile())

	assertCentralTurnstilePage(t, "plain gate", serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.1:1"))

	// the rule's own provider fields are untouched by all of this
	if sep.CaptchaConfig.SiteKey != ownSiteKey || sep.CaptchaConfig.SecretKey != "own-secret" {
		t.Fatal("stored provider fields of the rule were modified")
	}
	// editing the central config applies at once, no rule save
	c := centralTurnstile()
	c.SiteKey = "central-site-2"
	captcha.SetCentral(c)
	if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.1:1"); !strings.Contains(w.Body.String(), `"siteKey":"central-site-2"`) {
		t.Fatalf("central edit not applied to the rule: %.200q", w.Body.String())
	}
	// session duration of the central config is the one used to issue sessions
	if got := sep.EffectiveCaptchaConfig().SessionDuration; got != 600 {
		t.Fatalf("session duration %d, want the central 600", got)
	}
}

func TestCentralPlainGateVerifyAndAltchaEndpoint(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	sep.RequireCaptcha = true
	sep.CaptchaConfig = optInConfig()
	setCentralForTest(t, centralAltcha())

	w := httptest.NewRecorder()
	router.handleNonTLSRequest(w, altchaVerifyPost("198.51.100.1:1"), sep)
	assertCentralVerify(t, "plain gate verify", w)

	// the Altcha challenge endpoint is only served when the EFFECTIVE provider is Altcha
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com"+captcha.AltchaChallengePath, nil)
	r.RemoteAddr = "198.51.100.1:1"
	router.handleNonTLSRequest(w, r, sep)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"challenge"`) {
		t.Fatalf("altcha challenge endpoint not served for the central provider: %d", w.Code)
	}
	// and the page is the Altcha one
	if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.1:1"); !strings.Contains(w.Body.String(), `"provider":"altcha"`) {
		t.Fatalf("plain gate page is not the central Altcha page")
	}
}

func TestCentralExploitTrigger(t *testing.T) {
	router, sep := newExploitCaptchaEndpoint(t, true)
	sep.CaptchaConfig = optInConfig()
	setCentralForTest(t, centralTurnstile())
	assertCentralTurnstilePage(t, "exploit", serveNonTLS(router, sep, exploitURL, "198.51.100.1:1000"))

	// the verify endpoint reached through the exploit responder
	setCentralForTest(t, centralAltcha())
	sep.CaptchaConfig.ProtectedPathPrefixes = nil
	w := httptest.NewRecorder()
	r := altchaVerifyPost("198.51.100.1:1000")
	r.URL.RawQuery = "q=union+all+select+1"
	router.handleNonTLSRequest(w, r, sep)
	assertCentralVerify(t, "exploit verify", w)
}

func TestCentralCountryTrigger(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	sep.CaptchaConfig = optInConfig() // RequireCaptcha stays off: the country challenge does not need it
	rule.AddChallengeCountry("xx", "")
	setCountries(router, map[string]string{"198.51.100.9": "XX"})

	setCentralForTest(t, centralTurnstile())
	assertCentralTurnstilePage(t, "country", serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.9:1"))

	setCentralForTest(t, centralAltcha())
	w := httptest.NewRecorder()
	router.handleNonTLSRequest(w, altchaVerifyPost("198.51.100.9:1"), sep)
	assertCentralVerify(t, "country verify", w)
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com"+captcha.AltchaChallengePath, nil)
	r.RemoteAddr = "198.51.100.9:1"
	router.handleNonTLSRequest(w, r, sep)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"challenge"`) {
		t.Fatalf("country: altcha endpoint of the central provider not served: %d", w.Code)
	}
}

func TestCentralRulesEngineTrigger(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	addRule(t, eng, "", "challenge data", `http.path starts_with "/data"`, ruleset.Action{Type: ruleset.ActChallenge, TTLMinutes: 5})
	sep.CaptchaConfig = optInConfig()

	setCentralForTest(t, centralTurnstile())
	if !router.wafChallengeAvailable(sep) {
		t.Fatal("wafChallengeAvailable must see the central provider")
	}
	assertCentralTurnstilePage(t, "rules engine", rsGet(router, sep, "http://app.example.com/data", rsIPA, nil))

	setCentralForTest(t, centralAltcha())
	w := httptest.NewRecorder()
	if !router.ruleChallengeEndpoints(w, altchaVerifyPost(rsIPA), sep, "198.51.100.1") {
		t.Fatal("rule challenge verify endpoint not answered")
	}
	assertCentralVerify(t, "rules verify", w)
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com"+captcha.AltchaChallengePath, nil)
	if !router.ruleChallengeEndpoints(w, r, sep, "198.51.100.1") || !strings.Contains(w.Body.String(), `"challenge"`) {
		t.Fatalf("rules: altcha endpoint of the central provider not served: %d", w.Code)
	}
}

func TestCentralWAFChallengeTrigger(t *testing.T) {
	setCentralForTest(t, centralTurnstile())
	cfg := &waf.Config{Mode: waf.ModeBlock, ChallengeThreshold: 3, ChallengeTTLMinutes: 30, CustomRules: wafProbeRules}
	var ep *ProxyEndpoint
	h, hits, _ := newCentralWAFTestProxy(t, nil, func(e *ProxyEndpoint) {
		e.WAF = cfg
		e.CaptchaConfig = optInConfig()
		ep = e
	})
	h.Parent.captchaSessionStore = captcha.NewSessionStore()
	h.Parent.Option.WAFChallengeKeyFile = t.TempDir() + "/waf_challenge.key"

	w := serveWith(h, navReq("/?probe=3", ipA, uaA), nil)
	assertCentralTurnstilePage(t, "waf challenge", w)
	if atomic.LoadInt32(hits) != 0 {
		t.Fatal("request reached the upstream")
	}

	// verify handler of the WAF challenge band
	setCentralForTest(t, centralAltcha())
	wv := httptest.NewRecorder()
	if !h.Parent.wafChallengeVerify(wv, altchaVerifyPost(ipA), ep, cfg, "198.51.100.9") {
		t.Fatal("waf verify endpoint not answered")
	}
	assertCentralVerify(t, "waf verify", wv)
}

func TestCentralMissingFailsClosed(t *testing.T) {
	// no central provider configured at all
	captcha.SetCentral(nil)
	cfg := optInConfig()
	if captcha.ResolveCentral(cfg).IsConfigured() {
		t.Fatal("UseCentral without a central provider must not be configured")
	}

	// plain gate: blocked page, never an open door; exempt paths still pass
	router, sep, _ := newNonTLSTestRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	sep.RequireCaptcha = true
	sep.CaptchaConfig = optInConfig()
	sep.CaptchaConfig.ProtectedPathPrefixes = []string{"/private"}
	w := serveNonTLS(router, sep, "http://app.example.com/private/x", "198.51.100.1:1")
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), ownSiteKey) {
		t.Fatalf("plain gate without a central provider must fail closed: %d", w.Code)
	}
	if w := serveNonTLS(router, sep, "http://app.example.com/public", "198.51.100.1:1"); w.Code != 299 {
		t.Fatalf("path outside the protected prefixes must pass: %d", w.Code)
	}
	if router.wafChallengeAvailable(sep) {
		t.Fatal("wafChallengeAvailable must be false without a usable central provider")
	}

	// the other triggers fail closed through their existing fallbacks
	sep.CaptchaConfig.ProtectedPathPrefixes = nil
	rule, _ := router.Option.AccessController.GetAccessRuleByID("default")
	rule.AddChallengeCountry("xx", "")
	setCountries(router, map[string]string{"198.51.100.9": "XX"})
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.9:1"); w.Code != 403 || strings.Contains(w.Body.String(), "turnstile") {
		t.Fatalf("country challenge without a central provider must block: %d", w.Code)
	}

	// an UNCONFIGURED (not just missing) central config behaves the same
	setCentralForTest(t, &captcha.Central{Provider: captcha.ProviderCloudflare, SiteKey: "only-site-key"})
	if sep.EffectiveCaptchaConfig().IsConfigured() {
		t.Fatal("a central config without a secret must not be configured")
	}
}

func TestCentralOffIsUnchanged(t *testing.T) {
	// a rule that did not opt in ignores the central config completely
	setCentralForTest(t, centralTurnstile())
	router, sep, _ := newNonTLSTestRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	sep.RequireCaptcha = true
	sep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderCloudflare, SiteKey: ownSiteKey, SecretKey: "own-secret"}
	w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.1:1")
	if !strings.Contains(w.Body.String(), `"siteKey":"`+ownSiteKey+`"`) || strings.Contains(w.Body.String(), centralSiteKey) {
		t.Fatalf("a rule without UseCentral must keep its own provider: %.200q", w.Body.String())
	}
}
