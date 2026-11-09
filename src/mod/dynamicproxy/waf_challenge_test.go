package dynamicproxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

const wafProbeRules = `
SecRule ARGS:probe "@streq 3" "id:1000102,phase:1,pass,log,msg:'band probe 3',severity:'WARNING',setvar:'tx.inbound_anomaly_score_pl1=+3'"
`

func TestWAFChallengeSigner(t *testing.T) {
	s := &wafChallengeSigner{key: []byte("0123456789abcdef0123456789abcdef")}
	other := &wafChallengeSigner{key: []byte("fedcba9876543210fedcba9876543210")}
	val, _ := s.Issue("App.Example.com", "198.51.100.9:5000", "UA/1", time.Hour)

	if !s.Validate(val, "app.example.com", "198.51.100.9", "UA/1") {
		t.Fatal("fresh cookie rejected (port and host case must not matter)")
	}
	bad := map[string]bool{
		"other ip":       s.Validate(val, "app.example.com", "198.51.100.10", "UA/1"),
		"other ua":       s.Validate(val, "app.example.com", "198.51.100.9", "UA/2"),
		"other endpoint": s.Validate(val, "other.example.com", "198.51.100.9", "UA/1"),
		"other key":      other.Validate(val, "app.example.com", "198.51.100.9", "UA/1"),
		"empty":          s.Validate("", "app.example.com", "198.51.100.9", "UA/1"),
		"garbage":        s.Validate("not.a.cookie", "app.example.com", "198.51.100.9", "UA/1"),
		"no mac":         s.Validate(strings.Split(val, ".")[0]+".", "app.example.com", "198.51.100.9", "UA/1"),
		"truncated mac":  s.Validate(val[:len(val)-4], "app.example.com", "198.51.100.9", "UA/1"),
	}
	// tamper with a payload byte, keep the MAC
	parts := strings.SplitN(val, ".", 2)
	flipped := []byte(parts[0])
	flipped[len(flipped)/2] ^= 1
	bad["tampered payload"] = s.Validate(string(flipped)+"."+parts[1], "app.example.com", "198.51.100.9", "UA/1")
	expired, _ := s.Issue("app.example.com", "198.51.100.9", "UA/1", -time.Second)
	bad["expired"] = s.Validate(expired, "app.example.com", "198.51.100.9", "UA/1")
	for name, ok := range bad {
		if ok {
			t.Errorf("%s: cookie accepted", name)
		}
	}
}

func TestWAFChallengeKeyIsPersistedPerInstall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf", "waf_challenge.key")
	k1 := loadWAFChallengeKey(path)
	k2 := loadWAFChallengeKey(path)
	if len(k1) < 32 || string(k1) != string(k2) {
		t.Fatal("key must be created once and reused")
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0600 {
		t.Errorf("key file: %v %v", st, err)
	}
	if k3 := loadWAFChallengeKey(filepath.Join(dir, "other.key")); string(k3) == string(k1) {
		t.Error("two installs share a key")
	}
	if a, b := loadWAFChallengeKey(""), loadWAFChallengeKey(""); string(a) == string(b) {
		t.Error("in-memory keys must be random")
	}
}

func stubTurnstile(t *testing.T, answer string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(answer))
	}))
	old := captcha.TurnstileVerifyURL
	captcha.TurnstileVerifyURL = srv.URL
	t.Cleanup(func() { captcha.TurnstileVerifyURL = old; srv.Close() })
}

func challengeProxy(t *testing.T, withCaptcha bool, mode string) (*ProxyHandler, *int32) {
	t.Helper()
	cfg := &waf.Config{Mode: mode, ChallengeThreshold: 3, ChallengeTTLMinutes: 30, CustomRules: wafProbeRules}
	h, hits, _ := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) {
		ep.WAF = cfg
		if withCaptcha {
			ep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderCloudflare, SiteKey: "site", SecretKey: "secret"}
		}
	})
	h.Parent.captchaSessionStore = captcha.NewSessionStore()
	h.Parent.Option.WAFChallengeKeyFile = filepath.Join(t.TempDir(), "waf_challenge.key")
	return h, hits
}

func navReq(target string, remote, ua string) *http.Request {
	r := wafReq("GET", target, nil, map[string]string{"Accept": "text/html,application/xhtml+xml", "User-Agent": ua})
	r.RemoteAddr = remote
	return r
}

const (
	uaA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36"
	uaB = "Mozilla/5.0 (Windows NT 10.0) Firefox/121.0"
	ipA = "198.51.100.9:50000"
	ipB = "198.51.100.77:50000"
)

// solve answers a challenge through the verification endpoint and returns the challenge cookie
func solve(t *testing.T, h *ProxyHandler, remote, ua string, tlsConn bool) *http.Cookie {
	t.Helper()
	form := url.Values{"cf-turnstile-response": {"token"}}
	r := httptest.NewRequest("POST", "http://waf.test"+captcha.VerifyPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", ua)
	r.RemoteAddr = remote
	if tlsConn {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("verification answered %d: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == wafChallengeCookie {
			return c
		}
	}
	t.Fatal("verification did not set the WAF challenge cookie")
	return nil
}

func serveWith(h *ProxyHandler, r *http.Request, c *http.Cookie) *httptest.ResponseRecorder {
	if c != nil {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func countEvents(action string) int {
	return len(waf.Default.QueryEvents(waf.EventFilter{Endpoint: "waf.test", Action: action}))
}

func TestWAFChallengeFlowThroughProxy(t *testing.T) {
	stubTurnstile(t, `{"success":true}`)
	h, hits := challengeProxy(t, true, waf.ModeBlock)
	chBefore, passBefore := countEvents(waf.ActionChallenged), countEvents(waf.ActionChallengePassed)

	// below the band: untouched
	if w := serveWith(h, navReq("/?probe=0", ipA, uaA), nil); w.Code != 200 || atomic.LoadInt32(hits) != 1 {
		t.Fatalf("clean request: %d", w.Code)
	}

	// in the band: the existing CAPTCHA page (403 by the CAPTCHA convention), upstream not reached
	w := serveWith(h, navReq("/?probe=3", ipA, uaA), nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "turnstile") || atomic.LoadInt32(hits) != 1 {
		t.Fatalf("band request: code=%d hits=%d body=%.80q", w.Code, atomic.LoadInt32(hits), w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("challenge page must not be cached")
	}
	if countEvents(waf.ActionChallenged) != chBefore+1 {
		t.Error("challenged event not recorded")
	}

	// block band: normal block page, never the challenge
	if w := serveWith(h, navReq(sqliQuery, ipA, uaA), nil); w.Code != 403 || strings.Contains(w.Body.String(), "turnstile") {
		t.Fatalf("block band: %d", w.Code)
	}

	// solve it
	c := solve(t, h, ipA, uaA, false)
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure || c.Path != "/" || c.MaxAge != 30*60 {
		t.Errorf("cookie attributes: %+v", c)
	}
	if tc := solve(t, h, ipA, uaA, true); !tc.Secure {
		t.Error("cookie must be Secure on TLS")
	}

	// the cookie passes the band (and is logged), but not the block band
	if w := serveWith(h, navReq("/?probe=3", ipA, uaA), c); w.Code != 200 || atomic.LoadInt32(hits) != 2 {
		t.Fatalf("valid cookie in the band: code=%d hits=%d", w.Code, atomic.LoadInt32(hits))
	}
	if countEvents(waf.ActionChallengePassed) != passBefore+1 {
		t.Error("challenge_passed event not recorded")
	}
	if w := serveWith(h, navReq(sqliQuery, ipA, uaA), c); w.Code != 403 {
		t.Fatalf("a solved challenge must not open the block band, got %d", w.Code)
	}

	// replayed from another IP, another User-Agent, tampered, expired, signed by another key
	rejected := map[string]*http.Request{
		"other ip": navReq("/?probe=3", ipB, uaA),
		"other ua": navReq("/?probe=3", ipA, uaB),
	}
	for name, r := range rejected {
		if w := serveWith(h, r, c); w.Code != 403 || !strings.Contains(w.Body.String(), "turnstile") {
			t.Errorf("%s: cookie accepted (code=%d)", name, w.Code)
		}
	}
	signer := h.Parent.wafChallengeSigner()
	expired, _ := signer.Issue("waf.test", ipA, uaA, -time.Minute)
	forged, _ := (&wafChallengeSigner{key: []byte("an attacker's own key, 32+ bytes....")}).Issue("waf.test", ipA, uaA, time.Hour)
	for name, val := range map[string]string{"expired": expired, "forged": forged, "tampered": c.Value[:len(c.Value)-2] + "xx", "junk": "x"} {
		if w := serveWith(h, navReq("/?probe=3", ipA, uaA), &http.Cookie{Name: wafChallengeCookie, Value: val}); w.Code != 403 {
			t.Errorf("%s cookie accepted (code=%d)", name, w.Code)
		}
	}
	// the generic CAPTCHA session cookie does not unlock the band either
	sess, _ := h.Parent.captchaSessionStore.Issue("waf.test", 3600)
	if w := serveWith(h, navReq("/?probe=3", ipA, uaA), &http.Cookie{Name: captcha.CookieName, Value: sess}); w.Code != 403 {
		t.Errorf("CAPTCHA session cookie opened the band (code=%d)", w.Code)
	}
}

func TestWAFChallengeFailedVerificationSetsNoCookie(t *testing.T) {
	stubTurnstile(t, `{"success":false,"error-codes":["invalid-input-response"]}`)
	h, _ := challengeProxy(t, true, waf.ModeBlock)
	form := url.Values{"cf-turnstile-response": {"token"}}
	r := httptest.NewRequest("POST", "http://waf.test"+captcha.VerifyPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	r.RemoteAddr = ipA
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("failed verification: code=%d cookies=%v", w.Code, w.Result().Cookies())
	}
}

func TestWAFChallengeWithoutProviderBlocks(t *testing.T) {
	h, hits := challengeProxy(t, false, waf.ModeBlock)
	w := serveWith(h, navReq("/?probe=3", ipA, uaA), nil)
	if w.Code != 403 || strings.Contains(w.Body.String(), "turnstile") || atomic.LoadInt32(hits) != 0 {
		t.Fatalf("no provider must block with the normal 403 page: code=%d hits=%d", w.Code, atomic.LoadInt32(hits))
	}
	if !strings.Contains(w.Body.String(), "Request ID") {
		t.Error("expected the WAF block page")
	}
}

func TestWAFChallengeNonNavigationIsBlocked(t *testing.T) {
	h, hits := challengeProxy(t, true, waf.ModeBlock)
	api := wafReq("GET", "/?probe=3", nil, map[string]string{"Accept": "application/json"})
	if w := serveWith(h, api, nil); w.Code != 403 || strings.Contains(w.Body.String(), "turnstile") {
		t.Errorf("API client in the band: %d", w.Code)
	}
	post := wafReq("POST", "/?probe=3", []byte("a=b"), map[string]string{"Accept": "text/html", "Content-Type": "application/x-www-form-urlencoded"})
	if w := serveWith(h, post, nil); w.Code != 403 || strings.Contains(w.Body.String(), "turnstile") {
		t.Errorf("POST in the band: %d", w.Code)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Error("blocked requests reached the upstream")
	}
}

func TestWAFChallengeDetectionOnlyNeverActs(t *testing.T) {
	h, hits := challengeProxy(t, true, waf.ModeDetectionOnly)
	for _, target := range []string{"/?probe=3", sqliQuery} {
		if w := serveWith(h, navReq(target, ipA, uaA), nil); w.Code != 200 {
			t.Errorf("detection_only %s: %d", target, w.Code)
		}
	}
	if atomic.LoadInt32(hits) != 2 {
		t.Errorf("hits = %d", atomic.LoadInt32(hits))
	}
}

func TestWAFChallengeOffIsUnchanged(t *testing.T) {
	h, hits, _ := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) {
		ep.WAF = &waf.Config{Mode: waf.ModeBlock, CustomRules: wafProbeRules}
		ep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderCloudflare, SiteKey: "site", SecretKey: "secret"}
	})
	h.Parent.captchaSessionStore = captcha.NewSessionStore()
	if w := serveWith(h, navReq("/?probe=3", ipA, uaA), nil); w.Code != 200 || atomic.LoadInt32(hits) != 1 {
		t.Fatalf("band off: code=%d", w.Code)
	}
	// the verify path is not claimed by the WAF when the band is off: a wrong method reaches the normal chain
	r := httptest.NewRequest("GET", "http://waf.test"+captcha.VerifyPath, nil)
	r.RemoteAddr = ipA
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Set-Cookie") != "" {
		t.Error("unexpected cookie")
	}
}

// Challenged requests must not feed the automatic ban; blocked requests still do.
func TestWAFChallengedRequestsDoNotFeedAutoBan(t *testing.T) {
	h, _ := challengeProxy(t, true, waf.ModeBlock)
	m := abuse.New("")
	c := abuse.DefaultConfig()
	c.Enabled = true
	c.Detectors[abuse.KindForbidden] = abuse.Detector{Enabled: true, Threshold: 3, WindowSec: 60}
	c.Detectors[abuse.KindWAF] = abuse.Detector{Enabled: true, Threshold: 3, WindowSec: 60}
	if err := m.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	h.Parent.Option.Abuse = m
	var observed int32 // the notification spike detector must only see blocks
	oldObs := BlockObserver
	BlockObserver = func(site, forwardType string) { atomic.AddInt32(&observed, 1) }
	t.Cleanup(func() { BlockObserver = oldObs })

	for i := 0; i < 10; i++ {
		if w := serveWith(h, navReq("/?probe=3", ipA, uaA), nil); w.Code != 403 || !strings.Contains(w.Body.String(), "turnstile") {
			t.Fatalf("request %d not challenged: %d", i, w.Code)
		}
	}
	if len(m.List()) != 0 {
		t.Fatalf("challenged requests produced a ban: %+v", m.List())
	}
	if n := atomic.LoadInt32(&observed); n != 0 {
		t.Errorf("block observer saw %d challenged requests", n)
	}
	for i := 0; i < 3; i++ {
		serveWith(h, navReq(sqliQuery, ipA, uaA), nil)
	}
	if n := atomic.LoadInt32(&observed); n != 3 {
		t.Errorf("block observer saw %d blocks, want 3", n)
	}
	if _, banned := m.IsBanned("198.51.100.9", ""); !banned {
		t.Fatal("blocked requests must still feed the ban")
	}
}
