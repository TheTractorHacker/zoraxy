package dynamicproxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
)

func setCountries(router *Router, m map[string]string) {
	router.Option.AccessController.CountryResolver = func(ip string) (string, error) {
		if cc, ok := m[ip]; ok {
			return cc, nil
		}
		return "US", nil
	}
}

func TestCountryChallenge(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	router.captchaSessionStore = captcha.NewSessionStore()
	setCountries(router, map[string]string{"198.51.100.9": "XX", "198.51.100.10": "US"})
	rule.AddChallengeCountry("xx", "challenge test")

	// no CAPTCHA configured on the endpoint: fail closed (block), never open
	w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.9:1000")
	if w.Code != 403 || strings.Contains(w.Body.String(), "captcha") && w.Code == 299 {
		t.Fatalf("challenge without CAPTCHA must block, got %d", w.Code)
	}

	sep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderCloudflare, SiteKey: "k", SecretKey: "s"}
	// other countries are untouched
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.10:1000"); w.Code != 299 {
		t.Fatalf("unlisted country affected: %d", w.Code)
	}
	// challenged country gets the CAPTCHA page, upstream is never reached
	w = serveNonTLS(router, sep, "http://app.example.com/secret", "198.51.100.9:1000")
	if w.Code == 299 {
		t.Fatal("challenged client reached the upstream without a CAPTCHA")
	}
	if !strings.Contains(strings.ToLower(w.Body.String()), "captcha") && !strings.Contains(strings.ToLower(w.Body.String()), "turnstile") {
		t.Fatalf("no challenge page served: %d %q", w.Code, w.Body.String())
	}
	// a forged or foreign-host cookie does not pass
	for _, v := range []string{"garbage", "1.2.3", ""} {
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		r.RemoteAddr = "198.51.100.9:1000"
		r.AddCookie(&http.Cookie{Name: captcha.CookieName, Value: v})
		rec := httptest.NewRecorder()
		router.handleNonTLSRequest(rec, r, sep)
		if rec.Code == 299 {
			t.Fatalf("forged session %q accepted", v)
		}
	}
	// a valid session passes
	tok, _ := router.captchaSessionStore.Issue("app.example.com", 300)
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.RemoteAddr = "198.51.100.9:1000"
	r.AddCookie(&http.Cookie{Name: captcha.CookieName, Value: tok})
	rec := httptest.NewRecorder()
	router.handleNonTLSRequest(rec, r, sep)
	if rec.Code != 299 {
		t.Fatalf("verified session rejected: %d", rec.Code)
	}
	// a blacklist entry still wins over the challenge
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.9", "x")
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.9:1000"); w.Code != 403 {
		t.Fatalf("blacklist must win: %d", w.Code)
	}
}

func TestCountryChallengeUnresolvableCountryIsNotChallenged(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	rule.AddChallengeCountry("xx", "")
	router.Option.AccessController.CountryResolver = func(string) (string, error) { return "", http.ErrNotSupported }
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.9:1000"); w.Code != 299 {
		t.Fatalf("lookup failure changed behaviour: %d", w.Code)
	}
}

func TestDropOnBlock(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.9", "t")

	// default off: normal 403 page
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.9:1"); w.Code != 403 || w.Body.Len() == 0 {
		t.Fatalf("default must stay the 403 page: %d", w.Code)
	}
	rule.DropOnBlock = true
	// HTTP/1: hijack, close, nothing written
	srv, cli := net.Pipe()
	defer cli.Close()
	hw := &hijackRecorder{httptest.NewRecorder(), srv}
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.RemoteAddr = "198.51.100.9:1"
	router.handleNonTLSRequest(hw, r, sep)
	buf := make([]byte, 1)
	if n, err := cli.Read(buf); n != 0 || err == nil {
		t.Fatal("connection not closed")
	}
	if hw.Body.Len() != 0 || hw.Code == 403 && hw.Body.Len() > 0 {
		t.Fatal("response written to a dropped client")
	}
	// HTTP/2: abort
	func() {
		defer func() {
			if rec := recover(); rec != http.ErrAbortHandler {
				t.Fatalf("want ErrAbortHandler, got %v", rec)
			}
		}()
		router.handleNonTLSRequest(httptest.NewRecorder(), r, sep)
	}()
	// whitelist rejection also drops
	rule.BlacklistEnabled = false
	rule.WhitelistEnabled = true
	func() {
		defer func() {
			if rec := recover(); rec != http.ErrAbortHandler {
				t.Fatalf("whitelist miss not dropped: %v", rec)
			}
		}()
		router.handleNonTLSRequest(httptest.NewRecorder(), r, sep)
	}()
	// allowed clients are never dropped
	rule.WhitelistEnabled = false
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.77:1"); w.Code != 299 {
		t.Fatalf("clean client: %d", w.Code)
	}
}
