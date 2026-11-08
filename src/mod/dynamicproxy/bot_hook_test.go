package dynamicproxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
)

func newBotRouter(t *testing.T, mod func(*botrules.Config)) (*Router, *ProxyEndpoint, *botrules.Engine) {
	t.Helper()
	router, sep, _ := newNonTLSTestRouter(t)
	e := botrules.New("")
	c := botrules.DefaultConfig()
	c.Enabled = true
	c.Categories["scanner"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionBlock}
	if mod != nil {
		mod(&c)
	}
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	router.Option.Bots = e
	return router, sep, e
}

func serveUA(router *Router, sep *ProxyEndpoint, ua string) *httptest.ResponseRecorder {
	return serveWithHeaders(router, sep, "/", map[string][]string{"User-Agent": {ua}})
}

func TestBotRulesBlockAndPolicy(t *testing.T) {
	router, sep, _ := newBotRouter(t, nil)
	if w := serveUA(router, sep, "sqlmap/1.5"); w.Code != 403 {
		t.Fatalf("scanner not blocked: %d", w.Code)
	}
	if w := serveUA(router, sep, "Mozilla/5.0 Firefox"); w.Code != 299 {
		t.Fatalf("browser blocked: %d", w.Code)
	}
	sep.BotPolicy = "off"
	if w := serveUA(router, sep, "sqlmap/1.5"); w.Code != 299 {
		t.Fatalf("endpoint opt-out ignored: %d", w.Code)
	}
	// globally off + endpoint opt-in
	sep.BotPolicy = "on"
	c := router.Option.Bots.Config()
	c.Enabled = false
	router.Option.Bots.SetConfig(c)
	if w := serveUA(router, sep, "sqlmap/1.5"); w.Code != 403 {
		t.Fatalf("endpoint opt-in ignored: %d", w.Code)
	}
	sep.BotPolicy = ""
	if w := serveUA(router, sep, "sqlmap/1.5"); w.Code != 299 {
		t.Fatalf("globally disabled engine still blocks: %d", w.Code)
	}
	// no engine at all = unchanged
	router.Option.Bots = nil
	if w := serveUA(router, sep, "sqlmap/1.5"); w.Code != 299 {
		t.Fatal("nil engine changed behaviour")
	}
}

func TestBotRulesLogOnlyAndDrop(t *testing.T) {
	router, sep, _ := newBotRouter(t, func(c *botrules.Config) {
		c.Categories["scanner"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionLog}
		c.Custom = []botrules.Rule{{Name: "x", Pattern: "dropme", Action: botrules.ActionDrop}}
	})
	if w := serveUA(router, sep, "sqlmap"); w.Code != 299 {
		t.Fatalf("log-only must not block: %d", w.Code)
	}
	srv, cli := net.Pipe()
	defer cli.Close()
	hw := &hijackRecorder{httptest.NewRecorder(), srv}
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.RemoteAddr = "198.51.100.1:1"
	r.Header.Set("User-Agent", "dropme")
	router.handleNonTLSRequest(hw, r, sep)
	buf := make([]byte, 1)
	if n, err := cli.Read(buf); n != 0 || err == nil || hw.Body.Len() != 0 {
		t.Fatal("drop must close the connection without a response")
	}
}

func TestBotRulesChallenge(t *testing.T) {
	router, sep, _ := newBotRouter(t, func(c *botrules.Config) {
		c.Categories["scanner"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionChallenge}
	})
	router.captchaSessionStore = captcha.NewSessionStore()
	// no CAPTCHA on the endpoint: fail closed
	if w := serveUA(router, sep, "nikto"); w.Code != 403 {
		t.Fatalf("challenge without CAPTCHA must block: %d", w.Code)
	}
	sep.CaptchaConfig = &captcha.Config{Provider: captcha.ProviderCloudflare, SiteKey: "k", SecretKey: "s"}
	w := serveUA(router, sep, "nikto")
	if w.Code == 299 || !strings.Contains(strings.ToLower(w.Body.String()), "captcha") && !strings.Contains(strings.ToLower(w.Body.String()), "turnstile") {
		t.Fatalf("no challenge page: %d", w.Code)
	}
	tok, _ := router.captchaSessionStore.Issue("app.example.com", 300)
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.RemoteAddr = "198.51.100.1:1"
	r.Header.Set("User-Agent", "nikto")
	r.AddCookie(&http.Cookie{Name: captcha.CookieName, Value: tok})
	rec := httptest.NewRecorder()
	router.handleNonTLSRequest(rec, r, sep)
	if rec.Code != 299 {
		t.Fatalf("solved challenge rejected: %d", rec.Code)
	}
}

func TestBotRulesDuplicateUserAgentHeaders(t *testing.T) {
	router, sep, _ := newBotRouter(t, nil)
	// only the first User-Agent value is what r.UserAgent() reports; a second one must not hide the first
	w := serveWithHeaders(router, sep, "/", map[string][]string{"User-Agent": {"sqlmap", "Mozilla/5.0"}})
	if w.Code != 403 {
		t.Fatalf("bot hidden behind a second header: %d", w.Code)
	}
}
