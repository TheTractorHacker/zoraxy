package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/aicrawler"
	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

const gptUA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"

func crawlerEngine(t *testing.T, mod func(*aicrawler.Config)) *aicrawler.Engine {
	t.Helper()
	e := aicrawler.New("", "")
	c := aicrawler.DefaultConfig()
	c.Enabled = true
	if mod != nil {
		mod(&c)
	}
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestAICrawlerPolicyOffChangesNothing(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	// no engine, disabled engine, enabled engine without a policy: the request reaches the next stage
	for name, eng := range map[string]*aicrawler.Engine{"nil": nil, "disabled": aicrawler.New("", ""), "no policy": crawlerEngine(t, nil)} {
		router.Option.AICrawlers = eng
		if w := serveUA(router, sep, gptUA); w.Code != 299 {
			t.Errorf("%s: got %d", name, w.Code)
		}
	}
	// the older all-or-nothing switch keeps working exactly as before when no policy is set
	sep.BlockAICrawlers = true
	sep.MitigationAction = 1
	sep.InitializeExploitDetector()
	router.Option.AICrawlers = crawlerEngine(t, nil)
	if w := serveUA(router, sep, gptUA); w.Code != 403 {
		t.Fatalf("the AI crawlers switch no longer blocks: %d", w.Code)
	}
	router.Option.AICrawlers = nil
	if w := serveUA(router, sep, gptUA); w.Code != 403 {
		t.Fatalf("the AI crawlers switch no longer blocks without the engine: %d", w.Code)
	}
}

func TestAICrawlerActions(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	router.Option.AICrawlers = crawlerEngine(t, func(c *aicrawler.Config) {
		c.Global.Crawlers = map[string]string{"gptbot": aicrawler.ActBlock, "ccbot": aicrawler.ActChallenge, "claudebot": aicrawler.ActRateLimit, "bytespider": aicrawler.ActLog}
		c.Global.RateLimitPerMinute = 2
	})
	if w := serveUA(router, sep, gptUA); w.Code != 403 {
		t.Fatalf("block: %d", w.Code)
	}
	if w := serveUA(router, sep, "CCBot/2.0"); w.Code != 403 { // no CAPTCHA configured: fail closed like the bot rules
		t.Fatalf("challenge without a CAPTCHA must fail closed: %d", w.Code)
	}
	codes := []int{}
	for i := 0; i < 3; i++ {
		w := serveUA(router, sep, "ClaudeBot/1.0")
		codes = append(codes, w.Code)
		if w.Code == 429 && w.Header().Get("Retry-After") == "" {
			t.Error("429 without Retry-After")
		}
	}
	if codes[0] != 299 || codes[1] != 299 || codes[2] != 429 {
		t.Fatalf("rate limit: %v", codes)
	}
	if w := serveUA(router, sep, "Bytespider"); w.Code != 299 {
		t.Fatalf("log-only must not block: %d", w.Code)
	}
	if w := serveUA(router, sep, "Mozilla/5.0 Firefox/120"); w.Code != 299 {
		t.Fatalf("a browser is not affected: %d", w.Code)
	}
	// the decisions are in the blocked-request log with crawler name and decision; log-only is not a block
	items := waitBlocked(t, bl, 3)
	got := map[string]bool{}
	for _, it := range items {
		if it.Reason != blocklog.ReasonAICrawler {
			t.Errorf("reason %q", it.Reason)
		}
		got[it.Detail] = true
	}
	for _, want := range []string{"GPTBot (training)", "CCBot (training)", "ClaudeBot (training)"} {
		found := false
		for k := range got {
			if strings.Contains(k, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no log entry mentions %q: %v", want, got)
		}
	}
}

func TestAICrawlerAllowOverridesLegacySwitchAndBotCategory(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.BlockAICrawlers = true
	sep.MitigationAction = 1
	sep.InitializeExploitDetector()
	be := botrules.New("")
	bc := botrules.DefaultConfig()
	bc.Enabled = true
	bc.Categories["ai_crawler"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionBlock}
	bc.Categories["scanner"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionBlock}
	if err := be.SetConfig(bc); err != nil {
		t.Fatal(err)
	}
	router.Option.Bots = be
	// without a policy both older mechanisms block
	if w := serveUA(router, sep, gptUA); w.Code != 403 {
		t.Fatalf("legacy switch / bot category: %d", w.Code)
	}
	router.Option.AICrawlers = crawlerEngine(t, func(c *aicrawler.Config) { c.Global.Crawlers = map[string]string{"gptbot": aicrawler.ActAllow} })
	if w := serveUA(router, sep, gptUA); w.Code != 299 {
		t.Fatalf("an allowed crawler must pass the AI switch and the AI bot category: %d", w.Code)
	}
	// other AI crawlers without a policy are still stopped by the older switch
	if w := serveUA(router, sep, "ClaudeBot/1.0"); w.Code != 403 {
		t.Fatalf("a crawler without a policy changed behaviour: %d", w.Code)
	}
	// allowed is not exempt from the rest of the bot rules
	if w := serveUA(router, sep, gptUA+" sqlmap"); w.Code != 403 {
		t.Fatalf("an allowed crawler must still meet the other bot rules: %d", w.Code)
	}
	// ... nor from the common exploit patterns
	sep.BlockCommonExploits = true
	sep.InitializeExploitDetector()
	w := serveWithHeaders(router, sep, "/?q=union+all+select+1", map[string][]string{"User-Agent": {gptUA}})
	if w.Code != 403 {
		t.Fatalf("an allowed crawler must still meet the exploit patterns: %d", w.Code)
	}
}

func TestAICrawlerSpoofedClaimGetsTheSpoofAction(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	e := crawlerEngine(t, func(c *aicrawler.Config) {
		c.Global.Groups = map[string]string{aicrawler.GroupTraining: aicrawler.ActAllow}
		c.Global.VerifiedOnly = true
	})
	// the router resolves the client as 198.51.100.1 (see serveWithHeaders); only the documentation range 192.0.2.0/24 is "real"
	e.Ranges.SetPrefixes("openai-gptbot", []string{"192.0.2.0/24"}, time.Now())
	router.Option.AICrawlers = e
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	if w := serveUA(router, sep, gptUA); w.Code != 403 {
		t.Fatalf("a GPTBot claim from outside the published ranges must be refused: %d", w.Code)
	}
	items := waitBlocked(t, bl, 1)
	if !strings.Contains(items[0].Detail, "GPTBot") || !strings.Contains(items[0].Detail, "failed") {
		t.Fatalf("log detail %q", items[0].Detail)
	}
	// the genuine address is let through
	e.Ranges.SetPrefixes("openai-gptbot", []string{"198.51.100.0/24"}, time.Now())
	if w := serveUA(router, sep, gptUA); w.Code != 299 {
		t.Fatalf("a verified crawler must pass: %d", w.Code)
	}
}

// the WAF still inspects an allowed crawler unless the bypass is ticked AND the crawler is verified
func TestAICrawlerWAFOrder(t *testing.T) {
	build := func(mod func(*aicrawler.Config)) (*ProxyHandler, *int32) {
		h, hits, _ := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) { ep.WAF = &waf.Config{Mode: waf.ModeBlock} })
		e := crawlerEngine(t, func(c *aicrawler.Config) {
			c.Global.Crawlers = map[string]string{"gptbot": aicrawler.ActAllow}
			if mod != nil {
				mod(c)
			}
		})
		e.Ranges.SetPrefixes("openai-gptbot", []string{"198.51.100.0/24"}, time.Now()) // wafReq comes from 198.51.100.9
		h.Parent.Option.AICrawlers = e
		return h, hits
	}
	attack := "/item?id=1%27%20OR%20%271%27%3D%271"
	do := func(h *ProxyHandler) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, wafReq("GET", attack, nil, map[string]string{"User-Agent": gptUA}))
		return w.Code
	}
	h, hits := build(nil)
	if code := do(h); code != 403 || atomic.LoadInt32(hits) != 0 {
		t.Fatalf("an allowed crawler must still be inspected by the WAF: %d", code)
	}
	h, hits = build(func(c *aicrawler.Config) { c.Global.BypassWAF = true })
	if code := do(h); code != 200 || atomic.LoadInt32(hits) != 1 {
		t.Fatalf("verified + bypass ticked must skip the WAF: %d", code)
	}
	// ticked, but not verified (VerifiedOnly off, address outside the range) -> WAF applies
	h, hits = build(func(c *aicrawler.Config) { c.Global.BypassWAF = true })
	h.Parent.Option.AICrawlers.Ranges.SetPrefixes("openai-gptbot", []string{"192.0.2.0/24"}, time.Now())
	if code := do(h); code != 403 {
		t.Fatalf("an unverified crawler must never bypass the WAF: %d", code)
	}
	// without the policy the attack is blocked as always (and a normal request passes)
	h, _ = build(nil)
	h.Parent.Option.AICrawlers = nil
	if code := do(h); code != 403 {
		t.Fatalf("baseline: %d", code)
	}
}

func TestRobotsAndLLMSServeAndMerge(t *testing.T) {
	h, hits, _ := newCentralWAFTestProxy(t, nil, nil) // the upstream answers every path with 200 "upstream-ok"
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := wafReq("GET", path, nil, nil)
		h.ServeHTTP(w, r)
		return w
	}
	// off by default: the upstream's answer, untouched
	h.Parent.Option.AICrawlers = crawlerEngine(t, func(c *aicrawler.Config) {
		c.Global.Groups = map[string]string{aicrawler.GroupTraining: aicrawler.ActBlock}
	})
	if w := get("/robots.txt"); w.Body.String() != "upstream-ok" {
		t.Fatalf("robots.txt must be left alone by default: %q", w.Body.String())
	}
	// merge: the upstream file is kept and the generated rules are appended
	h.Parent.Option.AICrawlers = crawlerEngine(t, func(c *aicrawler.Config) {
		c.Global.Groups = map[string]string{aicrawler.GroupTraining: aicrawler.ActBlock}
		c.Sites = map[string]*aicrawler.SiteCfg{"waf.test": {Robots: aicrawler.RobotsCfg{Mode: aicrawler.RobotsMerge}, LLMS: aicrawler.LLMSCfg{Mode: aicrawler.LLMSFallback, Text: "# Site"}}}
	})
	w := get("/robots.txt")
	body := w.Body.String()
	if !strings.HasPrefix(body, "upstream-ok\n") || !strings.Contains(body, "User-agent: GPTBot\nUser-agent:") || !strings.Contains(body, "Disallow: /") {
		t.Fatalf("merge:\n%q", body)
	}
	if w.Header().Get("Content-Length") != "" && w.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Errorf("stale Content-Length %q for %d bytes", w.Header().Get("Content-Length"), len(body))
	}
	// the upstream has an llms.txt (it answers 200): fallback leaves it alone
	if w := get("/llms.txt"); w.Body.String() != "upstream-ok" {
		t.Fatalf("llms fallback replaced an existing upstream file: %q", w.Body.String())
	}
	// serve instead: the generated file, the upstream is not asked
	before := atomic.LoadInt32(hits)
	h.Parent.Option.AICrawlers = crawlerEngine(t, func(c *aicrawler.Config) {
		c.Global.Groups = map[string]string{aicrawler.GroupTraining: aicrawler.ActBlock}
		c.Sites = map[string]*aicrawler.SiteCfg{"waf.test": {Robots: aicrawler.RobotsCfg{Mode: aicrawler.RobotsServe}, LLMS: aicrawler.LLMSCfg{Mode: aicrawler.LLMSServe, Text: "# Site\n> hello"}}}
	})
	w = get("/robots.txt")
	if strings.Contains(w.Body.String(), "upstream-ok") || !strings.HasSuffix(w.Body.String(), "User-agent: *\nDisallow:\n") || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("serve:\n%q", w.Body.String())
	}
	w = get("/llms.txt")
	if w.Body.String() != "# Site\n> hello\n" {
		t.Fatalf("llms serve: %q", w.Body.String())
	}
	if atomic.LoadInt32(hits) != before {
		t.Error("serve mode must not ask the upstream")
	}
	// HEAD and other paths
	rec := httptest.NewRecorder()
	r := wafReq("HEAD", "/robots.txt", nil, nil)
	h.ServeHTTP(rec, r)
	if rec.Body.Len() != 0 || rec.Code != 200 {
		t.Errorf("HEAD: %d %q", rec.Code, rec.Body.String())
	}
	if w := get("/robots.txt/other"); w.Body.String() != "upstream-ok" {
		t.Error("only the exact path is answered")
	}
	// the switched-off site serves nothing even in serve mode
	h.Parent.Option.AICrawlers = crawlerEngine(t, func(c *aicrawler.Config) {
		c.Sites = map[string]*aicrawler.SiteCfg{"waf.test": {Mode: aicrawler.SiteOff, Robots: aicrawler.RobotsCfg{Mode: aicrawler.RobotsServe}}}
	})
	if w := get("/robots.txt"); w.Body.String() != "upstream-ok" {
		t.Error("a site that is off must not serve robots.txt")
	}
}

// merge writer unit cases: upstream without a file, compressed answer, non-text answer, HEAD
func TestCrawlerFileWriterCases(t *testing.T) {
	run := func(mode string, head bool, handler http.HandlerFunc) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		cw := &crawlerFileWriter{ResponseWriter: rec, head: head, mode: mode, body: "\n# Generated\nUser-agent: GPTBot\nDisallow: /\n\n"}
		handler(cw, httptest.NewRequest("GET", "/robots.txt", nil))
		cw.finish()
		return rec
	}
	// upstream 404: the page is dropped and the generated rules are served alone (200)
	rec := run("merge", false, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "not found") || !strings.HasPrefix(rec.Body.String(), "# Generated") {
		t.Fatalf("404: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("content type %q", rec.Header().Get("Content-Type"))
	}
	// llms fallback with 404
	rec = run("fallback", false, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "User-agent: GPTBot") {
		t.Fatalf("fallback: %d %q", rec.Code, rec.Body.String())
	}
	// compressed answer: untouched
	rec = run("merge", false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("zipped"))
	})
	if rec.Body.String() != "zipped" {
		t.Fatalf("compressed: %q", rec.Body.String())
	}
	// non-text answer (an HTML page): untouched
	rec = run("merge", false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>"))
	})
	if rec.Body.String() != "<html>" {
		t.Fatalf("html: %q", rec.Body.String())
	}
	// server error: untouched, never replaced
	rec = run("merge", false, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) })
	if rec.Code != 500 {
		t.Fatalf("5xx: %d", rec.Code)
	}
	// text/plain: appended, Content-Length dropped
	rec = run("merge", false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", "5")
		w.Write([]byte("hello"))
	})
	if !strings.HasPrefix(rec.Body.String(), "hello\n# Generated") || rec.Header().Get("Content-Length") != "" {
		t.Fatalf("append: %q cl=%q", rec.Body.String(), rec.Header().Get("Content-Length"))
	}
	// HEAD: no body is written
	rec = run("merge", true, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %q", rec.Code, rec.Body.String())
	}
}
