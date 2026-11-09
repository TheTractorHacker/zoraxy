package dynamicproxy

import (
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/visitors"
)

// waitBlocked waits until the log holds n entries (the router records from a goroutine)
func waitBlocked(t *testing.T, bl *blocklog.Log, n int) []blocklog.Entry {
	t.Helper()
	var items []blocklog.Entry
	for i := 0; i < 400; i++ {
		items = bl.List(blocklog.Filter{}, 0, 500).Items
		if len(items) >= n {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(items) != n {
		t.Fatalf("blocked log has %d entries, want %d: %+v", len(items), n, items)
	}
	return items
}

func findBlocked(items []blocklog.Entry, ip string) *blocklog.Entry {
	for i := range items {
		if items[i].IP == ip {
			return &items[i]
		}
	}
	return nil
}

// Real traffic through the non-TLS chain: every kind of rejection ends up in the log with its reason.
func TestBlockLogReasonsFromRealTraffic(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl

	// blacklist
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.9", "test")
	if w := serveNonTLS(router, sep, "http://app.example.com/secret/page?token=abc", "198.51.100.9:1000"); w.Code != 403 {
		t.Fatalf("blacklist: %d", w.Code)
	}
	// rate limit: burst of one request per second, the second one is rejected
	sep.RequireRateLimit, sep.RateLimit, sep.RateLimitBurst = true, 1, 1
	serveNonTLS(router, sep, "http://app.example.com/a", "198.51.100.20:1000")
	if w := serveNonTLS(router, sep, "http://app.example.com/a", "198.51.100.20:1000"); w.Code != 429 {
		t.Fatalf("rate limit: %d", w.Code)
	}
	sep.RequireRateLimit = false
	// bot rule
	e := botrules.New("")
	c := botrules.DefaultConfig()
	c.Enabled = true
	c.Categories["scanner"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionBlock}
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	router.Option.Bots = e
	if w := serveUA(router, sep, "sqlmap/1.5"); w.Code != 403 {
		t.Fatalf("bot: %d", w.Code)
	}
	// exploit detector
	sep.BlockCommonExploits = true
	sep.MitigationAction = 1
	sep.InitializeExploitDetector()
	if w := serveNonTLS(router, sep, "http://app.example.com/?q=union+all+select+1", "198.51.100.30:1000"); w.Code != 403 {
		t.Fatalf("exploit: %d", w.Code)
	}
	// header rule
	sep.HeaderRules = []*HeaderRule{{Name: "X-Edge-Key", Values: []string{"k"}}}
	sep.initHeaderRules()
	if w := serveNonTLS(router, sep, "http://app.example.com/h", "198.51.100.40:1000"); w.Code != 403 {
		t.Fatalf("header rule: %d", w.Code)
	}
	// a clean request is not logged
	sep.HeaderRules = nil
	sep.initHeaderRules()
	if w := serveNonTLS(router, sep, "http://app.example.com/ok", "198.51.100.50:1000"); w.Code != 299 {
		t.Fatalf("clean: %d", w.Code)
	}

	items := waitBlocked(t, bl, 5)
	want := map[string]string{ // the bot request comes from serveWithHeaders' fixed address 198.51.100.1
		"198.51.100.9":  blocklog.ReasonBlacklist,
		"198.51.100.20": blocklog.ReasonRateLimit,
		"198.51.100.30": blocklog.ReasonExploit,
		"198.51.100.40": blocklog.ReasonHeaderRule,
		"198.51.100.1":  blocklog.ReasonBot,
	}
	for ip, reason := range want {
		got := findBlocked(items, ip)
		if got == nil || got.Reason != reason {
			t.Errorf("%s: got %+v, want reason %s", ip, got, reason)
		}
	}
	bl9 := findBlocked(items, "198.51.100.9")
	if bl9.Status != 403 || bl9.Host != "app.example.com" || bl9.Method != "GET" || bl9.Rule != "app.example.com" {
		t.Errorf("blacklist entry misses the request facts: %+v", bl9)
	}
	if strings.Contains(bl9.Path, "token") || bl9.Path != "/secret/page" {
		t.Errorf("query string must not be kept by default: %q", bl9.Path)
	}
	if rl := findBlocked(items, "198.51.100.20"); rl.Status != 429 || !strings.Contains(rl.Detail, "1 req/s") {
		t.Errorf("rate limit entry: %+v", rl)
	}
	if b := findBlocked(items, "198.51.100.1"); b == nil || b.Detail == "" {
		t.Errorf("bot entry without rule name: %+v", b)
	}
	if ex := findBlocked(items, "198.51.100.30"); ex.Detail != "common exploit pattern" {
		t.Errorf("exploit entry: %+v", ex)
	}
	// the counters on the Status page and the log agree on what a block is
	for _, ft := range []string{"blacklist-dropped", "header-rule-1-x-edge-key", "bot-scanner", "auto-ban", "auth-basic", "country-challenge"} {
		if !blocklogAgrees(ft) {
			t.Errorf("%s is not counted as blocked", ft)
		}
	}
	if blocklogAgrees("bot-scanner-logonly") || blocklogAgrees("host-http") {
		t.Error("log-only bot hits and normal traffic must not count as blocked")
	}
}

func blocklogAgrees(ft string) bool { return blocklog.IsBlocked(ft) }

func TestBlockLogKeepQueryFollowsVisitorSetting(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	s := visitors.DefaultSettings()
	s.KeepQuery = true
	router.Option.VisitorTracker = visitors.New("", s)
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.9", "test")
	serveNonTLS(router, sep, "http://app.example.com/p?a=1", "198.51.100.9:1000")
	items := waitBlocked(t, bl, 1)
	if items[0].Path != "/p?a=1" {
		t.Errorf("KeepQuery on: %q", items[0].Path)
	}
}

// Privacy and exclusion settings that Visitors honours apply to the blocked log too
func TestBlockLogHonoursStatisticsFilters(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	var excludeBlocked atomic.Bool
	bl.SetExcludeBlocked(excludeBlocked.Load)
	bl.SetExcluder(func(ip string) bool { return ip == "198.51.100.2" })
	rule.BlacklistEnabled = true
	for _, ip := range []string{"198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5", "198.51.100.6"} {
		rule.AddIPToBlackList(ip, "t")
	}
	hit := func(ip string) { serveNonTLS(router, sep, "http://app.example.com/", ip+":1") }
	hit("198.51.100.2") // excluded network
	hit("198.51.100.3") // recorded
	sep.DisableStatisticCollection = true
	hit("198.51.100.4") // rule opted out of statistics
	sep.DisableStatisticCollection = false
	bl.SetEnabled(false)
	hit("198.51.100.5") // log switched off
	bl.SetEnabled(true)
	waitBlocked(t, bl, 1)
	time.Sleep(50 * time.Millisecond) // the goroutines of the skipped requests never record, give a wrong one time to show
	excludeBlocked.Store(true)
	hit("198.51.100.6") // "exclude blocked requests"
	time.Sleep(100 * time.Millisecond)
	items := bl.List(blocklog.Filter{}, 0, 50).Items
	if len(items) != 1 || items[0].IP != "198.51.100.3" {
		t.Fatalf("only the unfiltered request may be logged: %+v", items)
	}
}

func TestBlockLogAutoBanAndAuth(t *testing.T) {
	router, sep, m := newAbuseRouter(t, 404, nil)
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	for i := 0; i < 3; i++ {
		serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.5:1000")
	}
	if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.5:1000"); w.Code != 403 {
		t.Fatalf("banned client got %d", w.Code)
	}
	items := waitBlocked(t, bl, 1)
	if items[0].Reason != blocklog.ReasonAutoBan || items[0].Status != 403 || items[0].Detail == "" {
		t.Errorf("auto-ban entry: %+v", items[0])
	}
	_ = m

	// failed basic authentication is logged, the browser's first (credential-less) request is not
	router2, sep2, _ := newNonTLSTestRouter(t)
	bl2 := blocklog.New("", 100, blocklog.DefaultSettings())
	router2.Option.BlockLog = bl2
	sep2.AuthenticationProvider = &AuthenticationProvider{AuthMethod: AuthMethodBasic}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://app.example.com/admin", nil)
	r.RemoteAddr = "198.51.100.7:1"
	router2.handleNonTLSRequest(w, r, sep2)
	if w.Code != 401 {
		t.Fatalf("no credentials: %d", w.Code)
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "http://app.example.com/admin", nil)
	r.RemoteAddr = "198.51.100.8:1"
	r.SetBasicAuth("root", "wrong")
	router2.handleNonTLSRequest(w, r, sep2)
	if w.Code != 401 {
		t.Fatalf("wrong credentials: %d", w.Code)
	}
	items = waitBlocked(t, bl2, 1)
	if items[0].IP != "198.51.100.8" || items[0].Reason != blocklog.ReasonAuth || items[0].Status != 401 {
		t.Errorf("auth entry: %+v", items[0])
	}
}

// A WAF attack is logged with the id and message of the rule that matched
func TestBlockLogWAFRuleDetail(t *testing.T) {
	h, hits, _ := newWAFTestProxy(t, &waf.Config{Mode: waf.ModeBlock})
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	h.Parent.Option.BlockLog = bl
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("GET", "/item?id=1%27%20OR%20%271%27%3D%271", nil, nil))
	if w.Code != 403 || *hits != 0 {
		t.Fatalf("attack was not blocked: %d", w.Code)
	}
	// a harmless request is not logged
	h.ServeHTTP(httptest.NewRecorder(), wafReq("GET", "/item?id=5", nil, nil))
	items := waitBlocked(t, bl, 1)
	e := items[0]
	if e.Reason != blocklog.ReasonWAF || e.Status != 403 || e.IP != "198.51.100.9" || e.Host != "waf.test" {
		t.Fatalf("waf entry: %+v", e)
	}
	if !strings.Contains(e.Detail, "tx ") || len(strings.Fields(e.Detail)) < 3 {
		t.Errorf("waf detail should name the rule and the transaction: %q", e.Detail)
	}
	if strings.Contains(e.Path, "OR") || strings.Contains(e.Path, "?") {
		t.Errorf("the attack payload (query) must not be stored: %q", e.Path)
	}
}
