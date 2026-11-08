package botrules

import (
	"errors"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/exploits"
)

func engineWith(t *testing.T, mod func(*Config)) *Engine {
	t.Helper()
	e := New(t.TempDir() + "/bots.json")
	c := DefaultConfig()
	c.Enabled = true
	if mod != nil {
		mod(&c)
	}
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	return e
}

func ip(s string) func() string { return func() string { return s } }

func TestDisabledCategoriesMatchNothing(t *testing.T) {
	e := engineWith(t, nil)
	for _, ua := range []string{"sqlmap/1.5", "GPTBot/1.0", "AhrefsBot", "python-requests/2.3", ""} {
		if d := e.Evaluate(ua, ip("1.1.1.1")); d.Action != "" {
			t.Errorf("%q matched with everything off: %+v", ua, d)
		}
	}
}

func TestCategories(t *testing.T) {
	e := engineWith(t, func(c *Config) {
		c.Categories["scanner"] = CategoryCfg{true, ActionBlock}
		c.Categories["ai_crawler"] = CategoryCfg{true, ActionChallenge}
		c.Categories["seo"] = CategoryCfg{true, ActionLog}
	})
	cases := []struct{ ua, action, reason string }{
		{"Mozilla/5.0 (compatible; sqlmap/1.5)", ActionBlock, "scanner"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)", ActionChallenge, "ai_crawler"},
		{"Mozilla/5.0 (compatible; AhrefsBot/7.0)", ActionLog, "seo"},
		{"SQLMAP", ActionBlock, "scanner"}, //case insensitive
		{"Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0", "", ""},
		{"python-requests/2.31", "", ""}, //category not enabled
	}
	for _, c := range cases {
		d := e.Evaluate(c.ua, ip("203.0.113.1"))
		if d.Action != c.action || d.Reason != c.reason {
			t.Errorf("%q: %+v want %s/%s", c.ua, d, c.action, c.reason)
		}
	}
}

// the AI crawler category is built from the exploit detector's list, not a copy
func TestAICategoryReusesExploitDetectorList(t *testing.T) {
	var ai []string
	for _, c := range Categories() {
		if c.ID == "ai_crawler" {
			ai = c.Items
		}
	}
	src := exploits.AIBotPatterns()
	if len(ai) == 0 || len(ai) != len(src) {
		t.Fatalf("category has %d items, exploit list %d", len(ai), len(src))
	}
	for i, p := range src {
		if "(?i)"+ai[i] != strings.ToLower(p) {
			t.Fatalf("item %d diverged: %q vs %q", i, ai[i], p)
		}
	}
}

func TestCustomRulesOrderAndRegex(t *testing.T) {
	e := engineWith(t, func(c *Config) {
		c.Custom = []Rule{
			{Name: "allow-monitor", Type: MatchSubstring, Pattern: "uptimerobot", Action: ActionLog},
			{Name: "evil", Type: MatchRegex, Pattern: `^evil-\d+$`, Action: ActionBlock},
			{Name: "ci", Type: MatchRegex, Pattern: `bad(bot)?`, CaseInsensitive: true, Action: ActionDrop},
		}
	})
	for ua, want := range map[string]string{
		"UptimeRobot/2.0": ActionLog, "evil-123": ActionBlock, "evil-123x": "", "BADBOT": ActionDrop, "bad": ActionDrop, "good": "",
	} {
		if d := e.Evaluate(ua, nil); d.Action != want {
			t.Errorf("%q: got %q want %q", ua, d.Action, want)
		}
	}
}

func TestCatastrophicAndInvalidRegexRejectedOrBounded(t *testing.T) {
	e := New("")
	c := DefaultConfig()
	c.Enabled = true
	c.Custom = []Rule{{Name: "x", Type: MatchRegex, Pattern: `(a+)+$`, Action: ActionBlock}}
	if err := e.SetConfig(c); err != nil {
		t.Fatalf("RE2 handles this pattern in linear time, it should be accepted: %v", err)
	}
	long := strings.Repeat("a", 100000) + "!"
	start := time.Now()
	for i := 0; i < 100; i++ {
		e.Evaluate(long, nil)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("evaluation not bounded: %v", time.Since(start))
	}
	for _, p := range []string{`(?=a)b`, `(a)\1`, `(`, strings.Repeat("a", 201), `a{1001}`, `(a{500}){500}`, ``} {
		c.Custom = []Rule{{Name: "bad", Type: MatchRegex, Pattern: p, Action: ActionBlock}}
		if err := e.SetConfig(c); err == nil {
			t.Errorf("pattern %q accepted", p)
		}
	}
	c.Custom = []Rule{{Name: "bad", Type: "glob", Pattern: "x", Action: ActionBlock}}
	if e.SetConfig(c) == nil {
		t.Error("unknown type accepted")
	}
	c.Custom = []Rule{{Name: "bad", Type: MatchSubstring, Pattern: "x", Action: "explode"}}
	if e.SetConfig(c) == nil {
		t.Error("unknown action accepted")
	}
	c.Custom = make([]Rule, maxCustom+1)
	for i := range c.Custom {
		c.Custom[i] = Rule{Pattern: "x", Action: ActionLog}
	}
	if e.SetConfig(c) == nil {
		t.Error("rule count unbounded")
	}
	// a rejected update keeps the previous (working) configuration
	c = DefaultConfig()
	c.Enabled = true
	c.Custom = []Rule{{Name: "keep", Pattern: "keepme", Action: ActionBlock}}
	e.SetConfig(c)
	c.Custom = []Rule{{Name: "bad", Type: MatchRegex, Pattern: `(`, Action: ActionBlock}}
	e.SetConfig(c)
	if e.Evaluate("keepme", nil).Action != ActionBlock {
		t.Error("failed update dropped the active rules")
	}
}

func TestUserAgentTruncatedBeforeMatching(t *testing.T) {
	e := engineWith(t, func(c *Config) { c.Custom = []Rule{{Name: "tail", Pattern: "needle", Action: ActionBlock}} })
	ua := strings.Repeat("x", 600) + "needle"
	if e.Evaluate(ua, nil).Action != "" {
		t.Fatal("matching must only look at the first 512 bytes (bounded work)")
	}
	if e.Evaluate(strings.Repeat("x", 100)+"needle", nil).Action != ActionBlock {
		t.Fatal("normal UA not matched")
	}
}

func TestEmptyUserAgent(t *testing.T) {
	e := engineWith(t, nil)
	if e.Evaluate("", nil).Action != "" {
		t.Fatal("empty UA must be allowed by default")
	}
	e = engineWith(t, func(c *Config) { c.BlockEmptyUA = ActionBlock })
	if d := e.Evaluate("", nil); d.Action != ActionBlock || d.Reason != "empty-ua" {
		t.Fatalf("%+v", d)
	}
}

func TestGoodBotVerification(t *testing.T) {
	e := engineWith(t, func(c *Config) {
		c.Categories["seo"] = CategoryCfg{true, ActionBlock}
		c.Categories["bad_bot"] = CategoryCfg{true, ActionBlock}
		c.Custom = []Rule{{Name: "all-bots", Pattern: "bot", Action: ActionBlock}}
		c.AllowedBots = []string{"Googlebot", "Bingbot"}
		c.VerifyBots = true
	})
	lookups := 0
	e.LookupAddr = func(a string) ([]string, error) {
		lookups++
		switch a {
		case "66.249.66.1":
			return []string{"crawl-66-249-66-1.googlebot.com."}, nil
		case "203.0.113.5": //attacker controls the PTR: points at a google name, but forward lookup does not confirm
			return []string{"crawl-1.googlebot.com."}, nil
		case "203.0.113.6": //PTR in an attacker zone that merely contains the string
			return []string{"googlebot.com.evil.example."}, nil
		}
		return nil, errors.New("nxdomain")
	}
	e.LookupHost = func(h string) ([]string, error) {
		if h == "crawl-66-249-66-1.googlebot.com" {
			return []string{"66.249.66.1"}, nil
		}
		if h == "crawl-1.googlebot.com" {
			return []string{"198.51.100.200"}, nil
		}
		return nil, errors.New("nxdomain")
	}
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	if d := e.Evaluate(ua, ip("66.249.66.1")); d.Action != "" {
		t.Fatalf("verified Googlebot blocked: %+v", d)
	}
	for _, spoof := range []string{"203.0.113.5", "203.0.113.6", "203.0.113.7", ""} {
		d := e.Evaluate(ua, ip(spoof))
		if d.Action != ActionBlock || d.Reason != "fake-bot" {
			t.Errorf("spoofed Googlebot from %q not rejected: %+v", spoof, d)
		}
	}
	// results are cached (a flood of fake bots does not become a DNS flood)
	before := lookups
	for i := 0; i < 50; i++ {
		e.Evaluate(ua, ip("203.0.113.5"))
		e.Evaluate(ua, ip("66.249.66.1"))
	}
	if lookups != before {
		t.Fatalf("verification not cached: %d extra lookups", lookups-before)
	}
	// a bot that is not on the allow list is judged by the normal rules
	if d := e.Evaluate("Mozilla/5.0 (compatible; Baiduspider/2.0; OtherBot)", ip("66.249.66.1")); d.Action != ActionBlock {
		t.Fatalf("non-allowed bot passed: %+v", d)
	}
}

func TestGoodBotWithoutVerificationIsTrustedByName(t *testing.T) {
	e := engineWith(t, func(c *Config) {
		c.Custom = []Rule{{Name: "all-bots", Pattern: "bot", Action: ActionBlock}}
		c.AllowedBots = []string{"Googlebot"}
	})
	if e.Evaluate("Googlebot/2.1", nil).Action != "" {
		t.Fatal("allow-listed bot (verification off) must pass")
	}
}

func TestVerificationConcurrencyIsBounded(t *testing.T) {
	e := engineWith(t, func(c *Config) { c.AllowedBots = []string{"Googlebot"}; c.VerifyBots = true })
	block := make(chan struct{})
	e.LookupAddr = func(string) ([]string, error) { <-block; return nil, errors.New("x") }
	done := make(chan Decision, 64)
	for i := 0; i < 40; i++ {
		go func(i int) { done <- e.Evaluate("Googlebot", ip("203.0.113."+string(rune('0'+i%10)))) }(i)
	}
	// 16 lookups can be in flight, the rest must be rejected immediately instead of piling up
	rejected := 0
	timeout := time.After(2 * time.Second)
	for rejected < 24 {
		select {
		case d := <-done:
			if d.Reason == "fake-bot" {
				rejected++
			}
		case <-timeout:
			t.Fatalf("only %d lookups were shed", rejected)
		}
	}
	close(block)
}

func TestConfigRoundTripAndValidation(t *testing.T) {
	dir := t.TempDir() + "/b.json"
	e := New(dir)
	c := DefaultConfig()
	c.Enabled = true
	c.Categories["scanner"] = CategoryCfg{true, ActionBlock}
	c.AllowedBots = []string{"Bingbot"}
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	e2 := New(dir)
	if err := e2.Load(); err != nil || !e2.Enabled() || e2.Evaluate("nikto", nil).Action != ActionBlock {
		t.Fatalf("config not restored: %v", err)
	}
	for _, bad := range []func(*Config){
		func(c *Config) { c.Categories["nope"] = CategoryCfg{true, ActionBlock} },
		func(c *Config) { c.Categories["seo"] = CategoryCfg{true, "x"} },
		func(c *Config) { c.AllowedBots = []string{"Nobody"} },
		func(c *Config) { c.FakeBotAction = "x" },
		func(c *Config) { c.BlockEmptyUA = "x" },
	} {
		cc := DefaultConfig()
		bad(&cc)
		if cc.Validate() == nil {
			t.Error("invalid config accepted")
		}
	}
	// nil engine is safe
	var nilEng *Engine
	if nilEng.Enabled() {
		t.Error("nil engine enabled")
	}
}
