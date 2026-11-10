package aicrawler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ip(s string) func() string { return func() string { return s } }

// ---- registry and UA matching ----

func TestRegistryIntegrity(t *testing.T) {
	ids, uas, tokens := map[string]bool{}, map[string]bool{}, map[string]bool{}
	groups := map[string]bool{}
	for _, g := range Groups() {
		groups[g.ID] = true
	}
	srcs := map[string]bool{}
	for _, s := range Sources() {
		if !strings.HasPrefix(s.URL, "https://") {
			t.Errorf("source %s is not https", s.ID)
		}
		srcs[s.ID] = true
	}
	for _, e := range Registry() {
		if e.ID == "" || e.Name == "" || e.Operator == "" || e.Purpose == "" || e.Token == "" {
			t.Errorf("incomplete entry %+v", e)
		}
		if ids[e.ID] {
			t.Errorf("duplicate id %s", e.ID)
		}
		ids[e.ID] = true
		if !groups[e.Group] {
			t.Errorf("%s: unknown group %q", e.ID, e.Group)
		}
		if e.UA != strings.ToLower(e.UA) {
			t.Errorf("%s: UA substring must be lowercase", e.ID)
		}
		if e.TokenOnly == (e.UA != "") {
			t.Errorf("%s: a token-only entry has no UA substring and every other entry has one", e.ID)
		}
		if e.TokenOnly && e.Verify.Verifiable() {
			t.Errorf("%s: a token cannot be verified", e.ID)
		}
		if e.UA != "" {
			if uas[e.UA] {
				t.Errorf("duplicate UA %s", e.UA)
			}
			uas[e.UA] = true
		}
		if tokens[strings.ToLower(e.Token)] {
			t.Errorf("duplicate token %s", e.Token)
		}
		tokens[strings.ToLower(e.Token)] = true
		for _, s := range e.Verify.RangeSources {
			if !srcs[s] {
				t.Errorf("%s references unknown source %s", e.ID, s)
			}
		}
	}
	// no address range is shipped: only the operators' lists, fetched on request
	if len(NewRangeStore("").Status()) != len(Sources()) {
		t.Error("status must list every source")
	}
	for _, s := range NewRangeStore("").Status() {
		if s.Loaded {
			t.Errorf("source %s is loaded in a fresh store", s.ID)
		}
	}
}

func TestMatchUserAgents(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "gptbot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot", "oai-searchbot"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", "chatgpt-user"},
		{"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "claudebot"},
		{"Claude-SearchBot/1.0", "claude-searchbot"},
		{"claude-user", "claude-user"},
		{"anthropic-ai", "anthropic-ai"},
		{"Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)", "perplexitybot"},
		{"Mozilla/5.0 (compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)", "perplexity-user"},
		{"meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", "meta-externalagent"},
		{"Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)", "bytespider"},
		{"CCBot/2.0 (https://commoncrawl.org/faq/)", "ccbot"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.2.5 (KHTML, like Gecko) Version/8.0.2 Safari/600.2.5 (Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)", "amazonbot"},
		{"CLAUDEBOT", "claudebot"}, // case-insensitive
		{"Mozilla/5.0 (compatible; Diffbot/0.1; +http://www.diffbot.com)", "diffbot"},
	}
	for _, c := range cases {
		e, ok := Match(c.ua)
		if !ok || e.ID != c.want {
			t.Errorf("Match(%q) = %q ok=%v, want %q", c.ua, e.ID, ok, c.want)
		}
	}
	// clients that are not AI crawlers
	for _, ua := range []string{
		"", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", // a search engine, not an AI crawler
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", // link preview
		"Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)", // Applebot, not Applebot-Extended
		"curl/8.4.0", "Slackbot-LinkExpanding 1.0",
	} {
		if e, ok := Match(ua); ok {
			t.Errorf("Match(%q) = %s, must not match", ua, e.ID)
		}
	}
	// token-only entries never match a request
	if _, ok := Match("Google-Extended"); ok {
		t.Error("Google-Extended is a robots.txt token, not a User-Agent")
	}
	if _, ok := Match("Applebot-Extended"); ok {
		t.Error("Applebot-Extended is a robots.txt token, not a User-Agent")
	}
	// very long headers are cut, a bot name hidden beyond the cut is not matched (documented)
	if _, ok := Match(strings.Repeat("a", 600) + "GPTBot"); ok {
		t.Error("a User-Agent longer than the cap must be truncated before matching")
	}
}

// ---- configuration ----

func enabledCfg(mod func(*Config)) Config {
	c := DefaultConfig()
	c.Enabled = true
	if mod != nil {
		mod(&c)
	}
	return c
}

func newEngine(t *testing.T, c Config) *Engine {
	t.Helper()
	e := New("", "")
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDefaultIsOffAndChangesNothing(t *testing.T) {
	e := New("", "")
	if e.Enabled() {
		t.Fatal("the policy must be off by default")
	}
	if d := e.Evaluate("a.example", []string{"GPTBot/1.0"}, ip("198.51.100.1")); d.Outcome != OutNone || d.Matched {
		t.Fatalf("disabled engine decided something: %+v", d)
	}
	if fm := e.FileFor("a.example", "/robots.txt"); fm.Mode != "off" {
		t.Fatal("a disabled policy must not serve robots.txt")
	}
	var nilEng *Engine
	if d := nilEng.Evaluate("a", []string{"GPTBot"}, nil); d.Matched || nilEng.Enabled() {
		t.Fatal("nil engine must be inert")
	}
	// enabled, but no policy for the crawler: also nothing
	e = newEngine(t, enabledCfg(nil))
	d := e.Evaluate("a.example", []string{"GPTBot/1.0"}, ip("198.51.100.1"))
	if !d.Matched || d.Outcome != OutNone || d.Action != "" {
		t.Fatalf("enabled engine without a policy must leave the request alone: %+v", d)
	}
}

func TestOldAndPartialConfigsLoad(t *testing.T) {
	dir := t.TempDir()
	// no file at all
	e := New(filepath.Join(dir, "none.json"), "")
	if err := e.Load(); err != nil || e.Enabled() {
		t.Fatalf("missing file: err=%v enabled=%v", err, e.Enabled())
	}
	// a file from the future / with unknown fields and only a few known ones
	p := filepath.Join(dir, "old.json")
	os.WriteFile(p, []byte(`{"Enabled":true,"Global":{"Groups":{"training":"block"}},"SomethingNew":{"x":1}}`), 0o600)
	e = New(p, "")
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	c := e.Config()
	if !c.Enabled || c.Global.SpoofAction != ActBlock || c.Global.RateLimitPerMinute != DefaultRateLimit || c.Global.BypassWAF || c.Global.VerifiedOnly {
		t.Fatalf("defaults not applied to missing fields: %+v", c)
	}
	if d := e.Evaluate("x", []string{"CCBot/2.0"}, nil); d.Outcome != OutBlock {
		t.Fatalf("group policy of the old file not applied: %+v", d)
	}
	// a broken file is an error (the glue then starts disabled)
	os.WriteFile(p, []byte(`{"Enabled":`), 0o600)
	if err := New(p, "").Load(); err == nil {
		t.Fatal("broken JSON must be reported")
	}
	// an invalid value in the file is refused rather than half applied
	os.WriteFile(p, []byte(`{"Enabled":true,"Global":{"Crawlers":{"gptbot":"explode"}}}`), 0o600)
	if err := New(p, "").Load(); err == nil {
		t.Fatal("invalid action must be reported")
	}
}

// A crawler or group id from another version, or a corrupt range cache, must not switch the whole policy off
func TestLoadToleratesUnknownIDsAndCorruptRangeCache(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.json")
	rp := filepath.Join(dir, "r.json")
	os.WriteFile(p, []byte(`{"Enabled":true,"Global":{"Groups":{"training":"block","oldgroup":"block"},"Crawlers":{"nosuchbot":"block","gptbot":"allow"}},"Sites":{"s":{"Mode":"custom","Custom":{"Crawlers":{"gone":"block"}}}}}`), 0o600)
	os.WriteFile(rp, []byte(`{"sets":`), 0o600)
	e := New(p, rp)
	e.Load() // the range cache error may be reported, the policy must be live anyway
	if !e.Enabled() {
		t.Fatal("policy disabled by unknown ids or a corrupt range cache")
	}
	if d := e.Evaluate("x", []string{"CCBot/2.0"}, nil); d.Outcome != OutBlock {
		t.Fatalf("known entries of the file must still apply: %+v", d)
	}
	if d := e.Evaluate("x", []string{"GPTBot/1.0"}, nil); d.Outcome != OutAllow {
		t.Fatalf("crawler rule lost: %+v", d)
	}
}

func TestEvaluateMostRestrictiveOfSeveralClaims(t *testing.T) {
	e := New("", "")
	c := enabledCfg(func(c *Config) {
		c.Global.Crawlers = map[string]string{"chatgpt-user": ActAllow, "bytespider": ActBlock}
	})
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate("x", []string{"Bytespider ChatGPT-User"}, nil); d.Outcome != OutBlock {
		t.Fatalf("a longer allowed token hid a blocked crawler: %+v", d)
	}
	if d := e.Evaluate("x", []string{"ChatGPT-User", "Bytespider"}, nil); d.Outcome != OutBlock {
		t.Fatalf("a second header hid a blocked crawler: %+v", d)
	}
	// a crawler without a policy next to an allowed one: no exemption
	if d := e.Evaluate("x", []string{"ClaudeBot ChatGPT-User"}, nil); d.Outcome == OutAllow {
		t.Fatalf("allowed token exempted a crawler without a policy: %+v", d)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "aicrawler.json")
	e := New(p, filepath.Join(dir, "r.json"))
	c := enabledCfg(func(c *Config) {
		c.Global.Groups = map[string]string{GroupTraining: ActBlock}
		c.Robots.Mode = RobotsMerge
		c.Sites = map[string]*SiteCfg{"a.example": {Mode: SiteCustom, Custom: SiteSettings{Crawlers: map[string]string{"gptbot": ActAllow}}, LLMS: LLMSCfg{Mode: LLMSServe, Text: "# hi"}}}
	})
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config file missing or too open: %v %v", st, err)
	}
	e2 := New(p, filepath.Join(dir, "r.json"))
	if err := e2.Load(); err != nil {
		t.Fatal(err)
	}
	a, b := e.Config(), e2.Config()
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("round trip differs:\n%s\n%s", ja, jb)
	}
}

func TestValidate(t *testing.T) {
	bad := map[string]func(*Config){
		"unknown group":   func(c *Config) { c.Global.Groups = map[string]string{"nope": ActBlock} },
		"unknown crawler": func(c *Config) { c.Global.Crawlers = map[string]string{"nope": ActBlock} },
		"bad action":      func(c *Config) { c.Global.Crawlers = map[string]string{"gptbot": "explode"} },
		"token challenge": func(c *Config) { c.Global.Crawlers = map[string]string{"google-extended": ActChallenge} },
		"bad spoof":       func(c *Config) { c.Global.SpoofAction = ActAllow },
		"bad rate":        func(c *Config) { c.Global.RateLimitPerMinute = -1 },
		"huge rate":       func(c *Config) { c.Global.RateLimitPerMinute = 10000000 },
		"bad robots":      func(c *Config) { c.Robots.Mode = "yes" },
		"empty site":      func(c *Config) { c.Sites = map[string]*SiteCfg{"": {}} },
		"nil site":        func(c *Config) { c.Sites = map[string]*SiteCfg{"a": nil} },
		"bad site mode":   func(c *Config) { c.Sites = map[string]*SiteCfg{"a": {Mode: "x"}} },
		"bad llms mode":   func(c *Config) { c.Sites = map[string]*SiteCfg{"a": {LLMS: LLMSCfg{Mode: "x"}}} },
		"llms too long": func(c *Config) {
			c.Sites = map[string]*SiteCfg{"a": {LLMS: LLMSCfg{Mode: LLMSServe, Text: strings.Repeat("a", maxLLMSText+1)}}}
		},
		"llms nul":             func(c *Config) { c.Sites = map[string]*SiteCfg{"a": {LLMS: LLMSCfg{Mode: LLMSServe, Text: "a\x00b"}}} },
		"site spoof":           func(c *Config) { c.Sites = map[string]*SiteCfg{"a": {Custom: SiteSettings{SpoofAction: ActRateLimit}}} },
		"site newline in key":  func(c *Config) { c.Sites = map[string]*SiteCfg{"a\nb": {}} },
		"site robots bad mode": func(c *Config) { c.Sites = map[string]*SiteCfg{"a": {Robots: RobotsCfg{Mode: "zzz"}}} },
	}
	for name, mod := range bad {
		c := DefaultConfig()
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := New("", "").SetConfig(c); err == nil {
			t.Errorf("%s: SetConfig accepted", name)
		}
	}
	good := enabledCfg(func(c *Config) {
		c.Global.Groups = map[string]string{GroupAgent: ActAllow, GroupSearch: ""}
		c.Global.Crawlers = map[string]string{"google-extended": ActBlock}
	})
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

// ---- policy order ----

func TestPolicyOrderCrawlerBeatsGroupBeatsDefault(t *testing.T) {
	e := newEngine(t, enabledCfg(func(c *Config) {
		c.Global.Groups = map[string]string{GroupTraining: ActBlock, GroupAgent: ActAllow}
		c.Global.Crawlers = map[string]string{"ccbot": ActLog}
	}))
	cases := []struct {
		ua, want string
	}{
		{"GPTBot/1.0", OutBlock},         // group training
		{"CCBot/2.0", OutLogOnly},        // crawler entry beats the group
		{"ChatGPT-User/1.0", OutAllow},   // group agent
		{"PerplexityBot/1.0", OutNone},   // group search: no policy
		{"Mozilla/5.0 Firefox", OutNone}, // not a crawler
	}
	for _, c := range cases {
		if d := e.Evaluate("s", []string{c.ua}, ip("198.51.100.1")); d.Outcome != c.want {
			t.Errorf("%s: %q, want %q", c.ua, d.Outcome, c.want)
		}
	}
	// the first User-Agent header value that is a crawler decides (a duplicate header cannot hide it)
	if d := e.Evaluate("s", []string{"Mozilla/5.0", "GPTBot/1.0"}, nil); d.Outcome != OutBlock {
		t.Fatalf("second header value ignored: %+v", d)
	}
}

func TestSiteOverrides(t *testing.T) {
	e := newEngine(t, enabledCfg(func(c *Config) {
		c.Global.Groups = map[string]string{GroupTraining: ActBlock}
		c.Sites = map[string]*SiteCfg{
			"open.example":    {Mode: SiteCustom, Custom: SiteSettings{Crawlers: map[string]string{"gptbot": ActAllow}}},
			"off.example":     {Mode: SiteOff},
			"inherit.example": {Mode: SiteInherit},
			"group.example":   {Mode: SiteCustom, Custom: SiteSettings{Groups: map[string]string{GroupTraining: ActAllow}}},
		}
	}))
	check := func(site, ua, want string) {
		t.Helper()
		if d := e.Evaluate(site, []string{ua}, nil); d.Outcome != want {
			t.Errorf("%s %s: %q, want %q", site, ua, d.Outcome, want)
		}
	}
	check("any.example", "GPTBot", OutBlock)     // global
	check("inherit.example", "GPTBot", OutBlock) // explicit inherit
	check("open.example", "GPTBot", OutAllow)    // site crawler entry
	check("open.example", "CCBot", OutBlock)     // the rest still inherits
	check("off.example", "GPTBot", OutNone)      // switched off for the site
	check("group.example", "CCBot", OutAllow)    // site group entry beats the global group
	// switching the master switch off wins over everything
	c := e.Config()
	c.Enabled = false
	e.SetConfig(c)
	check("open.example", "GPTBot", OutNone)
}

// ---- verification and spoofing ----

func rangeEngine(t *testing.T, mod func(*Config)) *Engine {
	t.Helper()
	e := newEngine(t, enabledCfg(func(c *Config) {
		c.Global.Groups = map[string]string{GroupTraining: ActAllow}
		c.Global.VerifiedOnly = true
		if mod != nil {
			mod(c)
		}
	}))
	// fixtures, documentation ranges (RFC 5737 / 3849): not real crawler addresses
	if err := e.Ranges.SetPrefixes("openai-gptbot", []string{"192.0.2.0/24", "2001:db8:1::/48", "203.0.113.7"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestVerifiedOnlyAndSpoofing(t *testing.T) {
	e := rangeEngine(t, nil)
	for _, c := range []struct {
		ip  string
		out string
		spf bool
		ver string
	}{
		{"192.0.2.55", OutAllow, false, VerifyVerified},
		{"2001:db8:1::9", OutAllow, false, VerifyVerified},
		{"203.0.113.7", OutAllow, false, VerifyVerified},
		{"::ffff:192.0.2.55", OutAllow, false, VerifyVerified}, // IPv4-mapped form of an address inside the range
		{"198.51.100.1", OutBlock, true, VerifyFailed},         // claims GPTBot from elsewhere: spoofed
		{"", OutBlock, true, VerifyFailed},                     // unknown address: not verified
		{"not-an-ip", OutBlock, true, VerifyFailed},
	} {
		d := e.Evaluate("s", []string{"GPTBot/1.0"}, ip(c.ip))
		if d.Outcome != c.out || d.Spoofed != c.spf || d.Verification != c.ver {
			t.Errorf("ip %q: %+v, want out=%s spoofed=%v ver=%s", c.ip, d, c.out, c.spf, c.ver)
		}
	}
	if !strings.Contains(e.Evaluate("s", []string{"GPTBot"}, ip("198.51.100.1")).Detail(), "GPTBot") {
		t.Error("the decision detail must name the crawler")
	}
}

func TestVerifiedOnlyFailsClosedWhenUnverifiable(t *testing.T) {
	e := rangeEngine(t, nil)
	// ClaudeBot: Anthropic publishes no method -> cannot be verified -> not allowed under "verified only"
	d := e.Evaluate("s", []string{"ClaudeBot/1.0"}, ip("192.0.2.55"))
	if d.Outcome != OutBlock || !d.Spoofed || d.Verification != VerifyUnverifiable {
		t.Fatalf("unverifiable crawler must not be allowed under verified-only: %+v", d)
	}
	// documented range list but the admin never refreshed it: also unverifiable, also closed
	c := e.Config()
	c.Global.Groups = map[string]string{GroupSearch: ActAllow}
	e.SetConfig(c)
	d = e.Evaluate("s", []string{"PerplexityBot/1.0"}, ip("192.0.2.55"))
	if d.Outcome != OutBlock || d.Verification != VerifyUnverifiable {
		t.Fatalf("not refreshed ranges: %+v", d)
	}
	// without the option the User-Agent alone decides (documented as spoofable)
	c.Global.VerifiedOnly = false
	e.SetConfig(c)
	if d := e.Evaluate("s", []string{"PerplexityBot/1.0"}, ip("198.51.100.1")); d.Outcome != OutAllow || d.Spoofed {
		t.Fatalf("verified-only off: %+v", d)
	}
}

func TestSpoofActions(t *testing.T) {
	for act, want := range map[string]string{ActBlock: OutBlock, ActChallenge: OutChallenge, ActLog: OutLogOnly, "": OutBlock} {
		e := rangeEngine(t, func(c *Config) { c.Global.SpoofAction = act })
		d := e.Evaluate("s", []string{"GPTBot"}, ip("198.51.100.1"))
		if d.Outcome != want || !d.Spoofed {
			t.Errorf("spoof action %q: %+v, want %s", act, d, want)
		}
	}
}

func TestVerifiedOnlyDoesNotWeakenBlock(t *testing.T) {
	e := rangeEngine(t, func(c *Config) { c.Global.Groups = map[string]string{GroupTraining: ActBlock} })
	// a blocked crawler is blocked whether or not it is genuine
	for _, addr := range []string{"192.0.2.55", "198.51.100.1"} {
		if d := e.Evaluate("s", []string{"GPTBot"}, ip(addr)); d.Outcome != OutBlock {
			t.Errorf("%s: %+v", addr, d)
		}
	}
}

func TestReverseDNSFixtures(t *testing.T) {
	e := rangeEngine(t, func(c *Config) { c.Global.Groups = map[string]string{GroupTraining: ActAllow} })
	calls := 0
	e.LookupAddr = func(a string) ([]string, error) {
		calls++
		switch a {
		case "198.51.100.20":
			return []string{"crawl-1.amazonbot.amazon."}, nil
		case "198.51.100.21":
			return []string{"crawl-1.amazonbot.amazon."}, nil // forward lookup does not confirm
		case "198.51.100.22":
			return []string{"evil.example.com."}, nil
		}
		return nil, os.ErrNotExist
	}
	e.LookupHost = func(h string) ([]string, error) {
		if h == "crawl-1.amazonbot.amazon" {
			return []string{"198.51.100.20"}, nil
		}
		return nil, os.ErrNotExist
	}
	if d := e.Evaluate("s", []string{"Amazonbot/0.1"}, ip("198.51.100.20")); d.Outcome != OutAllow || d.Verification != VerifyVerified {
		t.Fatalf("forward-confirmed name must verify: %+v", d)
	}
	for _, a := range []string{"198.51.100.21", "198.51.100.22", "198.51.100.23"} {
		if d := e.Evaluate("s", []string{"Amazonbot/0.1"}, ip(a)); d.Outcome != OutBlock || d.Verification != VerifyFailed {
			t.Errorf("%s must fail: %+v", a, d)
		}
	}
	before := calls
	e.Evaluate("s", []string{"Amazonbot/0.1"}, ip("198.51.100.20"))
	if calls != before {
		t.Error("the verification result must be cached")
	}
}

func TestBypassWAFNeedsVerificationAndTheBox(t *testing.T) {
	// the box is off by default
	e := rangeEngine(t, nil)
	if d := e.Evaluate("s", []string{"GPTBot"}, ip("192.0.2.55")); d.Outcome != OutAllow || d.BypassWAF {
		t.Fatalf("bypass must be off by default: %+v", d)
	}
	// ticked: only verified crawlers
	e = rangeEngine(t, func(c *Config) { c.Global.BypassWAF = true })
	if d := e.Evaluate("s", []string{"GPTBot"}, ip("192.0.2.55")); !d.BypassWAF {
		t.Fatalf("verified + ticked must bypass: %+v", d)
	}
	// ticked, verified-only off, address outside the range: allowed by name, never bypassing
	e = rangeEngine(t, func(c *Config) { c.Global.BypassWAF = true; c.Global.VerifiedOnly = false })
	d := e.Evaluate("s", []string{"GPTBot"}, ip("198.51.100.1"))
	if d.Outcome != OutAllow || d.BypassWAF {
		t.Fatalf("a User-Agent alone must never bypass the WAF: %+v", d)
	}
	// the unverifiable crawler never bypasses
	e = rangeEngine(t, func(c *Config) { c.Global.BypassWAF = true; c.Global.VerifiedOnly = false })
	if d := e.Evaluate("s", []string{"ClaudeBot"}, ip("192.0.2.55")); d.Outcome != OutAllow || d.BypassWAF {
		t.Fatalf("unverifiable crawler bypassed the WAF: %+v", d)
	}
	// per-site override of the box
	f := false
	e = rangeEngine(t, func(c *Config) {
		c.Global.BypassWAF = true
		c.Sites = map[string]*SiteCfg{"strict": {Mode: SiteCustom, Custom: SiteSettings{BypassWAF: &f}}}
	})
	if d := e.Evaluate("strict", []string{"GPTBot"}, ip("192.0.2.55")); d.BypassWAF {
		t.Fatal("site override of the bypass ignored")
	}
}

func TestRateLimitAction(t *testing.T) {
	e := newEngine(t, enabledCfg(func(c *Config) {
		c.Global.Crawlers = map[string]string{"ccbot": ActRateLimit}
		c.Global.RateLimitPerMinute = 3
	}))
	now := time.Unix(1_700_000_000, 0)
	e.now = func() time.Time { return now }
	outs := []string{}
	for i := 0; i < 5; i++ {
		outs = append(outs, e.Evaluate("s", []string{"CCBot"}, nil).Outcome)
	}
	if strings.Join(outs, ",") != "allow,allow,allow,limited,limited" {
		t.Fatalf("rate limit: %v", outs)
	}
	// another site and another crawler have their own budget
	if e.Evaluate("other", []string{"CCBot"}, nil).Outcome != OutAllow {
		t.Error("budget must be per site")
	}
	now = now.Add(61 * time.Second)
	if e.Evaluate("s", []string{"CCBot"}, nil).Outcome != OutAllow {
		t.Error("budget must refill after a minute")
	}
}

func TestLogOnlyChangesNothing(t *testing.T) {
	e := newEngine(t, enabledCfg(func(c *Config) { c.Global.Groups = map[string]string{GroupTraining: ActLog} }))
	d := e.Evaluate("s", []string{"GPTBot"}, ip("198.51.100.1"))
	if d.Outcome != OutLogOnly || d.Spoofed || d.BypassWAF {
		t.Fatalf("%+v", d)
	}
}

func TestStatsCountDecisions(t *testing.T) {
	e := newEngine(t, enabledCfg(func(c *Config) { c.Global.Groups = map[string]string{GroupTraining: ActBlock} }))
	e.Evaluate("s", []string{"GPTBot"}, nil)
	e.Evaluate("s", []string{"GPTBot"}, nil)
	e.Evaluate("s", []string{"PerplexityBot"}, nil)
	got := map[string]uint64{}
	for _, r := range e.Stats() {
		got[r.Crawler+"/"+r.Decision] = r.Count
	}
	if got["gptbot/block"] != 2 || got["perplexitybot/default"] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestPreviewDoesNotCountOrLimit(t *testing.T) {
	e := newEngine(t, enabledCfg(func(c *Config) { c.Global.Crawlers = map[string]string{"gptbot": ActBlock} }))
	en, act, ok := e.Preview("s", "GPTBot/1.0")
	if !ok || en.ID != "gptbot" || act != ActBlock {
		t.Fatal("preview")
	}
	if len(e.Stats()) != 0 {
		t.Fatal("preview must not count")
	}
	if _, _, ok := e.Preview("s", "Mozilla"); ok {
		t.Fatal("not a crawler")
	}
}

// ---- informational posture ----

func TestPostureIsInformationalAndHonest(t *testing.T) {
	has := func(fs []Finding, id string) bool {
		for _, f := range fs {
			if f.ID == id {
				return true
			}
		}
		return false
	}
	e := New("", "")
	if f := e.Posture(2); !has(f, "policy-off") || !has(f, "legacy-switch") {
		t.Fatalf("%v", f)
	}
	e = newEngine(t, enabledCfg(func(c *Config) {
		c.Global.Groups = map[string]string{GroupTraining: ActAllow}
		c.Global.BypassWAF = true
		c.Robots.Mode = RobotsServe
	}))
	f := e.Posture(0)
	for _, id := range []string{"allow-unverified", "bypass-waf", "ranges-missing", "robots-only"} {
		if !has(f, id) {
			t.Errorf("missing finding %s in %v", id, f)
		}
	}
	for _, x := range f {
		if x.Level != "ok" && x.Level != "note" && x.Level != "attention" {
			t.Errorf("bad level %q", x.Level)
		}
	}
}
