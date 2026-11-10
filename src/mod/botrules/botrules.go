// Package botrules blocks, challenges or logs requests by User-Agent: managed
// category lists (AI crawlers, scanners, SEO bots, scrapers, HTTP libraries),
// custom substring / regex rules and an allow-list of good bots that is
// verified by reverse DNS (forward-confirmed), so a spoofed "Googlebot" is
// not trusted. Everything is off by default.
//
// Performance: the rule set is compiled once when the configuration changes.
// A request costs one lowercase of the (length capped) User-Agent and a few
// hundred substring searches; regular expressions are precompiled (RE2,
// linear time, so catastrophic patterns cannot stall the proxy).
package botrules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/exploits"
)

const (
	ActionBlock     = "block"
	ActionChallenge = "challenge"
	ActionLog       = "log"
	ActionDrop      = "drop"

	MatchSubstring = "substring"
	MatchRegex     = "regex"

	maxUA          = 512 //longer User-Agent headers are truncated before matching
	maxCustom      = 200
	maxPatternLen  = 200
	maxRegexLen    = 200
	maxVerifyCache = 8192
)

// Category is a managed list
type Category struct {
	ID    string
	Title string
	Items []string // lowercase substrings
}

func aiItems() []string {
	var out []string
	for _, p := range exploits.AIBotPatterns() { // reuse the exploit detector's AI crawler list
		p = strings.ToLower(strings.TrimPrefix(p, "(?i)"))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Categories returns the built-in lists
func Categories() []Category {
	return []Category{
		{"ai_crawler", "AI crawlers and training bots (shared with the exploit detector's list)", aiItems()},
		{"scanner", "Vulnerability scanners and attack tools", []string{"sqlmap", "nikto", "nmap scripting", "masscan", "zgrab", "acunetix", "nessus", "openvas", "wpscan", "dirbuster", "gobuster", "feroxbuster", "nuclei", "w3af", "havij", "netsparker", "arachni", "whatweb", "wfuzz", "ffuf", "hydra", "metasploit", "burpcollaborator", "paros", "skipfish", "zmeu", "morfeus", "jaeles"}},
		{"seo", "SEO and marketing crawlers", []string{"semrushbot", "ahrefsbot", "mj12bot", "dotbot", "blexbot", "petalbot", "dataforseo", "megaindex", "seokicks", "serpstatbot", "zoominfobot", "barkrowler", "seznambot", "rogerbot", "exabot", "linkpadbot", "serpapi", "seobilitybot"}},
		{"scraper", "Scraping frameworks and offline copiers", []string{"scrapy", "httrack", "webcopier", "webzip", "teleport pro", "offline explorer", "sitesucker", "webreaper", "webstripper", "blackwidow", "extractorpro", "emailcollector", "emailsiphon", "linkwalker", "heritrix", "colly", "apify", "crawl4ai", "headlesschrome"}},
		{"http_library", "Generic HTTP client libraries (often scripts)", []string{"python-requests", "python-urllib", "aiohttp", "httpx", "go-http-client", "okhttp", "java/", "apache-httpclient", "libwww-perl", "node-fetch", "axios/", "got (", "curl/", "wget/", "php/", "guzzlehttp", "ruby", "mechanize", "restsharp", "scrapy"}},
		{"bad_bot", "Known abusive bots and spam harvesters", []string{"indy library", "getright", "getweb!", "go!zilla", "download demon", "go-ahead-got-it", "grabnet", "turnitinbot", "sogou", "360spider", "pycurl", "msiecrawler", "ia_archiver-web.archive.org", "mail.ru_bot", "ltx71", "netcraftsurvey", "gigabot"}},
	}
}

// GoodBot is an allow-list entry verified by reverse DNS
type GoodBot struct {
	Name     string
	UA       string   // lowercase substring of the User-Agent
	Suffixes []string // the verified reverse DNS name must end with one of these
}

// GoodBots are the bots that can be verified by (forward-confirmed) reverse DNS
func GoodBots() []GoodBot {
	return []GoodBot{
		{"Googlebot", "googlebot", []string{".googlebot.com", ".google.com"}},
		{"Bingbot", "bingbot", []string{".search.msn.com"}},
		{"Yandex", "yandex", []string{".yandex.ru", ".yandex.net", ".yandex.com"}},
		{"Baidu", "baiduspider", []string{".baidu.com", ".baidu.jp"}},
		{"Applebot", "applebot", []string{".applebot.apple.com"}},
		{"DuckDuckBot", "duckduckbot", []string{".duckduckgo.com"}},
		{"Facebook", "facebookexternalhit", []string{".fbsv.net", ".facebook.com", ".tfbnw.net"}},
	}
}

// CategoryCfg enables a category with an action
type CategoryCfg struct {
	Enabled bool
	Action  string
}

// Rule is a custom rule
type Rule struct {
	Name            string
	Type            string // substring | regex
	Pattern         string
	CaseInsensitive bool
	Action          string
}

// Config is the persisted configuration
type Config struct {
	Enabled       bool                   // apply to every proxy rule (a proxy rule can opt in / out)
	Categories    map[string]CategoryCfg // by Category.ID
	Custom        []Rule
	AllowedBots   []string // GoodBot names that are trusted
	VerifyBots    bool     // verify allowed bots by reverse DNS; unverified claimants get FakeBotAction
	FakeBotAction string   // action for a spoofed good bot (default block)
	BlockEmptyUA  string   // "" = off, else the action for requests without a User-Agent
}

func validAction(a string) bool {
	return a == ActionBlock || a == ActionChallenge || a == ActionLog || a == ActionDrop
}

// Validate checks a configuration without applying it
func (c Config) Validate() error {
	known := map[string]bool{}
	for _, cat := range Categories() {
		known[cat.ID] = true
	}
	for id, cc := range c.Categories {
		if !known[id] {
			return fmt.Errorf("unknown category %q", id)
		}
		if !validAction(cc.Action) {
			return fmt.Errorf("category %s: invalid action", id)
		}
	}
	if len(c.Custom) > maxCustom {
		return fmt.Errorf("too many custom rules (max %d)", maxCustom)
	}
	for i, r := range c.Custom {
		if _, err := compileRule(r); err != nil {
			return fmt.Errorf("custom rule %d: %w", i+1, err)
		}
	}
	gb := map[string]bool{}
	for _, g := range GoodBots() {
		gb[g.Name] = true
	}
	for _, n := range c.AllowedBots {
		if !gb[n] {
			return fmt.Errorf("unknown good bot %q", n)
		}
	}
	if c.FakeBotAction != "" && !validAction(c.FakeBotAction) {
		return errors.New("invalid fake bot action")
	}
	if c.BlockEmptyUA != "" && !validAction(c.BlockEmptyUA) {
		return errors.New("invalid empty User-Agent action")
	}
	return nil
}

type compiledRule struct {
	Rule
	sub string
	re  *regexp.Regexp
}

func compileRule(r Rule) (*compiledRule, error) {
	if !validAction(r.Action) {
		return nil, errors.New("invalid action")
	}
	if r.Pattern == "" {
		return nil, errors.New("empty pattern")
	}
	switch r.Type {
	case MatchSubstring, "":
		if len(r.Pattern) > maxPatternLen {
			return nil, errors.New("pattern too long")
		}
		return &compiledRule{Rule: r, sub: strings.ToLower(r.Pattern)}, nil
	case MatchRegex:
		if len(r.Pattern) > maxRegexLen {
			return nil, errors.New("regular expression too long")
		}
		p := r.Pattern
		if r.CaseInsensitive {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p) //RE2: linear time, no backreferences / lookaround
		if err != nil {
			return nil, fmt.Errorf("invalid regular expression: %v", err)
		}
		return &compiledRule{Rule: r, re: re}, nil
	}
	return nil, errors.New("type must be substring or regex")
}

type catList struct {
	id, action string
	items      []string
}

type compiled struct {
	cfg      Config
	cats     []catList
	custom   []*compiledRule
	good     []GoodBot
	fakeAct  string
	emptyAct string
}

// Decision is the result of an evaluation
type Decision struct {
	Action string // "" = no match
	Reason string // e.g. "scanner", "custom:<name>", "fake-bot", "empty-ua" (never the User-Agent itself)
}

type vEntry struct {
	ok  bool
	exp time.Time
}

// Engine evaluates User-Agents. Safe for concurrent use.
type Engine struct {
	c    atomic.Pointer[compiled]
	path string

	// resolver hooks (tests)
	LookupAddr func(addr string) ([]string, error)
	LookupHost func(host string) ([]string, error)
	now        func() time.Time

	vmu   sync.Mutex
	vc    map[string]vEntry
	slots chan struct{} // bounds concurrent DNS lookups
}

// New creates an engine; folder "" = memory only
func New(folder string) *Engine {
	e := &Engine{path: folder, now: time.Now, vc: map[string]vEntry{}, slots: make(chan struct{}, 16),
		LookupAddr: net.LookupAddr, LookupHost: net.LookupHost}
	e.apply(Config{})
	return e
}

// DefaultConfig is disabled with sane preset actions
func DefaultConfig() Config {
	cats := map[string]CategoryCfg{}
	for _, c := range Categories() {
		act := ActionBlock
		cats[c.ID] = CategoryCfg{Enabled: false, Action: act}
	}
	return Config{Categories: cats, FakeBotAction: ActionBlock}
}

func (e *Engine) apply(cfg Config) {
	c := &compiled{cfg: cfg, fakeAct: cfg.FakeBotAction, emptyAct: cfg.BlockEmptyUA}
	if c.fakeAct == "" {
		c.fakeAct = ActionBlock
	}
	for _, cat := range Categories() {
		if cc, ok := cfg.Categories[cat.ID]; ok && cc.Enabled {
			c.cats = append(c.cats, catList{cat.ID, cc.Action, cat.Items})
		}
	}
	for _, r := range cfg.Custom {
		if cr, err := compileRule(r); err == nil {
			c.custom = append(c.custom, cr)
		}
	}
	allowed := map[string]bool{}
	for _, n := range cfg.AllowedBots {
		allowed[n] = true
	}
	for _, g := range GoodBots() {
		if allowed[g.Name] {
			c.good = append(c.good, g)
		}
	}
	e.c.Store(c)
}

// Config returns the active configuration
func (e *Engine) Config() Config { return e.c.Load().cfg }

// Enabled reports the global switch
func (e *Engine) Enabled() bool { return e != nil && e.c.Load().cfg.Enabled }

// SetConfig validates, applies and persists
func (e *Engine) SetConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.apply(cfg)
	if e.path == "" {
		return nil
	}
	js, _ := json.MarshalIndent(cfg, "", " ")
	if err := os.MkdirAll(filepath.Dir(e.path), 0o700); err != nil {
		return err
	}
	tmp := e.path + ".tmp"
	if err := os.WriteFile(tmp, js, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.path)
}

// Load reads the persisted configuration (missing = disabled defaults)
func (e *Engine) Load() error {
	if e.path == "" {
		return nil
	}
	js, err := os.ReadFile(e.path)
	if err != nil {
		return nil
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(js, &cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.apply(cfg)
	return nil
}

// Evaluate matches a User-Agent. clientIP is only called when a good bot has to be verified.
func (e *Engine) Evaluate(ua string, clientIP func() string) Decision {
	return e.EvaluateSkip(ua, clientIP, "")
}

// EvaluateSkip is Evaluate without the managed category skipCategory (""= none). The AI crawler policy uses it to
// leave out "ai_crawler" for a crawler it allowed explicitly; every other rule still applies.
func (e *Engine) EvaluateSkip(ua string, clientIP func() string, skipCategory string) Decision {
	c := e.c.Load()
	if len(ua) > maxUA {
		ua = ua[:maxUA]
	}
	if ua == "" {
		if c.emptyAct != "" {
			return Decision{c.emptyAct, "empty-ua"}
		}
		return Decision{}
	}
	lower := strings.ToLower(ua)

	for _, g := range c.good {
		if strings.Contains(lower, g.UA) {
			if !c.cfg.VerifyBots {
				return Decision{} //trusted by name (spoofable, documented)
			}
			if clientIP != nil && e.verifyBot(g, clientIP()) {
				return Decision{}
			}
			return Decision{c.fakeAct, "fake-bot"}
		}
	}
	for _, cr := range c.custom {
		var hit bool
		if cr.re != nil {
			hit = cr.re.MatchString(ua)
		} else {
			hit = strings.Contains(lower, cr.sub)
		}
		if hit {
			name := cr.Name
			if name == "" {
				name = "unnamed"
			}
			return Decision{cr.Action, "custom:" + name}
		}
	}
	for _, cat := range c.cats {
		if cat.id == skipCategory {
			continue
		}
		for _, it := range cat.items {
			if strings.Contains(lower, it) {
				return Decision{cat.action, cat.id}
			}
		}
	}
	return Decision{}
}

// verifyBot does forward-confirmed reverse DNS for the claimed bot
func (e *Engine) verifyBot(g GoodBot, ip string) bool {
	if ip == "" {
		return false
	}
	key := g.Name + "|" + ip
	now := e.now()
	e.vmu.Lock()
	if v, ok := e.vc[key]; ok && now.Before(v.exp) {
		e.vmu.Unlock()
		return v.ok
	}
	e.vmu.Unlock()

	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return false //too many lookups in flight: do not trust, do not cache
	}
	ok := false
	if names, err := e.LookupAddr(ip); err == nil {
		for _, n := range names {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
			suffixOK := false
			for _, s := range g.Suffixes {
				if strings.HasSuffix(n, s) {
					suffixOK = true
				}
			}
			if !suffixOK {
				continue
			}
			if addrs, err := e.LookupHost(n); err == nil {
				for _, a := range addrs {
					if sameIP(a, ip) {
						ok = true
					}
				}
			}
		}
	}
	ttl := time.Hour
	if !ok {
		ttl = 10 * time.Minute
	}
	e.vmu.Lock()
	if len(e.vc) >= maxVerifyCache {
		for k := range e.vc {
			delete(e.vc, k)
			if len(e.vc) < maxVerifyCache*9/10 {
				break
			}
		}
	}
	e.vc[key] = vEntry{ok, now.Add(ttl)}
	e.vmu.Unlock()
	return ok
}

func sameIP(a, b string) bool {
	x, y := net.ParseIP(a), net.ParseIP(b)
	return x != nil && y != nil && x.Equal(y)
}
