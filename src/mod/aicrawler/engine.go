package aicrawler

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Outcomes of an evaluation (what the proxy does)
const (
	OutNone      = ""          // not a known crawler, the policy is off, or the crawler has no policy: nothing changes
	OutAllow     = "allow"     // let it through; the AI crawler switch and the AI bot rule category do not stop it
	OutBlock     = "block"     // 403
	OutChallenge = "challenge" // CAPTCHA
	OutLimited   = "limited"   // over its rate limit: 429
	OutLogOnly   = "log"       // only logged; the rest of the chain behaves as without the policy
)

// Verification states
const (
	VerifyNotChecked   = "not-checked"
	VerifyVerified     = "verified"     // address inside a published range, or forward-confirmed reverse DNS matched
	VerifyFailed       = "failed"       // a method with data exists and the client does not match: spoofed
	VerifyUnverifiable = "unverifiable" // the operator documents no method, or its data has not been loaded yet
)

// Decision is the result of an evaluation
type Decision struct {
	Outcome      string
	Crawler      Entry // zero when no crawler matched
	Matched      bool
	Spoofed      bool   // the claim failed verification and the spoof action was applied
	Verification string // one of the Verify* states
	BypassWAF    bool   // verified, allowed, and the admin ticked the bypass
	Action       string // the configured action that was applied
}

// Detail is the short text of the blocked-request log: who and what was decided
func (d Decision) Detail() string {
	if !d.Matched {
		return ""
	}
	s := d.Crawler.Name + " (" + d.Crawler.Group + ")"
	if d.Spoofed {
		s += " claimed but " + d.Verification
	} else if d.Verification == VerifyVerified {
		s += " verified"
	}
	return s
}

// Engine evaluates User-Agents against the policy. Safe for concurrent use.
type Engine struct {
	path string
	cfg  atomic.Pointer[Config]

	Ranges *RangeStore

	// resolver hooks (tests)
	LookupAddr func(addr string) ([]string, error)
	LookupHost func(host string) ([]string, error)
	now        func() time.Time

	vmu   sync.Mutex
	vc    map[string]vEntry
	slots chan struct{}

	rl    limiter
	stats statsTable
}

type vEntry struct {
	state string
	exp   time.Time
}

// New creates an engine; folder-less (path "") keeps everything in memory. path is the config file,
// rangesPath the range cache file.
func New(path, rangesPath string) *Engine {
	e := &Engine{path: path, Ranges: NewRangeStore(rangesPath), now: time.Now, vc: map[string]vEntry{}, slots: make(chan struct{}, 16),
		LookupAddr: net.LookupAddr, LookupHost: net.LookupHost}
	c := DefaultConfig().normalise()
	e.cfg.Store(&c)
	e.rl.now = func() time.Time { return e.now() }
	return e
}

// Config returns a copy of the active configuration
func (e *Engine) Config() Config { return *e.cfg.Load() }

// Enabled reports the master switch
func (e *Engine) Enabled() bool { return e != nil && e.cfg.Load().Enabled }

// SetConfig validates, applies and persists
func (e *Engine) SetConfig(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	n := c.normalise()
	if e.path != "" {
		if err := saveConfig(e.path, n); err != nil {
			return err
		}
	}
	e.cfg.Store(&n)
	return nil
}

// Load reads the persisted configuration and the range cache. A missing file means the disabled defaults,
// an old or partial file keeps the defaults for every field it does not have.
func (e *Engine) Load() error {
	// The range cache is optional data: a corrupt file must not switch the policy off (the lists are fetched again)
	rangesErr := e.Ranges.Load()
	if e.path == "" {
		return rangesErr
	}
	js, err := os.ReadFile(e.path)
	if err != nil {
		return rangesErr
	}
	c := DefaultConfig()
	if err := json.Unmarshal(js, &c); err != nil {
		return err
	}
	// crawler and group ids come and go between versions: unknown ones are dropped, not fatal for the whole policy
	c.pruneUnknown()
	if err := c.Validate(); err != nil {
		return err
	}
	n := c.normalise()
	e.cfg.Store(&n)
	return rangesErr
}

// Preview says what the policy would do for a User-Agent on a site, without verifying, counting or limiting anything
// (the test box of the admin page). Action is the configured action, "" = no policy for that crawler.
func (e *Engine) Preview(site, ua string) (Entry, string, bool) {
	entry, ok := Match(ua)
	if !ok {
		return Entry{}, "", false
	}
	c := e.cfg.Load()
	ef := c.effectiveFor(site)
	if ef.off || !c.Enabled {
		return entry, "", true
	}
	return entry, ef.actionFor(entry), true
}

// Classify says which crawler a User-Agent claims to be, independent of any policy (for the UI test box)
func (e *Engine) Classify(ua string) (Entry, bool) { return Match(ua) }

// Evaluate judges one request of a site. userAgents are all values of the User-Agent header; clientIP is only
// called when a verification is needed.
func (e *Engine) Evaluate(site string, userAgents []string, clientIP func() string) Decision {
	if e == nil {
		return Decision{}
	}
	c := e.cfg.Load()
	if !c.Enabled {
		return Decision{}
	}
	ef := c.effectiveFor(site)
	if ef.off {
		return Decision{}
	}
	// Every claimed crawler is looked at, the most restrictive policy decides: a longer allowed token in the same
	// header (or in a second header) must not hide another crawler that is blocked or has no policy.
	var entry Entry
	found := false
	best := -1
	for _, ua := range userAgents {
		for _, m := range MatchAll(ua) {
			if r := actionStrictness(ef.actionFor(m)); r > best {
				best, entry, found = r, m, true
			}
		}
	}
	if !found {
		return Decision{}
	}
	d := Decision{Matched: true, Crawler: entry, Verification: VerifyNotChecked}
	act := ef.actionFor(entry)
	d.Action = act
	if act == "" {
		e.stats.add(site, entry.ID, "default", e.now())
		return d // no policy for this crawler: the existing behaviour applies
	}
	letsThrough := act == ActAllow || act == ActRateLimit
	ip := ""
	if clientIP != nil && (letsThrough && (ef.settings.VerifiedOnly || ef.settings.BypassWAF)) {
		ip = clientIP()
	}
	if letsThrough && (ef.settings.VerifiedOnly || ef.settings.BypassWAF) {
		d.Verification = e.verify(entry, ip)
	}
	if letsThrough && ef.settings.VerifiedOnly && d.Verification != VerifyVerified {
		d.Spoofed = true
		d.Outcome = spoofOutcome(ef.settings.SpoofAction)
		e.stats.add(site, entry.ID, "spoofed", e.now())
		return d
	}
	switch act {
	case ActAllow:
		d.Outcome = OutAllow
	case ActRateLimit:
		if e.rl.allow(site+"|"+entry.ID, ef.settings.RateLimitPerMinute) {
			d.Outcome = OutAllow
		} else {
			d.Outcome = OutLimited
		}
	case ActBlock:
		d.Outcome = OutBlock
	case ActChallenge:
		d.Outcome = OutChallenge
	case ActLog:
		d.Outcome = OutLogOnly
	}
	if d.Outcome == OutAllow && ef.settings.BypassWAF && d.Verification == VerifyVerified {
		d.BypassWAF = true // never on the User-Agent alone
	}
	e.stats.add(site, entry.ID, outcomeKey(d.Outcome), e.now())
	return d
}

// actionStrictness orders the configured actions for a request that claims several crawlers. "No policy" ranks above
// allow, log and rate limit because the older switches then still apply and must not be skipped.
func actionStrictness(a string) int {
	switch a {
	case ActBlock:
		return 6
	case ActChallenge:
		return 5
	case "":
		return 4
	case ActLog:
		return 3
	case ActRateLimit:
		return 2
	}
	return 1 // allow
}

func spoofOutcome(a string) string {
	switch a {
	case ActChallenge:
		return OutChallenge
	case ActLog:
		return OutLogOnly
	}
	return OutBlock
}

func outcomeKey(o string) string {
	if o == OutLimited {
		return "ratelimited"
	}
	return o
}

// Verify checks the claimed identity of a client address for a crawler (exported for the API test box)
func (e *Engine) Verify(entry Entry, ip string) string { return e.verify(entry, ip) }

func (e *Engine) verify(entry Entry, ip string) string {
	if !entry.Verify.Verifiable() {
		return VerifyUnverifiable
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return VerifyFailed
	}
	hadData := false
	if len(entry.Verify.RangeSources) > 0 {
		inside, had := e.Ranges.Contains(entry.Verify.RangeSources, addr)
		if inside {
			return VerifyVerified
		}
		hadData = had
	}
	if len(entry.Verify.RDNSSuffixes) > 0 {
		hadData = true // DNS is always available as a method
		if e.reverseDNS(entry, addr) {
			return VerifyVerified
		}
	}
	if !hadData {
		return VerifyUnverifiable // ranges documented, but the admin never refreshed them
	}
	return VerifyFailed
}

const maxVerifyCache = 8192

// reverseDNS does forward-confirmed reverse DNS (cached; at most 16 lookups in flight, otherwise "not verified")
func (e *Engine) reverseDNS(entry Entry, ip netip.Addr) bool {
	key := entry.ID + "|" + ip.String()
	now := e.now()
	e.vmu.Lock()
	if v, ok := e.vc[key]; ok && now.Before(v.exp) {
		e.vmu.Unlock()
		return v.state == VerifyVerified
	}
	e.vmu.Unlock()
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return false
	}
	ok := false
	if names, err := e.LookupAddr(ip.String()); err == nil {
		for _, n := range names {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
			suffix := false
			for _, s := range entry.Verify.RDNSSuffixes {
				if strings.HasSuffix(n, s) {
					suffix = true
				}
			}
			if !suffix {
				continue
			}
			if addrs, err := e.LookupHost(n); err == nil {
				for _, a := range addrs {
					if pa, err := netip.ParseAddr(a); err == nil && pa.Unmap() == ip.Unmap() {
						ok = true
					}
				}
			}
		}
	}
	ttl := time.Hour
	state := VerifyVerified
	if !ok {
		ttl, state = 10*time.Minute, VerifyFailed
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
	e.vc[key] = vEntry{state, now.Add(ttl)}
	e.vmu.Unlock()
	return ok
}

// ---- rate limit: fixed one minute window per site and crawler ----

type limiter struct {
	mu  sync.Mutex
	m   map[string]*window
	now func() time.Time
}

type window struct {
	start time.Time
	n     int
}

const maxWindows = 10000

func (l *limiter) allow(key string, perMinute int) bool {
	if perMinute <= 0 {
		perMinute = DefaultRateLimit
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*window{}
	}
	w := l.m[key]
	if w == nil {
		if len(l.m) >= maxWindows {
			for k, v := range l.m {
				if now.Sub(v.start) >= time.Minute {
					delete(l.m, k)
				}
			}
			if len(l.m) >= maxWindows {
				return false // full of live windows: fail closed
			}
		}
		w = &window{start: now}
		l.m[key] = w
	}
	if now.Sub(w.start) >= time.Minute {
		w.start, w.n = now, 0
	}
	if w.n >= perMinute {
		return false
	}
	w.n++
	return true
}

// ---- counters since start (bounded) ----

// StatRow is one counter row for the UI
type StatRow struct {
	Site     string `json:"site"`
	Crawler  string `json:"crawler"`
	Decision string `json:"decision"` // default | allow | block | challenge | ratelimited | spoofed | log
	Count    uint64 `json:"count"`
	Last     int64  `json:"last"`
}

type statsTable struct {
	mu sync.Mutex
	m  map[[3]string]*StatRow
}

const maxStatRows = 4000

func (s *statsTable) add(site, crawler, decision string, now time.Time) {
	k := [3]string{site, crawler, decision}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[[3]string]*StatRow{}
	}
	r := s.m[k]
	if r == nil {
		if len(s.m) >= maxStatRows {
			return
		}
		r = &StatRow{Site: site, Crawler: crawler, Decision: decision}
		s.m[k] = r
	}
	r.Count++
	r.Last = now.Unix()
}

// Stats returns the counters since the start of the process, most recent first
func (e *Engine) Stats() []StatRow {
	e.stats.mu.Lock()
	out := make([]StatRow, 0, len(e.stats.m))
	for _, r := range e.stats.m {
		out = append(out, *r)
	}
	e.stats.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Last != out[j].Last {
			return out[i].Last > out[j].Last
		}
		return out[i].Crawler < out[j].Crawler
	})
	return out
}
