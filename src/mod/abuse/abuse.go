// Package abuse is the built-in "fail2ban": it counts abusive events per
// client IP (repeated 401/403/404/429 responses, failed logins, WAF blocks,
// CAPTCHA failures ...) and bans offenders for a limited, escalating time.
//
// Everything is off by default (Config.Enabled=false). Bans live in memory
// behind a cheap lookup, are persisted to a JSON file and bounded in size.
// Loopback / private / link-local addresses, the allow-list, trusted proxies
// and the server's own address are never banned unless BanPrivate is set
// explicitly.
package abuse

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kind is a detector (event type)
type Kind string

const (
	KindUnauthorized Kind = "unauthorized"  // 401 responses (basic auth failures, upstream 401)
	KindForbidden    Kind = "forbidden"     // 403 responses
	KindNotFound     Kind = "not_found"     // 404 responses (scanner detection)
	KindRateLimited  Kind = "rate_limited"  // rate limiter rejections / 429
	KindWAF          Kind = "waf_block"     // WAF blocks
	KindExploit      Kind = "exploit_block" // exploit detector blocks
	KindBot          Kind = "bot_block"     // bot rule blocks
	KindCaptchaFail  Kind = "captcha_fail"  // failed CAPTCHA verification
	KindLoginFail    Kind = "login_fail"    // failed admin panel logins
	KindManual       Kind = "manual"        // manual / remote ban (not a detector)
)

// AllKinds are the configurable detectors
var AllKinds = []Kind{KindUnauthorized, KindForbidden, KindNotFound, KindRateLimited, KindWAF, KindExploit, KindBot, KindCaptchaFail, KindLoginFail}

// Detector: Threshold events within WindowSec seconds trigger a ban
type Detector struct {
	Enabled   bool
	Threshold int
	WindowSec int
}

// Config is the persisted configuration
type Config struct {
	Enabled          bool
	Detectors        map[Kind]Detector
	BanSeconds       int64    // base ban duration
	EscalationFactor float64  // multiplier per repeated offence (1 = no escalation)
	MaxBanSeconds    int64    // upper bound of escalation
	OffenderMemory   int64    // seconds an offender is remembered for escalation
	AllowList        []string // IPs / CIDRs that are never banned
	BanPrivate       bool     // explicitly allow banning loopback / private ranges
	IPv6Prefix       int      // IPv6 clients are tracked and banned per prefix (default 64)
	DropConnection   bool     // banned clients get the connection closed instead of a 403 page
	PerEndpoint      bool     // count and ban per proxy rule instead of globally
	ExcludeEndpoints []string // proxy rules (RootOrMatchingDomain) that never feed the detectors
	MaxTracked       int      // bound of the counter table
	MaxBans          int      // bound of the ban table
	RemoteTokenHash  string   `json:",omitempty"` // sha256 hex of the remote-ban API token ("" = remote API disabled)
}

// DefaultConfig is the disabled default
func DefaultConfig() Config {
	return Config{
		Detectors: map[Kind]Detector{
			KindUnauthorized: {Threshold: 10, WindowSec: 60},
			KindForbidden:    {Threshold: 20, WindowSec: 60},
			KindNotFound:     {Threshold: 30, WindowSec: 60},
			KindRateLimited:  {Threshold: 30, WindowSec: 60},
			KindWAF:          {Threshold: 5, WindowSec: 60},
			KindExploit:      {Threshold: 5, WindowSec: 60},
			KindBot:          {Threshold: 20, WindowSec: 60},
			KindCaptchaFail:  {Threshold: 5, WindowSec: 300},
			KindLoginFail:    {Threshold: 5, WindowSec: 300},
		},
		BanSeconds: 3600, EscalationFactor: 2, MaxBanSeconds: 7 * 86400,
		OffenderMemory: 7 * 86400, IPv6Prefix: 64, MaxTracked: 50000, MaxBans: 50000,
	}
}

const (
	hardMaxTracked = 1_000_000
	hardMaxBans    = 1_000_000
	maxWindowSec   = 86400
	maxThreshold   = 100000
	permanent      = -1
)

// Normalise validates and clamps a config; the returned config is safe to run
func (c Config) Normalise() (Config, error) {
	def := DefaultConfig()
	out := c
	det := map[Kind]Detector{}
	for k, d := range c.Detectors {
		known := false
		for _, kk := range AllKinds {
			if kk == k {
				known = true
			}
		}
		if !known {
			return c, fmt.Errorf("unknown detector %q", k)
		}
		if d.Threshold < 1 || d.Threshold > maxThreshold {
			return c, fmt.Errorf("detector %s: threshold must be 1..%d", k, maxThreshold)
		}
		if d.WindowSec < 1 || d.WindowSec > maxWindowSec {
			return c, fmt.Errorf("detector %s: window must be 1..%d seconds", k, maxWindowSec)
		}
		det[k] = d
	}
	for k, d := range def.Detectors { // fill missing detectors with (disabled) defaults
		if _, ok := det[k]; !ok {
			det[k] = d
		}
	}
	out.Detectors = det
	if out.BanSeconds <= 0 {
		out.BanSeconds = def.BanSeconds
	}
	if out.EscalationFactor < 1 {
		out.EscalationFactor = 1
	}
	if out.EscalationFactor > 10 {
		out.EscalationFactor = 10
	}
	if out.MaxBanSeconds < out.BanSeconds {
		out.MaxBanSeconds = out.BanSeconds
	}
	if out.OffenderMemory <= 0 {
		out.OffenderMemory = def.OffenderMemory
	}
	if out.IPv6Prefix == 0 {
		out.IPv6Prefix = 64
	}
	if out.IPv6Prefix < 32 || out.IPv6Prefix > 128 {
		return c, errors.New("IPv6Prefix must be 32..128")
	}
	if out.MaxTracked <= 0 {
		out.MaxTracked = def.MaxTracked
	}
	if out.MaxTracked > hardMaxTracked {
		out.MaxTracked = hardMaxTracked
	}
	if out.MaxBans <= 0 {
		out.MaxBans = def.MaxBans
	}
	if out.MaxBans > hardMaxBans {
		out.MaxBans = hardMaxBans
	}
	for _, a := range out.AllowList {
		if _, err := parsePrefix(a); err != nil {
			return c, fmt.Errorf("invalid allow-list entry %q", a)
		}
	}
	return out, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		a, bits := p.Addr().Unmap(), p.Bits()
		if p.Addr().Is4In6() && bits >= 96 {
			bits -= 96
		}
		return netip.PrefixFrom(a.WithZone(""), bits).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Ban is an active ban
type Ban struct {
	Key      string // internal key (scope|prefix)
	IP       string // normalised address or prefix, e.g. 203.0.113.7 or 2001:db8::/64
	Scope    string // "" = global, otherwise the proxy rule it applies to
	Reason   string
	Source   string // detector kind, "manual" or "remote"
	Created  int64  // unix seconds
	Expires  int64  // unix seconds, 0 = permanent (manual bans only)
	Level    int    // escalation level
	Endpoint string `json:",omitempty"` // endpoint that triggered it
}

type offender struct {
	Count int
	Last  int64
}

type counter struct {
	last int64
	ev   map[Kind][]int64
}

// Manager is the ban engine. Safe for concurrent use.
type Manager struct {
	cfg     atomic.Pointer[Config]
	allow   atomic.Pointer[[]netip.Prefix]
	enabled atomic.Bool
	now     func() time.Time
	path    string // config + state folder ("" = memory only)

	Protect func(netip.Addr) bool // optional: extra never-ban addresses (server IP, trusted proxies)
	OnBan   func(Ban)             // optional notification (called in its own goroutine)

	mu       sync.RWMutex
	bans     map[string]*Ban
	offender map[string]*offender
	dirty    atomic.Bool

	cmu      sync.Mutex
	counters map[string]*counter

	stop chan struct{}
	wg   sync.WaitGroup
}

// New creates a manager; folder may be "" for memory only (tests)
func New(folder string) *Manager {
	m := &Manager{now: time.Now, path: folder, bans: map[string]*Ban{}, offender: map[string]*offender{}, counters: map[string]*counter{}}
	m.setConfig(DefaultConfig())
	return m
}

// SetClock replaces the time source (tests)
func (m *Manager) SetClock(f func() time.Time) { m.now = f }

func (m *Manager) setConfig(c Config) {
	cc := c
	m.cfg.Store(&cc)
	var al []netip.Prefix
	for _, a := range c.AllowList {
		if p, err := parsePrefix(a); err == nil {
			al = append(al, p)
		}
	}
	m.allow.Store(&al)
	m.enabled.Store(c.Enabled)
}

// Config returns a copy of the active configuration
func (m *Manager) Config() Config {
	c := *m.cfg.Load()
	c.Detectors = map[Kind]Detector{}
	for k, v := range m.cfg.Load().Detectors {
		c.Detectors[k] = v
	}
	c.AllowList = append([]string(nil), c.AllowList...)
	c.ExcludeEndpoints = append([]string(nil), c.ExcludeEndpoints...)
	return c
}

// SetConfig validates, applies and persists a new configuration
func (m *Manager) SetConfig(c Config) error {
	n, err := c.Normalise()
	if err != nil {
		return err
	}
	m.setConfig(n)
	return m.saveConfig()
}

// Active reports whether the engine is enabled (single atomic load, hot path)
func (m *Manager) Active() bool { return m != nil && m.enabled.Load() }

// DropConnection reports whether banned clients get their connection closed
func (m *Manager) DropConnection() bool { return m.cfg.Load().DropConnection }

// NormaliseIP turns a client address into the tracking key. Handles ports,
// brackets, zones and IPv4-mapped IPv6; IPv6 addresses collapse to the
// configured prefix.
func NormaliseIP(s string, v6bits int) (key string, addr netip.Addr, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return "", netip.Addr{}, false
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		s = ap.Addr().String()
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", netip.Addr{}, false
	}
	a = a.WithZone("").Unmap()
	if a.Is6() && v6bits >= 1 && v6bits < 128 {
		return netip.PrefixFrom(a, v6bits).Masked().String(), a, true
	}
	return a.String(), a, true
}

func isPrivate(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast()
}

// Protected reports whether an address can never be auto banned
func (m *Manager) Protected(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, p := range *m.allow.Load() {
		if p.Contains(a) {
			return true
		}
	}
	if !m.cfg.Load().BanPrivate && isPrivate(a) {
		return true
	}
	return m.Protect != nil && m.Protect(a)
}

func banKey(scope, key string) string { return scope + "|" + key }

// IsBanned is the hot-path lookup. scope is the proxy rule name (consulted in
// addition to the global scope).
func (m *Manager) IsBanned(ip, scope string) (*Ban, bool) {
	if !m.enabled.Load() {
		return nil, false
	}
	m.mu.RLock()
	empty := len(m.bans) == 0
	m.mu.RUnlock()
	if empty {
		return nil, false
	}
	cfg := m.cfg.Load()
	key, addr, ok := NormaliseIP(ip, cfg.IPv6Prefix)
	if !ok || m.Protected(addr) {
		return nil, false
	}
	now := m.now().Unix()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range [2]string{banKey("", key), banKey(scope, key)} {
		if b, ok := m.bans[k]; ok && (b.Expires == 0 || b.Expires > now) {
			cp := *b
			return &cp, true
		}
		if scope == "" {
			break
		}
	}
	return nil, false
}

// Report records one event. It returns the new ban if this event caused one.
func (m *Manager) Report(ip, scope string, kind Kind, endpoint string) *Ban {
	if !m.enabled.Load() {
		return nil
	}
	cfg := m.cfg.Load()
	d, ok := cfg.Detectors[kind]
	if !ok || !d.Enabled {
		return nil
	}
	if endpoint != "" {
		for _, e := range cfg.ExcludeEndpoints {
			if e == endpoint {
				return nil
			}
		}
	}
	key, addr, ok := NormaliseIP(ip, cfg.IPv6Prefix)
	if !ok || m.Protected(addr) {
		return nil
	}
	if !cfg.PerEndpoint {
		scope = ""
	}
	bk := banKey(scope, key)
	now := m.now().Unix()

	m.mu.RLock()
	b, banned := m.bans[bk]
	banned = banned && (b.Expires == 0 || b.Expires > now)
	m.mu.RUnlock()
	if banned {
		return nil //already banned, do not count
	}

	m.cmu.Lock()
	c := m.counters[bk]
	if c == nil {
		if len(m.counters) >= cfg.MaxTracked {
			m.evictCountersLocked(now, cfg.MaxTracked)
		}
		c = &counter{ev: map[Kind][]int64{}}
		m.counters[bk] = c
	}
	c.last = now
	times := c.ev[kind]
	cut := now - int64(d.WindowSec)
	i := 0
	for i < len(times) && times[i] <= cut {
		i++
	}
	times = append(times[i:], now)
	if len(times) > d.Threshold {
		times = times[len(times)-d.Threshold:]
	}
	c.ev[kind] = times
	trip := len(times) >= d.Threshold
	if trip {
		delete(m.counters, bk)
	}
	m.cmu.Unlock()
	if !trip {
		return nil
	}
	return m.addBan(key, scope, fmt.Sprintf("%d x %s in %ds", d.Threshold, kind, d.WindowSec), string(kind), endpoint, 0)
}

func (m *Manager) evictCountersLocked(now int64, max int) {
	for k, c := range m.counters {
		if now-c.last > maxWindowSec {
			delete(m.counters, k)
		}
	}
	for k := range m.counters { // still full: drop arbitrary entries down to 90%
		if len(m.counters) < max-max/10 {
			break
		}
		delete(m.counters, k)
	}
}

// addBan creates a ban; secs==0 derives the duration (with escalation), -1 is permanent
func (m *Manager) addBan(key, scope, reason, source, endpoint string, secs int64) *Ban {
	cfg := m.cfg.Load()
	now := m.now().Unix()
	bk := banKey(scope, key)
	m.mu.Lock()
	defer m.mu.Unlock()
	off := m.offender[bk]
	level := 0
	if off != nil && now-off.Last <= cfg.OffenderMemory {
		level = off.Count
	}
	exp := int64(0)
	if secs >= 0 && secs != permanent {
		if secs == 0 {
			d := float64(cfg.BanSeconds)
			for i := 0; i < level && d < float64(cfg.MaxBanSeconds); i++ {
				d *= cfg.EscalationFactor
			}
			if d > float64(cfg.MaxBanSeconds) {
				d = float64(cfg.MaxBanSeconds)
			}
			secs = int64(d)
		}
		exp = now + secs
	}
	m.offender[bk] = &offender{Count: level + 1, Last: now}
	if len(m.offender) > cfg.MaxBans {
		for k, o := range m.offender {
			if now-o.Last > cfg.OffenderMemory {
				delete(m.offender, k)
			}
		}
	}
	if _, replacing := m.bans[bk]; !replacing && len(m.bans) >= cfg.MaxBans {
		m.pruneBansLocked(now, cfg.MaxBans)
	}
	b := &Ban{Key: bk, IP: key, Scope: scope, Reason: reason, Source: source, Created: now, Expires: exp, Level: level + 1, Endpoint: endpoint}
	m.bans[bk] = b
	m.dirty.Store(true)
	cp := *b
	if m.OnBan != nil {
		go m.OnBan(cp)
	}
	return &cp
}

func (m *Manager) pruneBansLocked(now int64, max int) {
	for k, b := range m.bans {
		if b.Expires != 0 && b.Expires <= now {
			delete(m.bans, k)
		}
	}
	for len(m.bans) >= max { // evict the ban that expires first (permanent ones last)
		vk, ve := "", int64(1<<62)
		for k, b := range m.bans {
			e := b.Expires
			if e == 0 {
				e = 1 << 61
			}
			if e < ve {
				ve, vk = e, k
			}
		}
		if vk == "" {
			return
		}
		delete(m.bans, vk)
	}
}

// ManualBan bans an address (IPv6: its tracking prefix). secs<=0 means
// permanent. Protected addresses are refused.
func (m *Manager) ManualBan(ip, scope, reason, source string, secs int64) (*Ban, error) {
	cfg := m.cfg.Load()
	key, addr, ok := NormaliseIP(ip, cfg.IPv6Prefix)
	if !ok {
		return nil, errors.New("invalid IP address")
	}
	if m.Protected(addr) {
		return nil, errors.New("address is protected (allow-list, private range, trusted proxy or this server) and cannot be banned")
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	if secs <= 0 {
		secs = permanent
	} else if secs > 10*365*86400 {
		secs = 10 * 365 * 86400
	}
	return m.addBan(key, scope, reason, source, "", secs), nil
}

// Unban removes a ban and forgets the offender history of that key
func (m *Manager) Unban(ip, scope string) bool {
	key, _, ok := NormaliseIP(ip, m.cfg.Load().IPv6Prefix)
	if !ok {
		return false
	}
	bk := banKey(scope, key)
	m.mu.Lock()
	_, existed := m.bans[bk]
	delete(m.bans, bk)
	delete(m.offender, bk)
	m.mu.Unlock()
	if existed {
		m.dirty.Store(true)
	}
	return existed
}

// List returns the active (unexpired) bans, newest first
func (m *Manager) List() []Ban {
	now := m.now().Unix()
	m.mu.RLock()
	out := make([]Ban, 0, len(m.bans))
	for _, b := range m.bans {
		if b.Expires == 0 || b.Expires > now {
			out = append(out, *b)
		}
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out
}

// Sweep removes expired bans and stale counters
func (m *Manager) Sweep() {
	now := m.now().Unix()
	m.mu.Lock()
	for k, b := range m.bans {
		if b.Expires != 0 && b.Expires <= now {
			delete(m.bans, k)
			m.dirty.Store(true)
		}
	}
	mem := m.cfg.Load().OffenderMemory
	for k, o := range m.offender {
		if now-o.Last > mem {
			delete(m.offender, k)
			m.dirty.Store(true)
		}
	}
	m.mu.Unlock()
	m.cmu.Lock()
	for k, c := range m.counters {
		if now-c.last > maxWindowSec {
			delete(m.counters, k)
		}
	}
	m.cmu.Unlock()
}

/* persistence */

type state struct {
	Bans      []Ban
	Offenders map[string]offender
}

func (m *Manager) cfgFile() string   { return filepath.Join(m.path, "config.json") }
func (m *Manager) stateFile() string { return filepath.Join(m.path, "bans.json") }

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *Manager) saveConfig() error {
	if m.path == "" {
		return nil
	}
	js, err := json.MarshalIndent(m.cfg.Load(), "", " ")
	if err != nil {
		return err
	}
	return writeAtomic(m.cfgFile(), js)
}

// Flush writes the ban state if it changed
func (m *Manager) Flush() error {
	if m.path == "" || !m.dirty.Swap(false) {
		return nil
	}
	m.mu.RLock()
	st := state{Offenders: map[string]offender{}}
	for _, b := range m.bans {
		st.Bans = append(st.Bans, *b)
	}
	for k, o := range m.offender {
		st.Offenders[k] = *o
	}
	m.mu.RUnlock()
	js, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := writeAtomic(m.stateFile(), js); err != nil {
		m.dirty.Store(true)
		return err
	}
	return nil
}

// Load reads config and state from disk (missing files = defaults)
func (m *Manager) Load() error {
	if m.path == "" {
		return nil
	}
	if js, err := os.ReadFile(m.cfgFile()); err == nil {
		c := DefaultConfig()
		if err := json.Unmarshal(js, &c); err != nil {
			return fmt.Errorf("abuse config: %w", err)
		}
		n, err := c.Normalise()
		if err != nil {
			return fmt.Errorf("abuse config: %w", err)
		}
		m.setConfig(n)
	}
	if js, err := os.ReadFile(m.stateFile()); err == nil {
		var st state
		if err := json.Unmarshal(js, &st); err != nil {
			return fmt.Errorf("abuse state: %w", err)
		}
		now := m.now().Unix()
		m.mu.Lock()
		for i := range st.Bans {
			b := st.Bans[i]
			if b.Expires != 0 && b.Expires <= now {
				continue
			}
			m.bans[b.Key] = &b
		}
		for k, o := range st.Offenders {
			o := o
			m.offender[k] = &o
		}
		m.mu.Unlock()
	}
	return nil
}

// Start launches the background flush / sweep loop
func (m *Manager) Start() {
	m.stop = make(chan struct{})
	stop := m.stop
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-t.C:
				n++
				if n%12 == 0 {
					m.Sweep()
				}
				m.Flush()
			case <-stop:
				return
			}
		}
	}()
}

// Stop ends the loop and flushes
func (m *Manager) Stop() {
	if m.stop != nil {
		close(m.stop)
		m.wg.Wait()
		m.stop = nil
	}
	m.Flush()
}
