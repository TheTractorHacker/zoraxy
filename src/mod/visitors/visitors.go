// Package visitors keeps a bounded, persistent list of who visited the proxied sites:
// one aggregate record per client IP plus a ring buffer of the most recent individual visits.
//
// Design
//   - The request path only builds an Event and does a non-blocking channel send (Record).
//     A single writer goroutine owns all updates, so there is no per-request lock and no
//     shared map access on the hot path. When the queue is full the event is dropped and
//     counted (Stats().Dropped) instead of slowing the proxy down.
//   - Memory is bounded: at most MaxIPs visitors (oldest last-seen are pruned), at most
//     maxHostsPerIP / maxPathsPerIP keys per visitor, MaxVisits ring entries, and every
//     attacker controlled string is truncated.
//   - Everything is persisted as one gzip'd JSON file (atomically replaced) periodically and
//     on Close, and restored on start.
package visitors

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxHostsPerIP = 16
	maxPathsPerIP = 12
	maxDailyKeep  = 30
	maxHostLen    = 253
	maxPathLen    = 300
	maxUALen      = 200
	maxRingUALen  = 80
	queueSize     = 8192
	fileVersion   = 1
)

// Settings are the user adjustable limits. Zero values are replaced by the defaults in Normalize.
type Settings struct {
	Enabled          bool `json:"Enabled"`          // master switch (default on)
	MaxIPs           int  `json:"MaxIPs"`           // cap on stored client IPs (default 20000)
	MaxAgeDays       int  `json:"MaxAgeDays"`       // drop IPs not seen for this long (default 90)
	MaxVisits        int  `json:"MaxVisits"`        // size of the recent visit ring buffer (default 5000)
	KeepQuery        bool `json:"KeepQuery"`        // store the URL query string (default off: it may contain tokens)
	NotifyNewCountry bool `json:"NotifyNewCountry"` // emit visitor.new_country (default off)
}

// DefaultSettings is what a fresh install runs with
func DefaultSettings() Settings {
	return Settings{Enabled: true, MaxIPs: 20000, MaxAgeDays: 90, MaxVisits: 5000}
}

// Normalize clamps the settings to sane ranges
func (s Settings) Normalize() Settings {
	d := DefaultSettings()
	if s.MaxIPs <= 0 {
		s.MaxIPs = d.MaxIPs
	}
	if s.MaxIPs < 100 {
		s.MaxIPs = 100
	}
	if s.MaxIPs > 500000 {
		s.MaxIPs = 500000
	}
	if s.MaxAgeDays <= 0 {
		s.MaxAgeDays = d.MaxAgeDays
	}
	if s.MaxAgeDays > 3650 {
		s.MaxAgeDays = 3650
	}
	if s.MaxVisits <= 0 {
		s.MaxVisits = d.MaxVisits
	}
	if s.MaxVisits < 100 {
		s.MaxVisits = 100
	}
	if s.MaxVisits > 200000 {
		s.MaxVisits = 200000
	}
	return s
}

// Event is one request as seen by the proxy
type Event struct {
	Time      time.Time
	IP        string
	Host      string
	Rule      string // proxy rule key (optional)
	Method    string
	Path      string // escaped path, optionally with the query
	UA        string
	Country   string // ISO code, lower or upper case
	Via       string // direct | cloudflare | proxy
	ViaHeader string // header the client address was taken from, when via != direct
	Status    int
	Blocked   bool
}

// DayCount is the number of hits on one UTC day (days since the Unix epoch)
type DayCount struct {
	Day int32  `json:"d"`
	N   uint32 `json:"n"`
}

// Visitor is the aggregate record of one client IP
type Visitor struct {
	IP         string            `json:"ip"`
	FirstSeen  int64             `json:"first"`
	LastSeen   int64             `json:"last"`
	Hits       uint64            `json:"hits"`
	Blocked    uint64            `json:"blocked"`
	Country    string            `json:"country"`
	Hosts      map[string]uint32 `json:"hosts"`
	Paths      map[string]uint32 `json:"paths,omitempty"`
	LastHost   string            `json:"lastHost"`
	LastPath   string            `json:"lastPath"`
	LastUA     string            `json:"ua"`
	LastStatus int               `json:"status"`
	Via        string            `json:"via"`
	ViaHeader  string            `json:"viaHeader,omitempty"`
	Daily      []DayCount        `json:"daily,omitempty"`
}

// Visit is one entry of the recent visit ring buffer
type Visit struct {
	Seq       uint64 `json:"seq"`
	Time      int64  `json:"t"`
	IP        string `json:"ip"`
	Host      string `json:"host"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Country   string `json:"country"`
	UA        string `json:"ua"`
	Via       string `json:"via"`
	Blocked   bool   `json:"blocked"`
	NewVisitr bool   `json:"new,omitempty"` // first ever hit of this IP
}

// Stats are counters for diagnostics and the UI
type Stats struct {
	IPs      int    `json:"ips"`
	Visits   int    `json:"visits"`
	Dropped  uint64 `json:"dropped"`
	Recorded uint64 `json:"recorded"`
	Seq      uint64 `json:"seq"`
	Enabled  bool   `json:"enabled"`
}

// Tracker is the visitor store. Create it with New; it is safe for concurrent use.
type Tracker struct {
	file     string
	settings atomic.Pointer[Settings]
	excluded atomic.Pointer[func(ip string) bool]
	exclBlk  atomic.Pointer[func() bool]
	queue    chan Event
	dropped  atomic.Uint64
	recorded atomic.Uint64

	mu        sync.RWMutex
	visitors  map[string]*Visitor
	ring      []Visit
	ringNext  int
	ringCount int
	seq       uint64
	countries map[string]struct{}
	dirty     bool

	// OnNewCountry is called (from the writer goroutine) the first time a country is seen after
	// the store already knew other countries. Optional; set before traffic arrives.
	OnNewCountry func(country, ip, host string)

	stop    chan struct{}
	done    chan struct{}
	started bool
}

// New creates a tracker persisted in file ("" = memory only). Call Start to run it.
func New(file string, s Settings) *Tracker {
	s = s.Normalize()
	t := &Tracker{
		file:      file,
		queue:     make(chan Event, queueSize),
		visitors:  make(map[string]*Visitor),
		countries: make(map[string]struct{}),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	t.ring = make([]Visit, s.MaxVisits)
	t.settings.Store(&s)
	return t
}

// SetExcluder installs the stats exclusion list check (own IPs / CIDRs)
func (t *Tracker) SetExcluder(f func(ip string) bool) {
	if f == nil {
		t.excluded.Store(nil)
		return
	}
	t.excluded.Store(&f)
}

// SetExcludeBlocked installs a switch: while it returns true, requests that Zoraxy itself rejected
// (access list, WAF, rate limit ...) are not recorded (the statistics "exclude blocked" toggle)
func (t *Tracker) SetExcludeBlocked(f func() bool) {
	if f == nil {
		t.exclBlk.Store(nil)
		return
	}
	t.exclBlk.Store(&f)
}

// Settings returns the active settings
func (t *Tracker) Settings() Settings { return *t.settings.Load() }

// SetSettings applies new limits (the ring buffer is resized, keeping the newest visits)
func (t *Tracker) SetSettings(s Settings) Settings {
	s = s.Normalize()
	t.mu.Lock()
	if s.MaxVisits != len(t.ring) {
		old := t.recentLocked(0, 0)
		t.ring = make([]Visit, s.MaxVisits)
		t.ringNext, t.ringCount = 0, 0
		if len(old) > s.MaxVisits {
			old = old[len(old)-s.MaxVisits:]
		}
		for _, v := range old {
			t.pushRingLocked(v)
		}
	}
	t.dirty = true
	t.mu.Unlock()
	t.settings.Store(&s)
	return s
}

// Start loads the persisted data and runs the writer goroutine
func (t *Tracker) Start() {
	if t.started {
		return
	}
	t.started = true
	t.load()
	go t.run()
}

// Close stops the writer, drains the queue and persists
func (t *Tracker) Close() {
	if !t.started {
		return
	}
	t.started = false
	close(t.stop)
	<-t.done
}

// Record queues one request. It never blocks and takes no lock: when the queue is full the
// event is dropped (and counted).
func (t *Tracker) Record(ev Event) {
	s := t.settings.Load()
	if !s.Enabled || ev.IP == "" {
		return
	}
	if ex := t.excluded.Load(); ex != nil && (*ex)(ev.IP) {
		return
	}
	if ev.Blocked {
		if f := t.exclBlk.Load(); f != nil && (*f)() {
			return
		}
	}
	select {
	case t.queue <- ev:
	default:
		t.dropped.Add(1)
	}
}

// Stats returns counters
func (t *Tracker) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Stats{IPs: len(t.visitors), Visits: t.ringCount, Dropped: t.dropped.Load(), Recorded: t.recorded.Load(),
		Seq: t.seq, Enabled: t.settings.Load().Enabled}
}

func (t *Tracker) run() {
	defer close(t.done)
	persist := time.NewTicker(5 * time.Minute)
	prune := time.NewTicker(10 * time.Minute)
	defer persist.Stop()
	defer prune.Stop()
	batch := make([]Event, 0, 256)
	for {
		select {
		case ev := <-t.queue:
			batch = append(batch[:0], ev)
		drain:
			for len(batch) < cap(batch) {
				select {
				case e := <-t.queue:
					batch = append(batch, e)
				default:
					break drain
				}
			}
			t.apply(batch)
		case <-persist.C:
			t.Save()
		case <-prune.C:
			t.Prune(time.Now())
		case <-t.stop:
			for {
				select {
				case e := <-t.queue:
					t.apply([]Event{e})
				default:
					t.Prune(time.Now())
					t.Save()
					return
				}
			}
		}
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// do not cut a UTF-8 sequence in half
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// clean removes control characters (log injection, terminal escapes) from stored text
func clean(s string, n int) string {
	s = trunc(s, n)
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			b := []byte(s)
			for j := range b {
				if b[j] < 0x20 || b[j] == 0x7f {
					b[j] = ' '
				}
			}
			return string(b)
		}
	}
	return s
}

// SplitPath removes the query string of a request target unless keep is set
func SplitPath(p string, keep bool) string {
	if !keep {
		if i := strings.IndexByte(p, '?'); i >= 0 {
			p = p[:i]
		}
	}
	return p
}

func (t *Tracker) apply(evs []Event) {
	s := t.settings.Load()
	var newCountry []Event
	t.mu.Lock()
	for _, ev := range evs {
		t.recorded.Add(1)
		if _, err := netip.ParseAddr(ev.IP); err != nil {
			continue // never store anything that is not an IP address
		}
		now := ev.Time
		if now.IsZero() {
			now = time.Now()
		}
		ts := now.Unix()
		host := strings.ToLower(clean(ev.Host, maxHostLen))
		if h, _, ok := strings.Cut(host, ":"); ok && !strings.Contains(host[strings.Index(host, ":")+1:], ":") {
			host = h // strip :port, keep bare IPv6 literals
		}
		path := clean(SplitPath(ev.Path, s.KeepQuery), maxPathLen)
		ua := clean(ev.UA, maxUALen)
		cc := normalizeCountry(ev.Country)
		if isNonPublicIP(ev.IP) {
			cc = LocalCountry
		}
		via := ev.Via
		if via == "" {
			via = ViaDirect
		}

		v := t.visitors[ev.IP]
		isNew := v == nil
		if isNew {
			v = &Visitor{IP: ev.IP, FirstSeen: ts, Hosts: map[string]uint32{}}
			t.visitors[ev.IP] = v
		}
		v.LastSeen = ts
		v.Hits++
		if ev.Blocked {
			v.Blocked++
		}
		if cc != "" {
			v.Country = cc
		}
		bump(v.Hosts, host, maxHostsPerIP)
		if v.Paths == nil {
			v.Paths = map[string]uint32{}
		}
		bump(v.Paths, path, maxPathsPerIP)
		v.LastHost, v.LastPath, v.LastUA, v.LastStatus = host, path, ua, ev.Status
		v.Via, v.ViaHeader = via, trunc(ev.ViaHeader, 40)
		day := int32(ts / 86400)
		if n := len(v.Daily); n > 0 && v.Daily[n-1].Day == day {
			v.Daily[n-1].N++
		} else {
			v.Daily = append(v.Daily, DayCount{Day: day, N: 1})
			if len(v.Daily) > maxDailyKeep {
				v.Daily = append(v.Daily[:0], v.Daily[len(v.Daily)-maxDailyKeep:]...)
			}
		}

		t.seq++
		t.pushRingLocked(Visit{Seq: t.seq, Time: ts, IP: ev.IP, Host: host, Method: trunc(ev.Method, 10), Path: path,
			Status: ev.Status, Country: cc, UA: trunc(ua, maxRingUALen), Via: via, Blocked: ev.Blocked, NewVisitr: isNew})
		t.dirty = true

		if cc != "" {
			if _, known := t.countries[cc]; !known {
				if len(t.countries) > 0 && s.NotifyNewCountry {
					newCountry = append(newCountry, Event{Country: cc, IP: ev.IP, Host: host})
				}
				t.countries[cc] = struct{}{}
			}
		}
	}
	// soft cap: prune in a batch once we are 5% over, so the O(n) scan is amortised
	if len(t.visitors) > s.MaxIPs+s.MaxIPs/20 {
		t.pruneLocked(time.Now(), s)
	}
	t.mu.Unlock()
	if cb := t.OnNewCountry; cb != nil {
		for _, e := range newCountry {
			cb(e.Country, e.IP, e.Host)
		}
	}
}

// bump increments a counter in a size capped map, evicting the lowest count entry when full
func bump(m map[string]uint32, key string, max int) {
	if _, ok := m[key]; !ok && len(m) >= max {
		var lk string
		var lv uint32 = ^uint32(0)
		for k, v := range m {
			if v < lv {
				lk, lv = k, v
			}
		}
		delete(m, lk)
	}
	m[key]++
}

func (t *Tracker) pushRingLocked(v Visit) {
	if len(t.ring) == 0 {
		return
	}
	t.ring[t.ringNext] = v
	t.ringNext = (t.ringNext + 1) % len(t.ring)
	if t.ringCount < len(t.ring) {
		t.ringCount++
	}
}

// recentLocked returns up to limit visits (oldest first) with Seq > afterSeq; limit 0 = all
func (t *Tracker) recentLocked(afterSeq uint64, limit int) []Visit {
	out := make([]Visit, 0, t.ringCount)
	start := (t.ringNext - t.ringCount + len(t.ring)) % len(t.ring)
	for i := 0; i < t.ringCount; i++ {
		v := t.ring[(start+i)%len(t.ring)]
		if v.Seq > afterSeq {
			out = append(out, v)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Recent returns the newest visits matching the filter, newest first, with Seq > afterSeq
func (t *Tracker) Recent(afterSeq uint64, limit int, f Filter) []Visit {
	t.mu.RLock()
	all := t.recentLocked(afterSeq, 0)
	t.mu.RUnlock()
	out := make([]Visit, 0, 64)
	for i := len(all) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		if f.matchVisit(&all[i]) {
			out = append(out, all[i])
		}
	}
	return out
}

// Prune applies the retention settings
func (t *Tracker) Prune(now time.Time) int {
	s := t.settings.Load()
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pruneLocked(now, s)
}

func (t *Tracker) pruneLocked(now time.Time, s *Settings) int {
	removed := 0
	cut := now.Add(-time.Duration(s.MaxAgeDays) * 24 * time.Hour).Unix()
	for ip, v := range t.visitors {
		if v.LastSeen < cut {
			delete(t.visitors, ip)
			removed++
		}
	}
	if len(t.visitors) > s.MaxIPs {
		all := make([]*Visitor, 0, len(t.visitors))
		for _, v := range t.visitors {
			all = append(all, v)
		}
		sort.Slice(all, func(i, j int) bool { return all[i].LastSeen < all[j].LastSeen })
		for _, v := range all[:len(all)-s.MaxIPs] {
			delete(t.visitors, v.IP)
			removed++
		}
	}
	if removed > 0 {
		t.dirty = true
	}
	return removed
}

// Delete removes one IP (aggregate and its entries in the recent list)
func (t *Tracker) Delete(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.visitors[ip]
	delete(t.visitors, ip)
	kept := t.recentLocked(0, 0)
	n := kept[:0]
	for _, v := range kept {
		if v.IP != ip {
			n = append(n, v)
		}
	}
	if len(n) != len(kept) {
		ok = true
		t.ringNext, t.ringCount = 0, 0
		for _, v := range n {
			t.pushRingLocked(v)
		}
	}
	if ok {
		t.dirty = true
	}
	return ok
}

// Purge deletes everything (also the persisted file)
func (t *Tracker) Purge() {
	t.mu.Lock()
	t.visitors = make(map[string]*Visitor)
	t.countries = make(map[string]struct{})
	t.ringNext, t.ringCount = 0, 0
	t.dirty = true
	t.mu.Unlock()
	t.Save()
}

// Get returns a copy of one visitor and its recent visits (newest first)
func (t *Tracker) Get(ip string) (*Visitor, []Visit) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	v := t.visitors[ip]
	if v == nil {
		return nil, nil
	}
	c := cloneVisitor(v)
	var recent []Visit
	for _, r := range t.recentLocked(0, 0) {
		if r.IP == ip {
			recent = append(recent, r)
		}
	}
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	return c, recent
}

func cloneVisitor(v *Visitor) *Visitor {
	c := *v
	c.Hosts = make(map[string]uint32, len(v.Hosts))
	for k, n := range v.Hosts {
		c.Hosts[k] = n
	}
	c.Paths = make(map[string]uint32, len(v.Paths))
	for k, n := range v.Paths {
		c.Paths[k] = n
	}
	c.Daily = append([]DayCount(nil), v.Daily...)
	return &c
}

// ---- persistence ----

type fileFormat struct {
	Version  int       `json:"version"`
	Saved    int64     `json:"saved"`
	Seq      uint64    `json:"seq"`
	Visitors []Visitor `json:"visitors"`
	Visits   []Visit   `json:"visits"`
}

// Save writes the store to disk if something changed (atomic replace)
func (t *Tracker) Save() error {
	if t.file == "" {
		return nil
	}
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return nil
	}
	ff := fileFormat{Version: fileVersion, Saved: time.Now().Unix(), Seq: t.seq, Visits: t.recentLocked(0, 0)}
	ff.Visitors = make([]Visitor, 0, len(t.visitors))
	for _, v := range t.visitors {
		ff.Visitors = append(ff.Visitors, *v)
	}
	// marshal while holding the lock (the maps inside Visitor are mutated by the writer); compress and write after
	raw, merr := json.Marshal(&ff)
	t.dirty = merr != nil
	t.mu.Unlock()
	if merr != nil {
		return merr
	}

	if err := os.MkdirAll(filepath.Dir(t.file), 0o700); err != nil {
		return err
	}
	tmp := t.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)
	_, err = zw.Write(raw)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		t.mu.Lock()
		t.dirty = true
		t.mu.Unlock()
		return err
	}
	return os.Rename(tmp, t.file)
}

func (t *Tracker) load() {
	if t.file == "" {
		return
	}
	f, err := os.Open(t.file)
	if err != nil {
		return
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return
	}
	var ff fileFormat
	if err := json.NewDecoder(zr).Decode(&ff); err != nil || ff.Version != fileVersion {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range ff.Visitors {
		v := ff.Visitors[i]
		if v.IP == "" {
			continue
		}
		if v.Hosts == nil {
			v.Hosts = map[string]uint32{}
		}
		// records written by older builds cut zone names to two letters ("Private" became PR =
		// Puerto Rico, "CarrierNAT" CA = Canada); a non-public address has no country
		if isNonPublicIP(v.IP) {
			v.Country = LocalCountry
		}
		t.visitors[v.IP] = &v
		if v.Country != "" {
			t.countries[v.Country] = struct{}{}
		}
	}
	t.seq = ff.Seq
	for _, v := range ff.Visits {
		if isNonPublicIP(v.IP) {
			v.Country = LocalCountry
		}
		t.pushRingLocked(v)
	}
	t.pruneLocked(time.Now(), t.settings.Load())
}

// ---- client attribution ----

// Values of Event.Via
const (
	ViaDirect     = "direct"
	ViaCloudflare = "cloudflare"
	ViaProxy      = "proxy"
)

// Attribute tells how a request reached us. peerIP is the TCP peer address and clientIP the
// address the access layer attributed the request to (GetClientIPForEndpoint, which only follows
// forwarded headers when the peer is a trusted proxy). If both are equal the request is direct:
// a CF-Connecting-IP header sent by an untrusted peer was ignored upstream and is never reported
// here as "cloudflare". Otherwise the header carrying clientIP names the intermediary.
func Attribute(peerIP, clientIP string, h http.Header) (via, header string) {
	if clientIP == "" || clientIP == peerIP || sameAddr(peerIP, clientIP) {
		return ViaDirect, ""
	}
	for _, name := range []string{"Cf-Connecting-Ip", "Cf-Connecting-Ipv6", "True-Client-Ip"} {
		if hv := h.Get(name); hv != "" && sameAddr(firstIP(hv), clientIP) {
			if name == "True-Client-Ip" && h.Get("Cf-Ray") == "" {
				break
			}
			return ViaCloudflare, canonicalHeader(name)
		}
	}
	for _, name := range []string{"X-Real-Ip", "Fastly-Client-Ip", "X-Forwarded-For"} {
		if hv := h.Get(name); hv != "" && sameAddr(firstIP(hv), clientIP) {
			return ViaProxy, canonicalHeader(name)
		}
	}
	return ViaProxy, ""
}

func canonicalHeader(n string) string {
	switch n {
	case "Cf-Connecting-Ip":
		return "CF-Connecting-IP"
	case "Cf-Connecting-Ipv6":
		return "CF-Connecting-IPv6"
	case "True-Client-Ip":
		return "True-Client-IP"
	case "X-Real-Ip":
		return "X-Real-IP"
	case "Fastly-Client-Ip":
		return "Fastly-Client-IP"
	}
	return n
}

func firstIP(v string) string {
	v, _, _ = strings.Cut(v, ",")
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	return v
}

func sameAddr(a, b string) bool {
	if a == b {
		return true
	}
	pa, e1 := netip.ParseAddr(a)
	pb, e2 := netip.ParseAddr(b)
	return e1 == nil && e2 == nil && pa.Unmap() == pb.Unmap()
}

// LocalCountry is stored instead of a country for private, loopback, link-local,
// CGNAT and other non-public addresses. It is three letters on purpose so it can
// never be mistaken for an ISO 3166 code.
const LocalCountry = "LAN"

// normalizeCountry returns the upper-case two-letter ISO code, "" for no answer, or
// LocalCountry when the geo database answered with a zone name such as "Private".
func normalizeCountry(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	if len(c) == 2 {
		return strings.ToUpper(c)
	}
	return LocalCountry
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isNonPublicIP reports addresses that cannot sit in any country.
func isNonPublicIP(ip string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || cgnatPrefix.Contains(a)
}
