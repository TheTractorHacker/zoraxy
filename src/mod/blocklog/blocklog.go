// Package blocklog keeps a bounded log of the requests Zoraxy itself rejected (access list,
// auto-ban, rate limit, WAF, bot / header / path rules, CAPTCHA, client certificate, auth ...)
// so the "Blocked" counters of the Status page can be explained: what, who, and why.
package blocklog

import (
	"compress/gzip"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	// DefaultCapacity is the number of entries kept
	DefaultCapacity = 2000
	maxPathLen      = 300
	maxUALen        = 160
	maxDetailLen    = 240
	fileVersion     = 1
)

// Entry is one rejected request
type Entry struct {
	Seq     uint64 `json:"seq"`
	Time    int64  `json:"t"` // unix seconds
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	Host    string `json:"host"`
	Rule    string `json:"rule,omitempty"` // proxy rule key
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"` // status code logged (444 = connection dropped without an answer)
	Reason  string `json:"reason"`
	Detail  string `json:"detail,omitempty"`
	UA      string `json:"ua,omitempty"`

	Tags []string `json:"tags,omitempty"` // tags set by rules of the rules engine on this request

	// Ref is the short reference the visitor was shown (8 characters, see NewRef / FormatRef). RuleID is the
	// machine key of what fired (bot:http_library, access:Office, waf:941100 ...). Both are empty on
	// entries written by older versions.
	Ref    string `json:"ref,omitempty"`
	RuleID string `json:"rid,omitempty"`
}

// Settings are persisted by the caller
type Settings struct {
	Enabled bool `json:"Enabled"`
}

// DefaultSettings records blocked requests
func DefaultSettings() Settings { return Settings{Enabled: true} }

// Log is the store. Safe for concurrent use.
type Log struct {
	file     string
	enabled  atomic.Bool
	excluded atomic.Pointer[func(ip string) bool]
	exclBlk  atomic.Pointer[func() bool]

	mu       sync.RWMutex
	ring     []Entry
	next     int
	count    int
	seq      uint64
	dirty    bool
	recorded uint64
	byReason map[string]uint64 // since start, not bounded by the ring
	byRef    map[string]uint64 // Ref -> Seq of the entries that are still in the ring

	stop    chan struct{}
	done    chan struct{}
	started bool
}

// New creates a log persisted in file ("" = memory only) holding at most capacity entries
func New(file string, capacity int, s Settings) *Log {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	l := &Log{file: file, ring: make([]Entry, capacity), byReason: map[string]uint64{}, byRef: map[string]uint64{},
		stop: make(chan struct{}), done: make(chan struct{})}
	l.enabled.Store(s.Enabled)
	return l
}

// SetEnabled switches recording on or off
func (l *Log) SetEnabled(v bool) { l.enabled.Store(v) }

// Enabled reports whether new blocked requests are recorded
func (l *Log) Enabled() bool { return l.enabled.Load() }

// SetExcluder installs the statistics exclusion list check (own IPs / networks)
func (l *Log) SetExcluder(f func(ip string) bool) {
	if f == nil {
		l.excluded.Store(nil)
		return
	}
	l.excluded.Store(&f)
}

// SetExcludeBlocked installs the statistics "exclude blocked requests" switch
func (l *Log) SetExcludeBlocked(f func() bool) {
	if f == nil {
		l.exclBlk.Store(nil)
		return
	}
	l.exclBlk.Store(&f)
}

// ExcludesBlocked reports whether the statistics settings ask to leave blocked requests out
func (l *Log) ExcludesBlocked() bool {
	if f := l.exclBlk.Load(); f != nil {
		return (*f)()
	}
	return false
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) { // do not cut inside a UTF-8 sequence
		s = s[:len(s)-1]
	}
	return s
}

// Record adds one entry. It takes a short lock only; no I/O.
func (l *Log) Record(e Entry) {
	if l == nil || !l.enabled.Load() || e.IP == "" || e.Reason == "" {
		return
	}
	if ex := l.excluded.Load(); ex != nil && (*ex)(e.IP) {
		return
	}
	if l.ExcludesBlocked() {
		return
	}
	if e.Time == 0 {
		e.Time = time.Now().Unix()
	}
	if a, err := netip.ParseAddr(e.IP); err == nil {
		e.IP = a.String() // one spelling per address, so the IP filter and the top list agree
	}
	e.Host = strings.ToLower(trunc(e.Host, 253))
	e.Path = trunc(e.Path, maxPathLen)
	e.UA = trunc(e.UA, maxUALen)
	e.Detail = trunc(e.Detail, maxDetailLen)
	e.RuleID = trunc(e.RuleID, maxDetailLen)
	e.Ref = NormalizeRef(e.Ref)
	l.mu.Lock()
	l.seq++
	e.Seq = l.seq
	if old := &l.ring[l.next]; l.count == len(l.ring) && old.Ref != "" && l.byRef[old.Ref] == old.Seq {
		delete(l.byRef, old.Ref) //the entry is about to be overwritten
	}
	if e.Ref != "" {
		if _, taken := l.byRef[e.Ref]; taken {
			e.Ref = "" //a reference belongs to the first entry that has it, a repeat must not take it over
		} else {
			l.byRef[e.Ref] = e.Seq
		}
	}
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.count < len(l.ring) {
		l.count++
	}
	l.recorded++
	l.byReason[e.Reason]++
	l.dirty = true
	l.mu.Unlock()
}

// Filter narrows the log
type Filter struct {
	Reason string
	Host   string // exact, lower case
	IP     string // exact
	Q      string // case-insensitive substring of ip, host, path, detail, UA, reason
	Since  int64  // unix seconds
	Ref    string // exact reference ID (any spelling, see NormalizeRef); looked up through the index
}

func (f Filter) match(e *Entry, withReason bool) bool {
	if f.Since > 0 && e.Time < f.Since {
		return false
	}
	if withReason && f.Reason != "" && e.Reason != f.Reason {
		return false
	}
	if f.Ref != "" && e.Ref != NormalizeRef(f.Ref) {
		return false
	}
	if f.Host != "" && e.Host != f.Host {
		return false
	}
	if f.IP != "" && e.IP != f.IP {
		return false
	}
	if f.Q != "" {
		q := strings.ToLower(f.Q)
		if !strings.Contains(strings.ToLower(e.IP), q) && !strings.Contains(strings.ToLower(e.Host), q) &&
			!strings.Contains(strings.ToLower(e.Path), q) && !strings.Contains(strings.ToLower(e.Detail), q) &&
			!strings.Contains(strings.ToLower(e.UA), q) && !strings.Contains(e.Reason, q) {
			return false
		}
	}
	return true
}

// snapshotLocked returns the entries oldest first
func (l *Log) snapshotLocked() []Entry {
	out := make([]Entry, 0, l.count)
	start := 0
	if l.count == len(l.ring) {
		start = l.next
	}
	for i := 0; i < l.count; i++ {
		out = append(out, l.ring[(start+i)%len(l.ring)])
	}
	return out
}

// ListResult is one page, newest first
type ListResult struct {
	Total int     `json:"total"` // entries matching the filter
	Items []Entry `json:"items"`
	Next  uint64  `json:"next"` // pass as before= for the next page (0 = no more)
}

// List returns up to limit matching entries older than seq before (0 = from the newest)
func (l *Log) List(f Filter, before uint64, limit int) ListResult {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	res := ListResult{Items: []Entry{}}
	if f.Ref != "" { //O(1) through the index instead of a scan
		e, ok := l.GetByRef(f.Ref)
		if !ok || !f.match(&e, true) {
			return res
		}
		res.Total = 1
		if before == 0 || e.Seq < before {
			res.Items = append(res.Items, e)
		}
		return res
	}
	l.mu.RLock()
	all := l.snapshotLocked()
	l.mu.RUnlock()
	for i := len(all) - 1; i >= 0; i-- {
		e := &all[i]
		if !f.match(e, true) {
			continue
		}
		res.Total++
		if before != 0 && e.Seq >= before {
			continue
		}
		if len(res.Items) < limit {
			res.Items = append(res.Items, *e)
		} else if res.Next == 0 {
			res.Next = res.Items[len(res.Items)-1].Seq
		}
	}
	return res
}

// Count is a label and how often it occurred
type Count struct {
	Key string `json:"key"`
	N   int    `json:"n"`
}

// Bucket is the number of blocked requests in one hour
type Bucket struct {
	Hour int64 `json:"hour"` // unix seconds at the start of the hour
	N    int   `json:"n"`
}

// Summary explains the log
type Summary struct {
	Total      int               `json:"total"`
	Reasons    []Count           `json:"reasons"`
	TopIPs     []Count           `json:"topIPs"`
	TopHosts   []Count           `json:"topHosts"`
	TopPaths   []Count           `json:"topPaths"`
	Hourly     []Bucket          `json:"hourly"` // last 24 hours, oldest first
	Oldest     int64             `json:"oldest"` // oldest entry in the log (unix seconds, 0 = empty)
	Newest     int64             `json:"newest"`
	Capacity   int               `json:"capacity"`
	Kept       int               `json:"kept"`
	Recorded   uint64            `json:"recorded"` // since the process started
	Enabled    bool              `json:"enabled"`
	Truncated  bool              `json:"truncated"` // the log is full: older blocked requests have been discarded
	ExclBlock  bool              `json:"excludeBlocked"`
	SinceStart map[string]uint64 `json:"sinceStart"`
}

func top(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Summarize counts the entries that match f (the Reason field of f is ignored so the breakdown
// stays complete while one reason is selected)
func (l *Log) Summarize(f Filter, now time.Time) Summary {
	l.mu.RLock()
	all := l.snapshotLocked()
	s := Summary{Capacity: len(l.ring), Kept: l.count, Recorded: l.recorded, Enabled: l.enabled.Load(),
		Truncated: l.count == len(l.ring), SinceStart: map[string]uint64{}}
	for k, v := range l.byReason {
		s.SinceStart[k] = v
	}
	l.mu.RUnlock()
	s.ExclBlock = l.ExcludesBlocked()

	reasons, ips, hosts, paths := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	hourStart := now.Truncate(time.Hour).Unix()
	first := hourStart - 23*3600
	s.Hourly = make([]Bucket, 24)
	for i := range s.Hourly {
		s.Hourly[i].Hour = first + int64(i)*3600
	}
	for i := range all {
		e := &all[i]
		if s.Oldest == 0 || e.Time < s.Oldest {
			s.Oldest = e.Time
		}
		if e.Time > s.Newest {
			s.Newest = e.Time
		}
		if !f.match(e, false) {
			continue
		}
		s.Total++
		reasons[e.Reason]++
		ips[e.IP]++
		hosts[e.Host]++
		paths[e.Path]++
		if e.Time >= first {
			if idx := int((e.Time - first) / 3600); idx >= 0 && idx < 24 {
				s.Hourly[idx].N++
			}
		}
	}
	s.Reasons = top(reasons, 50)
	s.TopIPs, s.TopHosts, s.TopPaths = top(ips, 10), top(hosts, 10), top(paths, 10)
	return s
}

// Clear erases the log
func (l *Log) Clear() {
	l.mu.Lock()
	l.next, l.count = 0, 0
	for i := range l.ring {
		l.ring[i] = Entry{}
	}
	l.byReason = map[string]uint64{}
	l.byRef = map[string]uint64{}
	l.dirty = true
	l.mu.Unlock()
}

type fileFormat struct {
	Version int     `json:"v"`
	Saved   int64   `json:"saved"`
	Seq     uint64  `json:"seq"`
	Entries []Entry `json:"entries"`
}

// Start loads the persisted entries and runs the periodic save
func (l *Log) Start() {
	if l.started {
		return
	}
	l.started = true
	l.load()
	go func() {
		defer close(l.done)
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				l.Save()
			case <-l.stop:
				l.Save()
				return
			}
		}
	}()
}

// Close persists and stops
func (l *Log) Close() {
	if !l.started {
		return
	}
	l.started = false
	close(l.stop)
	<-l.done
}

// Save writes the log (atomic replace) when it changed
func (l *Log) Save() error {
	if l.file == "" {
		return nil
	}
	l.mu.Lock()
	if !l.dirty {
		l.mu.Unlock()
		return nil
	}
	ff := fileFormat{Version: fileVersion, Saved: time.Now().Unix(), Seq: l.seq, Entries: l.snapshotLocked()}
	l.dirty = false
	l.mu.Unlock()

	fail := func(err error) error {
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
		return err
	}
	raw, err := json.Marshal(&ff)
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(l.file), 0o700); err != nil {
		return fail(err)
	}
	tmp := l.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fail(err)
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
		return fail(err)
	}
	if err := os.Rename(tmp, l.file); err != nil {
		return fail(err)
	}
	return nil
}

func (l *Log) load() {
	if l.file == "" {
		return
	}
	f, err := os.Open(l.file)
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
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := ff.Entries
	if len(entries) > len(l.ring) {
		entries = entries[len(entries)-len(l.ring):]
	}
	for _, e := range entries {
		if e.Ref != "" {
			e.Ref = NormalizeRef(e.Ref)
		}
		if e.Ref != "" {
			l.byRef[e.Ref] = e.Seq
		}
		l.ring[l.next] = e
		l.next = (l.next + 1) % len(l.ring)
		if l.count < len(l.ring) {
			l.count++
		}
	}
	l.seq = ff.Seq
}
