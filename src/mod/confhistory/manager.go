package confhistory

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var errTooLarge = errors.New("configuration is too large to snapshot")

// Options configures a Manager.
type Options struct {
	ConfDir  string
	DB       KV        // sys.db; nil disables the table export
	Registry *Registry // nil: DefaultRegistry()
	Debounce time.Duration
	// MaxWait bounds how long a continuous burst can postpone a capture.
	MaxWait time.Duration
	Now     func() time.Time
	Logf    func(format string, a ...any)
	// Reload makes the process pick up restored files (Zoraxy restarts itself).
	Reload func() error
	// Validate runs the loaders' own validators on a file that is about to be
	// restored. Optional.
	Validate func(rel string, data []byte) error
	// Managed returns a non empty reason when a hub or primary owns the file
	// (restore skips it). Optional.
	Managed func(rel string) string
	// Actor names the admin behind an API request (nil: "admin").
	Actor func(r *http.Request) string
	// HealthyAfter is how long a restarted process must stay up to confirm a
	// restore (default 20 s).
	HealthyAfter time.Duration
}

// Manager is the configuration history.
type Manager struct {
	opt  Options
	reg  *Registry
	seal *sealer

	mu       sync.Mutex // serialises every store access and restore
	idx      *index
	settings Settings
	hold     map[int64]bool //versions a running restore depends on

	pmu       sync.Mutex // debounce state
	timer     *time.Timer
	burstAt   time.Time
	actors    []string
	summaries []string
	lastPre   time.Time

	// test hooks: fail a restore stage on purpose
	failAt map[string]error
}

// New opens (and if needed creates) the store.
func New(opt Options) (*Manager, error) {
	if opt.ConfDir == "" {
		return nil, errors.New("confhistory: conf dir required")
	}
	if opt.Registry == nil {
		opt.Registry = DefaultRegistry()
	}
	if opt.Debounce <= 0 {
		opt.Debounce = 2 * time.Second
	}
	if opt.MaxWait <= 0 {
		opt.MaxWait = 10 * time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.HealthyAfter <= 0 {
		opt.HealthyAfter = 20 * time.Second
	}
	m := &Manager{opt: opt, reg: opt.Registry, hold: map[int64]bool{}, settings: DefaultSettings(), failAt: map[string]error{}}
	var err error
	m.seal, err = loadOrCreateKey(m.dir("history.key"))
	if err != nil {
		return nil, err
	}
	if raw, err := os.ReadFile(m.dir(settingsFile)); err == nil {
		var s Settings
		if json.Unmarshal(raw, &s) == nil && s.Validate() == nil {
			m.settings = s
		}
	}
	return m, nil
}

// Registry exposes the registry so other modules can register roots and tables.
func (m *Manager) Registry() *Registry { return m.reg }

func (m *Manager) now() time.Time { return m.opt.Now() }

// Settings returns the retention settings.
func (m *Manager) Settings() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

// SetSettings validates and stores the retention settings and prunes.
func (m *Manager) SetSettings(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, _ := json.Marshal(s)
	if err := writeAtomic(m.dir(settingsFile), raw, 0o600); err != nil {
		return err
	}
	m.settings = s
	m.pruneLocked()
	return nil
}

// CaptureInfo describes why a snapshot is taken.
type CaptureInfo struct {
	Actor   string
	Trigger string
	Summary string
}

// Capture stores the current configuration as a new version. It returns the
// newest version and false when nothing changed since it.
func (m *Manager) Capture(ci CaptureInfo) (Meta, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.captureLocked(ci)
}

func (m *Manager) captureLocked(ci CaptureInfo) (Meta, bool, error) {
	if !m.settings.Enabled && ci.Trigger != "pre-restore" && ci.Trigger != "manual" {
		return Meta{}, false, errors.New("configuration history is disabled")
	}
	idx, err := m.loadIndexLocked()
	if err != nil {
		return Meta{}, false, err
	}
	st, _, err := m.collect()
	if err != nil {
		return Meta{}, false, err
	}
	mf := manifest{}
	var bytes int64
	for p, e := range st {
		name := m.seal.name(e.Data)
		mf[p] = manifestEntry{Blob: name, Mode: e.Mode, Size: int64(len(e.Data))}
		bytes += int64(len(e.Data))
	}
	paths := sortedKeys(mf)
	parts := make([]string, 0, len(paths)*2)
	for _, p := range paths {
		parts = append(parts, p, mf[p].Blob)
	}
	hash := m.seal.nameOf(parts...)

	var prev manifest
	if n := len(idx.Versions); n > 0 {
		last := idx.Versions[n-1]
		if last.Hash == hash {
			return last, false, nil
		}
		if prev, err = m.loadManifest(last.ID); err != nil {
			prev = nil //damaged predecessor: record everything as added rather than failing
			m.opt.Logf("[history] previous version unreadable (%v); recording a full snapshot", err)
		}
	}
	for _, p := range paths {
		if err := m.putBlob(mf[p].Blob, st[p].Data); err != nil {
			return Meta{}, false, err
		}
	}
	id := idx.NextID
	if err := m.saveManifest(id, mf); err != nil {
		return Meta{}, false, err
	}
	meta := Meta{
		ID: id, Time: m.now().Unix(), Actor: trim(ci.Actor, 64), Trigger: ci.Trigger, Summary: trim(ci.Summary, 200),
		Hash: hash, Files: len(mf), Bytes: bytes, Changes: m.diffManifests(prev, mf),
	}
	if meta.Trigger == "" {
		meta.Trigger = "api"
	}
	if meta.Summary == "" {
		meta.Summary = summarizeChanges(meta.Changes)
	}
	idx.NextID = id + 1
	idx.Versions = append(idx.Versions, meta)
	if err := m.saveIndexLocked(); err != nil {
		idx.Versions = idx.Versions[:len(idx.Versions)-1]
		idx.NextID = id
		os.Remove(m.manifestPath(id))
		return Meta{}, false, err
	}
	m.pruneLocked()
	return meta, true, nil
}

func (m *Manager) diffManifests(prev, cur manifest) []Change {
	var out []Change
	for _, p := range sortedKeys(cur) {
		pe, ok := prev[p]
		switch {
		case !ok:
			out = append(out, m.change(p, "added"))
		case pe.Blob != cur[p].Blob:
			out = append(out, m.change(p, "changed"))
		}
	}
	for _, p := range sortedKeys(prev) {
		if _, ok := cur[p]; !ok {
			out = append(out, m.change(p, "removed"))
		}
	}
	return out
}

func (m *Manager) change(p, kind string) Change {
	return Change{Path: p, Area: m.reg.AreaOf(p), Kind: kind, Label: m.Label(p)}
}

func summarizeChanges(ch []Change) string {
	switch len(ch) {
	case 0:
		return "No changes"
	case 1:
		return "Changed " + ch[0].Label
	}
	return fmt.Sprintf("Changed %s and %d more", ch[0].Label, len(ch)-1)
}

// Label gives a path a friendly name ("Proxy rule example.com").
func (m *Manager) Label(p string) string {
	if t, ok := strings.CutPrefix(p, dbPrefix); ok {
		return "Settings table " + t
	}
	base := p[strings.LastIndex(p, "/")+1:]
	stem := strings.TrimSuffix(strings.TrimSuffix(base, ".config"), ".json")
	switch m.reg.AreaOf(p) {
	case "proxy":
		return "Proxy rule " + stem
	case "redirect":
		return "Redirect " + stem
	case "access":
		return "Access " + stem
	case "streams":
		return "Stream proxy " + stem
	case "pathrules":
		return "Path rule " + stem
	case "certs":
		return "Certificate file " + base
	}
	return base
}

func trim(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// ---------------------------------------------------------------- debounce

// Notify records that a request changed (or may have changed) the
// configuration. Calls within the debounce window share one version.
func (m *Manager) Notify(actor, summary string) {
	m.pmu.Lock()
	defer m.pmu.Unlock()
	m.actors = appendUnique(m.actors, actor)
	m.summaries = appendUnique(m.summaries, summary)
	now := time.Now() //debounce timers run on the wall clock
	if m.timer == nil {
		m.burstAt = now
		m.timer = time.AfterFunc(m.opt.Debounce, m.fire)
		return
	}
	wait := m.opt.Debounce
	if left := m.opt.MaxWait - now.Sub(m.burstAt); left < wait {
		if left < 0 {
			left = 0
		}
		wait = left
	}
	m.timer.Reset(wait)
}

func appendUnique(l []string, s string) []string {
	if s == "" {
		return l
	}
	for _, e := range l {
		if e == s {
			return l
		}
	}
	return append(l, s)
}

// Pending reports whether a debounced capture is waiting.
func (m *Manager) Pending() bool {
	m.pmu.Lock()
	defer m.pmu.Unlock()
	return m.timer != nil
}

func (m *Manager) takeBatch() (CaptureInfo, bool) {
	m.pmu.Lock()
	defer m.pmu.Unlock()
	if m.timer == nil {
		return CaptureInfo{}, false
	}
	m.timer.Stop()
	m.timer = nil
	ci := CaptureInfo{Trigger: "api", Actor: strings.Join(m.actors, ", ")}
	switch len(m.summaries) {
	case 0:
	case 1:
		ci.Summary = m.summaries[0]
	default:
		ci.Summary = fmt.Sprintf("%s (+%d more changes)", m.summaries[0], len(m.summaries)-1)
	}
	m.actors, m.summaries = nil, nil
	return ci, true
}

func (m *Manager) fire() {
	ci, ok := m.takeBatch()
	if !ok {
		return
	}
	if _, _, err := m.Capture(ci); err != nil {
		m.opt.Logf("[history] snapshot failed: %v", err)
	}
}

// Flush captures a waiting debounced batch immediately (shutdown, tests).
func (m *Manager) Flush() {
	m.fire()
}

// PreChange is called before a configuration changing request runs. When the
// configuration drifted since the newest version (edited on disk, renewed
// certificates...) that state is recorded first, so "undo" returns to exactly
// the state before the request.
func (m *Manager) PreChange() {
	m.pmu.Lock()
	skip := m.timer != nil || time.Since(m.lastPre) < time.Second
	m.lastPre = time.Now()
	m.pmu.Unlock()
	if skip {
		return
	}
	m.captureDrift()
}

func (m *Manager) captureDrift() {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, err := m.loadIndexLocked()
	if err != nil || !m.settings.Enabled {
		return
	}
	ci := CaptureInfo{Actor: "system", Trigger: "external", Summary: "Changes made outside the admin UI (or by renewals)"}
	if len(idx.Versions) == 0 {
		ci.Trigger, ci.Summary = "baseline", "Starting point: configuration before the first recorded change"
	}
	if _, _, err := m.captureLocked(ci); err != nil {
		m.opt.Logf("[history] snapshot failed: %v", err)
	}
}

// Start records the baseline (or drift since the last run). Call it once the
// modules are loaded; it also removes stale restore working folders.
func (m *Manager) Start() {
	m.cleanStale()
	m.captureDrift()
}

// ---------------------------------------------------------------- queries

// Filter selects versions for List.
type Filter struct {
	Object   string // substring of a changed path or label
	Actor    string
	From, To int64 // unix seconds, 0 = open
	Page     int
	PageSize int
}

// ListResult is a page of versions, newest first.
type ListResult struct {
	Items    []Meta `json:"items"`
	Total    int    `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"pageSize"`
}

// List returns versions matching f, newest first.
func (m *Manager) List(f Filter) (ListResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, err := m.loadIndexLocked()
	if err != nil {
		return ListResult{}, err
	}
	if f.PageSize <= 0 || f.PageSize > 200 {
		f.PageSize = 25
	}
	if f.Page < 1 {
		f.Page = 1
	}
	obj, act := strings.ToLower(f.Object), strings.ToLower(f.Actor)
	var all []Meta
	for _, v := range idx.Versions {
		if f.From > 0 && v.Time < f.From || f.To > 0 && v.Time > f.To {
			continue
		}
		if act != "" && !strings.Contains(strings.ToLower(v.Actor), act) {
			continue
		}
		if obj != "" {
			hit := strings.Contains(strings.ToLower(v.Summary), obj)
			for _, c := range v.Changes {
				if strings.Contains(strings.ToLower(c.Path), obj) || strings.Contains(strings.ToLower(c.Label), obj) {
					hit = true
				}
			}
			if !hit {
				continue
			}
		}
		all = append(all, v)
	}
	sortMetaDesc(all)
	res := ListResult{Total: len(all), Page: f.Page, PageSize: f.PageSize}
	lo := (f.Page - 1) * f.PageSize
	if lo < len(all) {
		hi := lo + f.PageSize
		if hi > len(all) {
			hi = len(all)
		}
		res.Items = all[lo:hi]
	}
	if res.Items == nil {
		res.Items = []Meta{}
	}
	return res, nil
}

// Get returns one version's metadata.
func (m *Manager) Get(id int64) (Meta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getLocked(id)
}

func (m *Manager) getLocked(id int64) (Meta, error) {
	idx, err := m.loadIndexLocked()
	if err != nil {
		return Meta{}, err
	}
	for _, v := range idx.Versions {
		if v.ID == id {
			return v, nil
		}
	}
	return Meta{}, fmt.Errorf("version %d does not exist (it may have been pruned)", id)
}

// Previous returns the id of the version before id (0 if none).
func (m *Manager) Previous(id int64) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, err := m.loadIndexLocked()
	if err != nil {
		return 0
	}
	var prev int64
	for _, v := range idx.Versions {
		if v.ID == id {
			return prev
		}
		prev = v.ID
	}
	return 0
}

// LastRestore returns the outcome of the most recent restore.
func (m *Manager) LastRestore() *RestoreRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, err := m.loadIndexLocked()
	if err != nil || idx.LastRestore == nil {
		return nil
	}
	c := *idx.LastRestore
	return &c
}

// Count returns how many versions are stored.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, err := m.loadIndexLocked()
	if err != nil {
		return 0
	}
	return len(idx.Versions)
}

// Latest returns the id of the newest version (0 when there is none)
func (m *Manager) Latest() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, err := m.loadIndexLocked()
	if err != nil || len(idx.Versions) == 0 {
		return 0
	}
	return idx.Versions[len(idx.Versions)-1].ID
}

// IDs returns all version ids ascending (tests).
func (m *Manager) IDs() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, _ := m.loadIndexLocked()
	if idx == nil {
		return nil
	}
	out := make([]int64, 0, len(idx.Versions))
	for _, v := range idx.Versions {
		out = append(out, v.ID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
