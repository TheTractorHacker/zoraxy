package blocklistimport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/access"
)

const (
	// MinIntervalMinutes keeps scheduled refreshes polite towards list providers
	MinIntervalMinutes = 15
	// MaxIntervalMinutes is one week
	MaxIntervalMinutes = 7 * 24 * 60
	// MaxSources bounds the number of URL sources
	MaxSources = 50
)

// Source is a URL blocklist attached to one access rule list
type Source struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	RuleID          string `json:"ruleId"`
	List            string `json:"list"` //blacklist or whitelist
	URL             string `json:"url"`
	IntervalMinutes int    `json:"intervalMinutes"` //0 = manual refresh only
	Enabled         bool   `json:"enabled"`         //scheduled refresh on/off

	LastRun      int64  `json:"lastRun"`
	LastSuccess  int64  `json:"lastSuccess"`
	LastError    string `json:"lastError"`
	LastAccepted int    `json:"lastAccepted"`
	LastRemoved  int    `json:"lastRemoved"`
	EntryCount   int    `json:"entryCount"`
}

// Manager stores the URL sources and runs the scheduled refresh
type Manager struct {
	path    string
	getRule func(id string) (*access.AccessRule, error)
	Fetcher *Fetcher

	mu      sync.Mutex
	sources map[string]*Source
	running map[string]bool

	stop chan struct{}
	done chan struct{}
	now  func() time.Time
}

// NewManager loads the sources from path (created on first save)
func NewManager(path string, getRule func(id string) (*access.AccessRule, error)) (*Manager, error) {
	m := &Manager{
		path: path, getRule: getRule, Fetcher: &Fetcher{},
		sources: map[string]*Source{}, running: map[string]bool{}, now: time.Now,
	}
	b, err := os.ReadFile(path)
	if err == nil {
		var list []*Source
		if err := json.Unmarshal(b, &list); err != nil {
			return nil, err
		}
		for _, s := range list {
			if s != nil && s.ID != "" {
				m.sources[s.ID] = s
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

func (m *Manager) saveLocked() error {
	list := make([]*Source, 0, len(m.sources))
	for _, s := range m.sources {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func newID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// List returns a copy of the sources, optionally only those of a rule
func (m *Manager) List(ruleID string) []Source {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Source{}
	for _, s := range m.sources {
		if ruleID == "" || s.RuleID == ruleID {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name || (out[i].Name == out[j].Name && out[i].ID < out[j].ID)
	})
	return out
}

// Get returns one source
func (m *Manager) Get(id string) (Source, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sources[id]
	if !ok {
		return Source{}, false
	}
	return *s, true
}

func validInterval(n int) error {
	if n == 0 {
		return nil
	}
	if n < MinIntervalMinutes || n > MaxIntervalMinutes {
		return errors.New("refresh interval must be 0 (manual) or between 15 minutes and 7 days")
	}
	return nil
}

// Add registers a new URL source (does not download yet)
func (m *Manager) Add(s Source) (Source, error) {
	if _, err := kindOf(s.List); err != nil {
		return Source{}, err
	}
	if _, err := ValidateURL(s.URL); err != nil {
		return Source{}, err
	}
	if err := validInterval(s.IntervalMinutes); err != nil {
		return Source{}, err
	}
	if _, err := m.getRule(s.RuleID); err != nil {
		return Source{}, err
	}
	s.Name = CleanComment(s.Name)
	if s.Name == "" {
		s.Name = "import"
	}
	s.Enabled = s.Enabled && s.IntervalMinutes > 0
	s.LastRun, s.LastSuccess, s.LastError, s.LastAccepted, s.LastRemoved, s.EntryCount = 0, 0, "", 0, 0, 0

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sources) >= MaxSources {
		return Source{}, errors.New("too many sources")
	}
	for {
		s.ID = newID()
		if _, exists := m.sources[s.ID]; !exists {
			break
		}
	}
	cp := s
	m.sources[s.ID] = &cp
	if err := m.saveLocked(); err != nil {
		delete(m.sources, s.ID)
		return Source{}, err
	}
	return s, nil
}

// Update changes the schedule of a source
func (m *Manager) Update(id string, intervalMinutes int, enabled bool, name string) error {
	if err := validInterval(intervalMinutes); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sources[id]
	if !ok {
		return errors.New("source not found")
	}
	s.IntervalMinutes = intervalMinutes
	s.Enabled = enabled && intervalMinutes > 0
	if n := CleanComment(name); n != "" {
		s.Name = n
	}
	return m.saveLocked()
}

// Remove deletes a source; with removeEntries the entries it added are removed too
func (m *Manager) Remove(id string, removeEntries bool) (int, error) {
	m.mu.Lock()
	s, ok := m.sources[id]
	if !ok {
		m.mu.Unlock()
		return 0, errors.New("source not found")
	}
	if m.running[id] {
		m.mu.Unlock()
		return 0, errors.New("source is being refreshed, try again")
	}
	cp := *s
	m.mu.Unlock()

	removed := 0
	if removeEntries {
		if rule, err := m.getRule(cp.RuleID); err == nil {
			n, err := RemoveSourceEntries(rule, cp.List, cp.ID)
			if err != nil {
				return 0, err
			}
			removed = n
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sources, id)
	return removed, m.saveLocked()
}

// Refresh downloads the source and replaces the entries it previously added
// (and only those). Failures keep the existing entries untouched.
func (m *Manager) Refresh(ctx context.Context, id string) (*Report, error) {
	m.mu.Lock()
	s, ok := m.sources[id]
	if !ok {
		m.mu.Unlock()
		return nil, errors.New("source not found")
	}
	if m.running[id] {
		m.mu.Unlock()
		return nil, errors.New("refresh already running")
	}
	m.running[id] = true
	src := *s
	m.mu.Unlock()

	rep, err := m.doRefresh(ctx, src)

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.running, id)
	if cur, ok := m.sources[id]; ok {
		cur.LastRun = m.now().Unix()
		if err != nil {
			cur.LastError = err.Error()
		} else {
			cur.LastError = ""
			cur.LastSuccess = cur.LastRun
			cur.LastAccepted = rep.Accepted
			cur.LastRemoved = rep.Removed
			cur.EntryCount = rep.ListSizeAfter //refined below
		}
		if err == nil {
			if rule, rerr := m.getRule(cur.RuleID); rerr == nil {
				cur.EntryCount = CountSourceEntries(rule, cur.List, cur.ID)
			}
		}
		m.saveLocked()
	}
	return rep, err
}

func (m *Manager) doRefresh(ctx context.Context, src Source) (*Report, error) {
	rule, err := m.getRule(src.RuleID)
	if err != nil {
		return nil, err
	}
	body, err := m.Fetcher.Fetch(ctx, src.URL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	// Comments inside remote files are not trusted/kept; entries carry the source name
	parsed, err := Parse(body, 0, src.Name, false)
	if err != nil {
		return nil, err
	}
	return Apply(rule, src.List, parsed, src.ID)
}

// Start runs the scheduler: every minute due sources (enabled, interval > 0) are refreshed
func (m *Manager) Start() {
	m.mu.Lock()
	if m.stop != nil {
		m.mu.Unlock()
		return
	}
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	stop, done := m.stop, m.done
	m.mu.Unlock()
	go func() {
		defer close(done)
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				m.RunDue(context.Background())
			}
		}
	}()
}

// Stop stops the scheduler
func (m *Manager) Stop() {
	m.mu.Lock()
	stop, done := m.stop, m.done
	m.stop, m.done = nil, nil
	m.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
}

// RunDue refreshes every source whose interval has elapsed and returns the ids refreshed
func (m *Manager) RunDue(ctx context.Context) []string {
	now := m.now()
	var due []string
	m.mu.Lock()
	for id, s := range m.sources {
		if s.Enabled && s.IntervalMinutes > 0 && !m.running[id] &&
			now.Sub(time.Unix(s.LastRun, 0)) >= time.Duration(s.IntervalMinutes)*time.Minute {
			due = append(due, id)
		}
	}
	m.mu.Unlock()
	sort.Strings(due)
	for _, id := range due {
		c, cancel := context.WithTimeout(ctx, 2*time.Minute)
		m.Refresh(c, id)
		cancel()
	}
	return due
}

// TagOf exposes the tag of a source for the UI
func TagOf(id string) string { return strings.TrimSpace(Tag(id)) }
