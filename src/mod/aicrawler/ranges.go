package aicrawler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxPrefixesPerSource = 20000
	maxPrefixLen         = 64
)

// stored form of one list
type storedSet struct {
	Fetched  int64    `json:"fetched"` // unix seconds
	Prefixes []string `json:"prefixes"`
}

type parsedSet struct {
	fetched  time.Time
	prefixes []netip.Prefix
}

// RangeStore holds the published address ranges of the crawlers. It is filled only by an explicit
// refresh (or by SetPrefixes in tests / by an import) and cached on disk; nothing is fetched at start-up.
type RangeStore struct {
	mu   sync.RWMutex
	path string
	sets map[string]*parsedSet
}

// NewRangeStore creates a store; path "" = memory only
func NewRangeStore(path string) *RangeStore {
	return &RangeStore{path: path, sets: map[string]*parsedSet{}}
}

// Load reads the cache file (a missing file is an empty store)
func (s *RangeStore) Load() error {
	if s.path == "" {
		return nil
	}
	js, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}
	var raw struct {
		Sets map[string]storedSet `json:"sets"`
	}
	if err := json.Unmarshal(js, &raw); err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, src := range Sources() {
		allowed[src.ID] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, set := range raw.Sets {
		if !allowed[id] {
			continue // a source that is no longer in the allow-list is dropped
		}
		ps, err := parsePrefixList(set.Prefixes)
		if err != nil {
			continue
		}
		s.sets[id] = &parsedSet{fetched: time.Unix(set.Fetched, 0), prefixes: ps}
	}
	return nil
}

func (s *RangeStore) save() error {
	if s.path == "" {
		return nil
	}
	raw := struct {
		Sets map[string]storedSet `json:"sets"`
	}{map[string]storedSet{}}
	for id, set := range s.sets {
		list := make([]string, len(set.prefixes))
		for i, p := range set.prefixes {
			list[i] = p.String()
		}
		raw.Sets[id] = storedSet{Fetched: set.fetched.Unix(), Prefixes: list}
	}
	js, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, js)
}

func parsePrefixList(in []string) ([]netip.Prefix, error) {
	if len(in) > maxPrefixesPerSource {
		return nil, fmt.Errorf("more than %d prefixes", maxPrefixesPerSource)
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || len(p) > maxPrefixLen {
			return nil, errors.New("invalid prefix")
		}
		if !strings.Contains(p, "/") {
			a, err := netip.ParseAddr(p)
			if err != nil {
				return nil, fmt.Errorf("invalid prefix %q", p)
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		pf, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q", p)
		}
		out = append(out, pf.Masked())
	}
	return out, nil
}

// SetPrefixes replaces the list of one source (validated) and persists the cache
func (s *RangeStore) SetPrefixes(id string, prefixes []string, fetched time.Time) error {
	ps, err := parsePrefixList(prefixes)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.sets[id] = &parsedSet{fetched: fetched, prefixes: ps}
	err = s.save()
	s.mu.Unlock()
	return err
}

// Has reports whether data for the source is loaded
func (s *RangeStore) Has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := s.sets[id]
	return set != nil && len(set.prefixes) > 0
}

// Contains reports whether ip is inside any loaded range of the sources, and whether any of them had data.
func (s *RangeStore) Contains(sources []string, ip netip.Addr) (inside, hadData bool) {
	ip = ip.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, id := range sources {
		set := s.sets[id]
		if set == nil || len(set.prefixes) == 0 {
			continue
		}
		hadData = true
		for _, p := range set.prefixes {
			if p.Contains(ip) {
				return true, true
			}
		}
	}
	return false, hadData
}

// SourceStatus is the state of one list for the UI
type SourceStatus struct {
	ID      string   `json:"id"`
	URL     string   `json:"url"`
	Loaded  bool     `json:"loaded"`
	Count   int      `json:"count"`
	Fetched int64    `json:"fetched,omitempty"`
	UsedBy  []string `json:"usedBy"`
}

// Status lists every allow-listed source with its state
func (s *RangeStore) Status() []SourceStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []SourceStatus{}
	for _, src := range Sources() {
		st := SourceStatus{ID: src.ID, URL: src.URL, UsedBy: []string{}}
		for _, e := range registry {
			for _, id := range e.Verify.RangeSources {
				if id == src.ID {
					st.UsedBy = append(st.UsedBy, e.Name)
				}
			}
		}
		if set := s.sets[src.ID]; set != nil && len(set.prefixes) > 0 {
			st.Loaded, st.Count, st.Fetched = true, len(set.prefixes), set.fetched.Unix()
		}
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ParseRangeJSON extracts the prefixes of a published list. It accepts the shapes the operators use:
// {"prefixes":[{"ipv4Prefix":"..."},{"ipv6Prefix":"..."}]} (also ip_prefix / ipv6_prefix / cidr / prefix),
// a top-level array of such objects or of plain strings. Anything else is an error: a list that parses to
// nothing must never replace a good one.
func ParseRangeJSON(js []byte) ([]string, error) {
	var top interface{}
	if err := json.Unmarshal(js, &top); err != nil {
		return nil, errors.New("the answer is not JSON")
	}
	var list []interface{}
	switch v := top.(type) {
	case []interface{}:
		list = v
	case map[string]interface{}:
		p, ok := v["prefixes"].([]interface{})
		if !ok {
			return nil, errors.New("the JSON has no prefixes list")
		}
		list = p
	default:
		return nil, errors.New("unexpected JSON shape")
	}
	out := []string{}
	for _, it := range list {
		switch v := it.(type) {
		case string:
			out = append(out, v)
		case map[string]interface{}:
			for _, k := range []string{"ipv4Prefix", "ipv6Prefix", "ip_prefix", "ipv6_prefix", "cidr", "prefix"} {
				if s, ok := v[k].(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
		if len(out) > maxPrefixesPerSource {
			return nil, fmt.Errorf("more than %d prefixes", maxPrefixesPerSource)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("the list contains no prefixes")
	}
	if _, err := parsePrefixList(out); err != nil {
		return nil, err
	}
	return out, nil
}
