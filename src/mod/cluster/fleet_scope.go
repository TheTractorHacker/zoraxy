package cluster

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

/*
	Scope registry (Fleet / central management)

	A scope is one kind of configuration the hub can manage centrally. The
	hub decides per group or node which scopes are managed. Everything not
	managed stays node local and is never touched.

	The built-in scopes are file based: they own a few roots of the conf
	folder. Other scopes (for example the central WAF policy, which lives in
	the settings database) implement the same interface and are added with
	RegisterScope; they exchange their data as FileEntry items whose paths
	are private to the scope (use a "<scope>:" prefix, such as
	"waf:policy.json") and persist them in Apply through ScopePlan.Commit.
*/

// Selection says which parts of a scope a node manages.
type Selection struct {
	// ProxyTags limits the "proxy" scope to rules carrying at least one of
	// these tags. Empty = all proxy rules.
	ProxyTags []string `json:"proxyTags,omitempty"`
}

// ScopeEnv gives a scope access to the node or hub it runs on.
type ScopeEnv struct {
	ConfDir string
}

// ScopePlan is what Apply decided for a node.
type ScopePlan struct {
	// Roots are the conf roots this plan rewrites (file scopes). The install is
	// atomic across all scopes of one apply.
	Roots []string
	// Files is the complete final content of Roots after the apply, which for a
	// merging scope includes node local files that are kept.
	Files []FileEntry
	// ManagedKeys are the object keys (conf relative paths) now owned by the hub.
	ManagedKeys []string
	// Conflicts lists local objects with the same key that the hub replaced.
	Conflicts []Conflict
	// Commit persists non file state (after the files were installed, before
	// the reload). Undo is called if anything after Commit fails.
	Commit func() error
	Undo   func()
}

// Conflict reports a node local object that the hub replaced ("hub wins").
type Conflict struct {
	Scope string `json:"scope"`
	Key   string `json:"key"`
}

// Scope is a pluggable unit of centrally managed configuration.
type Scope interface {
	Name() string
	Label() string
	// Export returns the scope's items from the hub's own state, filtered by sel.
	Export(env *ScopeEnv, sel Selection) ([]FileEntry, error)
	// Validate checks items against the scope's schema. It runs on the hub when
	// publishing and again on the node before anything is written.
	Validate(items []FileEntry) error
	// Apply computes the node side result of installing items. prevManaged is
	// the set of keys the hub owned after the previous apply (so objects the hub
	// no longer publishes can be removed without touching local ones).
	Apply(env *ScopeEnv, items []FileEntry, prevManaged []string) (*ScopePlan, error)
	// OwnsPath reports whether an item path belongs to this scope.
	OwnsPath(p string) bool
}

var (
	scopeMu  sync.RWMutex
	scopeReg = map[string]Scope{}
)

// RegisterScope adds a scope. Registering a name twice replaces it, which
// lets the WAF branch register its scope from its own init.
func RegisterScope(s Scope) {
	scopeMu.Lock()
	scopeReg[s.Name()] = s
	scopeMu.Unlock()
}

// UnregisterScope removes a scope (tests).
func UnregisterScope(name string) {
	scopeMu.Lock()
	delete(scopeReg, name)
	scopeMu.Unlock()
}

// GetScope looks a scope up by name.
func GetScope(name string) (Scope, bool) {
	scopeMu.RLock()
	defer scopeMu.RUnlock()
	s, ok := scopeReg[name]
	return s, ok
}

// ScopeNames lists the registered scopes, sorted.
func ScopeNames() []string {
	scopeMu.RLock()
	defer scopeMu.RUnlock()
	out := make([]string, 0, len(scopeReg))
	for n := range scopeReg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ScopeInfo describes a scope for the UI.
type ScopeInfo struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// ScopeList returns names and labels.
func ScopeList() []ScopeInfo {
	var out []ScopeInfo
	for _, n := range ScopeNames() {
		if s, ok := GetScope(n); ok {
			out = append(out, ScopeInfo{n, s.Label()})
		}
	}
	return out
}

// scopeForPath finds the scope that owns an item path.
func scopeForPath(p string) (Scope, bool) {
	for _, n := range ScopeNames() {
		if s, ok := GetScope(n); ok && s.OwnsPath(p) {
			return s, true
		}
	}
	return nil, false
}

// ---------------------------------------------------------------------
// built-in file scopes

func init() {
	RegisterScope(&fileScope{name: "proxy", label: "Proxy rules", roots: []string{"proxy"}, merge: true, kind: "proxy"})
	RegisterScope(&fileScope{name: "redirect", label: "Redirect rules", roots: []string{"redirect"}, kind: "json"})
	RegisterScope(&fileScope{name: "access", label: "Access rules and trusted proxies", roots: []string{"access", "trusted_proxies.json"}, kind: "json"})
	RegisterScope(&fileScope{name: "pathrules", label: "Path blocking rules", roots: []string{"rules"}, kind: "json"})
	RegisterScope(&fileScope{name: "streamproxy", label: "Stream proxy rules", roots: []string{"streamproxy"}, kind: "json"})
	RegisterScope(&fileScope{name: "acme", label: "ACME configuration", roots: []string{"acme_conf.json"}, kind: "json"})
	RegisterScope(&fileScope{name: "ruleset", label: "Rules engine (global and per-site rules, lists)", roots: []string{"ruleset"}, kind: "json"})
	RegisterScope(&fileScope{name: "waf", label: "Central WAF policy and profiles", roots: []string{"waf_central.json"}, kind: "json"})
	RegisterScope(&fileScope{name: "certs", label: "Certificates (private keys are sent to nodes)", roots: []string{certRoot}, kind: "raw"})
}

// fileScope manages a set of conf roots. A merging scope (proxy) keeps node
// local files next to the managed ones; the others own their roots entirely.
type fileScope struct {
	name, label string
	roots       []string
	merge       bool
	kind        string // proxy | json | raw
}

func (s *fileScope) Name() string  { return s.name }
func (s *fileScope) Label() string { return s.label }

func (s *fileScope) OwnsPath(p string) bool {
	for _, r := range s.roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

func (s *fileScope) Export(env *ScopeEnv, sel Selection) ([]FileEntry, error) {
	all, err := CollectFiles(env.ConfDir, true)
	if err != nil {
		return nil, err
	}
	var out []FileEntry
	for _, f := range all.Files {
		if !s.OwnsPath(f.Path) {
			continue
		}
		if s.kind == "proxy" && len(sel.ProxyTags) > 0 && !hasAnyTag(f.Data, sel.ProxyTags) {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

func hasAnyTag(data []byte, want []string) bool {
	var v struct{ Tags []string }
	json.Unmarshal(data, &v)
	have := map[string]bool{}
	for _, t := range v.Tags {
		have[strings.ToLower(strings.TrimSpace(t))] = true
	}
	for _, w := range want {
		if have[strings.ToLower(strings.TrimSpace(w))] {
			return true
		}
	}
	return false
}

func (s *fileScope) Validate(items []FileEntry) error {
	for _, f := range items {
		if !s.OwnsPath(f.Path) {
			return fmt.Errorf("%s: path %q is outside this scope", s.name, f.Path)
		}
		if s.kind != "raw" && (strings.HasSuffix(f.Path, ".json") || strings.HasSuffix(f.Path, ".config")) && !json.Valid(f.Data) {
			return fmt.Errorf("%s: %q is not valid JSON", s.name, f.Path)
		}
	}
	return nil
}

func (s *fileScope) Apply(env *ScopeEnv, items []FileEntry, prevManaged []string) (*ScopePlan, error) {
	plan := &ScopePlan{Roots: append([]string{}, s.roots...)}
	incoming := map[string]bool{}
	for _, f := range items {
		incoming[f.Path] = true
		plan.ManagedKeys = append(plan.ManagedKeys, f.Path)
	}
	sort.Strings(plan.ManagedKeys)
	if !s.merge {
		plan.Files = append(plan.Files, items...) //the hub owns the whole root
		return plan, nil
	}
	// Merging scope: keep local files, replace the hub's, drop what the hub
	// owned before but no longer publishes.
	prev := map[string]bool{}
	for _, k := range prevManaged {
		prev[k] = true
	}
	local, err := CollectFiles(env.ConfDir, true)
	if err != nil {
		return nil, err
	}
	for _, f := range local.Files {
		if !s.OwnsPath(f.Path) {
			continue
		}
		switch {
		case incoming[f.Path]:
			if !prev[f.Path] { //a node local object with the same key: hub wins
				plan.Conflicts = append(plan.Conflicts, Conflict{Scope: s.name, Key: f.Path})
			}
		case prev[f.Path]:
			//was managed, hub dropped it
		default:
			plan.Files = append(plan.Files, f) //node local, keep
		}
	}
	plan.Files = append(plan.Files, items...)
	return plan, nil
}

func validScopeNames(names []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		if _, ok := GetScope(n); !ok {
			return nil, fmt.Errorf("unknown scope %q", n)
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
