// Package confhistory keeps a restorable history of the Zoraxy configuration.
//
// Every successful change made through the admin API (or the REST API v1)
// creates a version: a content addressed, AES-256-GCM sealed copy of the
// allow-listed configuration (conf files plus an export of the settings
// tables of sys.db). Versions can be listed, compared (secrets masked) and
// restored, atomically, with a boot guard that rolls a restore back when the
// restarted process does not become healthy. See DEVELOPMENT.md.
package confhistory

import (
	"path"
	"sort"
	"strings"
	"sync"
)

// Area groups registry items for the UI and for scoped restore.
type Area struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// OptIn areas are never part of a "whole configuration" restore; they
	// must be requested explicitly (certificates: a restore would replace a
	// certificate that was renewed since).
	OptIn bool `json:"optIn,omitempty"`
}

// Root is a file or directory below the conf folder that is part of the
// history. It is the allow-list: nothing outside the registered roots is ever
// read into a version or written by a restore.
type Root struct {
	Path string // slash separated, relative to the conf folder; a file or a directory
	Area string
	// Exts restricts the files of a directory root to these suffixes
	// (empty: any file name that passes the safe name check).
	Exts []string
	// MaxDepth is how many path elements below a directory root are allowed
	// (default 1: files directly inside; 0 or 1 means the same).
	MaxDepth int
	// NoContent hides the content in diffs (certificates and keys); only the
	// fact that the file changed is shown.
	NoContent bool
}

// Table is a settings table of sys.db that holds configuration.
type Table struct {
	Name string
	Area string
	// MaskAll hides every value of the table in diffs.
	MaskAll bool
}

// Registry is the single list of what a version contains. Other modules may
// register their own roots and tables (call Register* before the first
// capture, normally from an init function or the glue code).
type Registry struct {
	mu     sync.RWMutex
	roots  []Root
	tables []Table
	areas  map[string]Area
	order  []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{areas: map[string]Area{}} }

// RegisterArea declares an area (idempotent; the first label wins).
func (r *Registry) RegisterArea(a Area) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.areas[a.ID]; ok {
		return
	}
	r.areas[a.ID] = a
	r.order = append(r.order, a.ID)
}

// RegisterRoot adds a file or directory. Unsafe paths panic: the list is
// code, not user input.
func (r *Registry) RegisterRoot(root Root) {
	if !safeRel(root.Path) || strings.HasPrefix(root.Path, "db/") || root.Path == "db" || strings.HasPrefix(root.Path, ".history") {
		panic("confhistory: unsafe root " + root.Path)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if root.MaxDepth < 1 {
		root.MaxDepth = 1
	}
	r.roots = append(r.roots, root)
}

// RegisterTable adds a sys.db table.
func (r *Registry) RegisterTable(t Table) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tables = append(r.tables, t)
}

// Roots returns a copy of the registered roots.
func (r *Registry) Roots() []Root {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Root(nil), r.roots...)
}

// Tables returns a copy of the registered tables.
func (r *Registry) Tables() []Table {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Table(nil), r.tables...)
}

// Areas returns the areas in registration order.
func (r *Registry) Areas() []Area {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Area, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.areas[id])
	}
	return out
}

// AreaOf returns the area id of an entry path ("" if the path is not covered).
func (r *Registry) AreaOf(p string) string {
	if t, ok := strings.CutPrefix(p, dbPrefix); ok {
		for _, tb := range r.Tables() {
			if tb.Name == t {
				return tb.Area
			}
		}
		return ""
	}
	if root, ok := r.matchFile(p); ok {
		return root.Area
	}
	return ""
}

// IsOptIn reports whether an area is excluded from whole configuration restores.
func (r *Registry) IsOptIn(area string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.areas[area].OptIn
}

// AreaLabel returns the display name of an area.
func (r *Registry) AreaLabel(id string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.areas[id]; ok {
		return a.Label
	}
	return id
}

// NoContent reports whether the diff must not show the content of a path.
func (r *Registry) NoContent(p string) bool {
	if root, ok := r.matchFile(p); ok {
		return root.NoContent
	}
	return false
}

// MaskAll reports whether all values of a db entry path are hidden.
func (r *Registry) MaskAll(p string) bool {
	if t, ok := strings.CutPrefix(p, dbPrefix); ok {
		for _, tb := range r.Tables() {
			if tb.Name == t {
				return tb.MaskAll
			}
		}
	}
	return false
}

// ValidFile is the single gatekeeper for file paths, on the collect side and
// on the restore side: relative, clean, slash separated, no traversal, and
// inside a registered root with an allowed name.
func (r *Registry) ValidFile(p string) bool {
	_, ok := r.matchFile(p)
	return ok
}

// ValidTable reports whether a db entry path names a registered table.
func (r *Registry) ValidTable(p string) bool {
	t, ok := strings.CutPrefix(p, dbPrefix)
	if !ok {
		return false
	}
	for _, tb := range r.Tables() {
		if tb.Name == t {
			return true
		}
	}
	return false
}

// ValidEntry accepts a file or a table path.
func (r *Registry) ValidEntry(p string) bool { return r.ValidFile(p) || r.ValidTable(p) }

const dbPrefix = "db/"

func safeRel(p string) bool {
	if p == "" || len(p) > 300 || strings.ContainsAny(p, "\\\x00") || path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." {
			return false
		}
		for _, c := range s {
			if c < 0x20 || c == 0x7f {
				return false
			}
		}
	}
	return true
}

func (r *Registry) matchFile(p string) (Root, bool) {
	if !safeRel(p) || strings.HasPrefix(p, dbPrefix) {
		return Root{}, false
	}
	parts := strings.Split(p, "/")
	for _, s := range parts {
		if strings.HasPrefix(s, ".") { //hidden files and the history store itself
			return Root{}, false
		}
	}
	for _, root := range r.Roots() {
		if p == root.Path {
			return root, true
		}
		if !strings.HasPrefix(p, root.Path+"/") {
			continue
		}
		rest := strings.TrimPrefix(p, root.Path+"/")
		if len(strings.Split(rest, "/")) > root.MaxDepth {
			continue
		}
		if len(root.Exts) > 0 {
			ok := false
			for _, e := range root.Exts {
				if strings.HasSuffix(rest, e) {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		return root, true
	}
	return Root{}, false
}

// DefaultRegistry builds the registry of Zoraxy itself.
//
// Captured (conf folder): proxy rules, redirects, access rules, stream proxy,
// path rules, trusted proxies, ACME settings, central WAF, bot rules, basic
// auth lists, blocklist sources, notification settings, log settings, auto-ban
// settings, plugin groups, SSO branding and group policies, ECH settings and
// certificates (opt-in). Captured (sys.db): the settings tables listed below (not the dashboard bandwidth counters).
//
// Never captured: logs, statistics, visitors, block log, sessions, caches,
// admin accounts and password hashes (table auth), API tokens (table
// apitokens), OAuth sessions, SSO user databases, the cluster / Fleet state,
// the admin TLS certificate, updater state, GeoIP databases, the WAF challenge
// key, the config version marker and the history store itself.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, a := range []Area{
		{ID: "proxy", Label: "Proxy rules"},
		{ID: "redirect", Label: "Redirect rules"},
		{ID: "access", Label: "Access rules and trusted proxies"},
		{ID: "streams", Label: "Stream proxy"},
		{ID: "pathrules", Label: "Path rules"},
		{ID: "waf", Label: "Web application firewall"},
		{ID: "ruleset", Label: "Rules engine (WHEN / THEN rules and lists)"},
		{ID: "security", Label: "Bot rules, AI crawler policy, basic auth lists, blocklists, auto-ban"},
		{ID: "acme", Label: "ACME and certificate settings"},
		{ID: "sso", Label: "Single sign-on"},
		{ID: "notify", Label: "Notifications"},
		{ID: "logging", Label: "Logging"},
		{ID: "plugins", Label: "Plugins"},
		{ID: "ech", Label: "Encrypted Client Hello"},
		{ID: "settings", Label: "Global settings"},
		{ID: "certs", Label: "Certificates and private keys", OptIn: true},
	} {
		r.RegisterArea(a)
	}
	for _, root := range []Root{
		{Path: "proxy", Area: "proxy", Exts: []string{".config"}},
		{Path: "redirect", Area: "redirect", MaxDepth: 2},
		{Path: "access", Area: "access", Exts: []string{".json"}},
		{Path: "streamproxy", Area: "streams", MaxDepth: 2},
		{Path: "rules", Area: "pathrules", MaxDepth: 3},
		{Path: "ruleset", Area: "ruleset", Exts: []string{".json"}, MaxDepth: 3},
		{Path: "trusted_proxies.json", Area: "access"},
		{Path: "waf_central.json", Area: "waf"},
		{Path: "botrules.json", Area: "security"},
		{Path: "aicrawler.json", Area: "security"},
		{Path: "basicauth_lists.json", Area: "security"},
		{Path: "blocklist_sources.json", Area: "security"},
		{Path: "abuse/config.json", Area: "security"},
		{Path: "acme_conf.json", Area: "acme"},
		{Path: "notify.json", Area: "notify"},
		{Path: "log_conf.json", Area: "logging"},
		{Path: "sitelog.json", Area: "logging"},
		{Path: "plugin_groups.json", Area: "plugins"},
		{Path: "sso/zorxauth/groupPolicy", Area: "sso", Exts: []string{".json"}},
		{Path: "sso/zorxauth/branding", Area: "sso", MaxDepth: 2},
		{Path: "ech/ech.json", Area: "ech"},
		{Path: "certs", Area: "certs", MaxDepth: 2, NoContent: true},
	} {
		r.RegisterRoot(root)
	}
	for _, t := range []Table{
		{Name: "settings", Area: "settings"},
		{Name: "redirect", Area: "redirect"},
		{Name: "acme", Area: "acme", MaskAll: true},
		{Name: "acmepref", Area: "acme", MaskAll: true},
		{Name: "wolmac", Area: "settings"},
		{Name: "fwdproxy", Area: "settings"},
		{Name: "webserv", Area: "settings"},
		{Name: "blocklog", Area: "settings"},
		{Name: "visitors", Area: "settings"},
		{Name: "uptime", Area: "settings"},
		{Name: "statsettings", Area: "settings"},
		{Name: "ruletemplates", Area: "proxy"},
		{Name: "plugins", Area: "plugins"},
		{Name: "plugin_hooks", Area: "plugins"},
		{Name: "oauth2", Area: "sso", MaskAll: true},
		{Name: "oauth2_providers", Area: "sso", MaskAll: true},
		{Name: "auth_sso_forward", Area: "sso"},
	} {
		r.RegisterTable(t)
	}
	return r
}

// sortedKeys is a small helper used across the package.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
