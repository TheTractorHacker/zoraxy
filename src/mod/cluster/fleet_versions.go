package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func nonceHexN(n int) *regexp.Regexp { return regexp.MustCompile(fmt.Sprintf(`^[0-9a-f]{%d}$`, n)) }

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (h *Hub) versionFile(id int64) string {
	return filepath.Join(h.versionDir(), strconv.FormatInt(id, 10)+".zcs")
}

// splitItems turns per scope items into payload files and extra items.
func splitItems(items map[string][]FileEntry) (files, extra []FileEntry) {
	names := make([]string, 0, len(items))
	for n := range items {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, it := range items[n] {
			if validEntryPath(it.Path, ManagedRoots(true)) {
				files = append(files, it)
			} else {
				extra = append(extra, it)
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(extra, func(i, j int) bool { return extra[i].Path < extra[j].Path })
	return
}

// groupItems is the reverse of splitItems.
func groupItems(files, extra []FileEntry) map[string][]FileEntry {
	out := map[string][]FileEntry{}
	for _, f := range append(append([]FileEntry{}, files...), extra...) {
		if s, ok := scopeForPath(f.Path); ok {
			out[s.Name()] = append(out[s.Name()], f)
		}
	}
	return out
}

// Capture stores the hub's current configuration as a new immutable version.
// Content is sealed at rest (AES-GCM + HMAC) with the hub key. If nothing
// changed since the newest version, that version is returned instead.
func (h *Hub) Capture(by, note string) (VersionMeta, bool, error) {
	if !h.active() {
		return VersionMeta{}, false, errors.New("this node is not a fleet hub")
	}
	h.mu.Lock()
	captureCerts := h.st.Settings.CaptureCerts
	h.mu.Unlock()
	env := &ScopeEnv{ConfDir: h.m.opt.ConfDir}
	items := map[string][]FileEntry{}
	var scopes []string
	for _, n := range ScopeNames() {
		if n == "certs" && !captureCerts {
			continue
		}
		s, _ := GetScope(n)
		its, err := s.Export(env, Selection{})
		if err != nil {
			return VersionMeta{}, false, fmt.Errorf("scope %s: %w", n, err)
		}
		if err := s.Validate(its); err != nil {
			return VersionMeta{}, false, fmt.Errorf("scope %s is not valid: %w", n, err)
		}
		for _, it := range its {
			if isTemplated(it.Path) {
				if _, err := PlaceholdersIn(it.Data); err != nil {
					return VersionMeta{}, false, fmt.Errorf("%s: %w", it.Path, err)
				}
			}
		}
		items[n] = its
		scopes = append(scopes, n)
	}
	files, extra := splitItems(items)
	idx := map[string]string{}
	for _, f := range append(append([]FileEntry{}, files...), extra...) {
		idx[f.Path] = digest(f.Data)
	}
	vhash := hashStrings("version", strings.Join(scopes, ","), HashFiles(files), HashFiles(extra))

	h.mu.Lock()
	if n := len(h.st.Versions); n > 0 && h.st.Versions[n-1].Hash == vhash {
		v := h.st.Versions[n-1]
		h.mu.Unlock()
		return v, false, nil
	}
	h.mu.Unlock()

	key, err := h.key()
	if err != nil {
		return VersionMeta{}, false, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.st.NextVer
	p := &Payload{Roots: ManagedRoots(true), IncludesCerts: true, Files: files, ContentHash: HashFiles(files), Fleet: &FleetMeta{Extra: extra}}
	raw, err := Seal(key, id, h.now().Unix(), h.st.HubID, p)
	if err != nil {
		return VersionMeta{}, false, err
	}
	if err := writeFileAtomic(h.versionFile(id), raw, 0o600); err != nil {
		return VersionMeta{}, false, err
	}
	v := VersionMeta{ID: id, CreatedAt: h.now().Unix(), CreatedBy: trimTo(by, 64), Note: trimTo(note, 200), Scopes: scopes, Hash: vhash, Files: idx}
	h.st.Versions = append(h.st.Versions, v)
	h.st.NextVer = id + 1
	h.pruneVersionsLocked()
	if err := h.saveLocked(); err != nil {
		return VersionMeta{}, false, err
	}
	h.auditLocked(AuditEntry{At: v.CreatedAt, Actor: by, Action: "version.capture", Target: "v" + strconv.FormatInt(id, 10), Detail: fmt.Sprintf("%d files %s", len(idx), v.Note)})
	return v, true, nil
}

// pruneVersionsLocked keeps the newest KeepVersions plus every version that
// a group or an active rollout still refers to.
func (h *Hub) pruneVersionsLocked() {
	keep := h.st.Settings.KeepVersions
	if keep < 2 {
		keep = DefaultKeepVersions
	}
	used := map[int64]bool{}
	for _, g := range h.st.Groups {
		used[g.Desired] = true
		if g.Rollout != nil {
			used[g.Rollout.Version], used[g.Rollout.PrevVersion] = true, true
		}
	}
	for len(h.st.Versions) > keep {
		drop := -1
		for i, v := range h.st.Versions { //oldest first
			if !used[v.ID] {
				drop = i
				break
			}
		}
		if drop < 0 || len(h.st.Versions)-1 < keep {
			return
		}
		os.Remove(h.versionFile(h.st.Versions[drop].ID))
		h.st.Versions = append(h.st.Versions[:drop], h.st.Versions[drop+1:]...)
	}
}

func (h *Hub) versionMeta(id int64) (VersionMeta, bool) {
	for _, v := range h.st.Versions {
		if v.ID == id {
			return v, true
		}
	}
	return VersionMeta{}, false
}

// loadVersion decrypts a stored version (small LRU cache).
func (h *Hub) loadVersion(id int64) (map[string][]FileEntry, error) {
	h.cacheMu.Lock()
	if it, ok := h.cache[id]; ok {
		h.cacheMu.Unlock()
		return it, nil
	}
	h.cacheMu.Unlock()
	key, err := h.key()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(h.versionFile(id))
	if err != nil {
		return nil, fmt.Errorf("version %d is not available", id)
	}
	_, p, err := Open(key, raw)
	if err != nil {
		return nil, fmt.Errorf("version %d cannot be opened: %w", id, err)
	}
	var extra []FileEntry
	if p.Fleet != nil {
		extra = p.Fleet.Extra
	}
	items := groupItems(p.Files, extra)
	h.cacheMu.Lock()
	h.cache[id] = items
	h.cacheOrder = append(h.cacheOrder, id)
	for len(h.cacheOrder) > 3 {
		delete(h.cache, h.cacheOrder[0])
		h.cacheOrder = h.cacheOrder[1:]
	}
	h.cacheMu.Unlock()
	return items, nil
}

// DiffEntry is one changed path between two versions.
type DiffEntry struct {
	Path   string `json:"path"`
	Scope  string `json:"scope"`
	Change string `json:"change"` //added | removed | changed
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
}

const maxDiffContent = 32 << 10

// Diff lists what changed from version a to version b. Contents are included
// for small non secret text files only (never certificates and keys).
func (h *Hub) Diff(a, b int64) ([]DiffEntry, error) {
	h.mu.Lock()
	va, okA := h.versionMeta(a)
	vb, okB := h.versionMeta(b)
	h.mu.Unlock()
	if a == 0 {
		okA = true
		va = VersionMeta{Files: map[string]string{}}
	}
	if !okA || !okB {
		return nil, errors.New("unknown version")
	}
	var out []DiffEntry
	add := func(p, change string) {
		sc := ""
		if s, ok := scopeForPath(p); ok {
			sc = s.Name()
		} else if i := strings.Index(p, ":"); i > 0 {
			sc = p[:i]
		}
		out = append(out, DiffEntry{Path: p, Scope: sc, Change: change})
	}
	for p, hb := range vb.Files {
		if ha, ok := va.Files[p]; !ok {
			add(p, "added")
		} else if ha != hb {
			add(p, "changed")
		}
	}
	for p := range va.Files {
		if _, ok := vb.Files[p]; !ok {
			add(p, "removed")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if len(out) == 0 {
		return out, nil
	}
	var itA, itB map[string][]FileEntry
	if a != 0 {
		itA, _ = h.loadVersion(a)
	}
	itB, _ = h.loadVersion(b)
	find := func(it map[string][]FileEntry, scope, p string) ([]byte, bool) {
		for _, f := range it[scope] {
			if f.Path == p {
				return f.Data, true
			}
		}
		return nil, false
	}
	for i := range out {
		e := &out[i]
		if strings.HasPrefix(e.Path, certRoot+"/") || len(e.Path) == 0 {
			continue
		}
		if d, ok := find(itA, e.Scope, e.Path); ok && len(d) <= maxDiffContent {
			e.Old = string(d)
		}
		if d, ok := find(itB, e.Scope, e.Path); ok && len(d) <= maxDiffContent {
			e.New = string(d)
		}
	}
	return out, nil
}
