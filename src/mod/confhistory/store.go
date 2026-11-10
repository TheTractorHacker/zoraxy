package confhistory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Store layout below <conf>/.history (directory 0700, files 0600):
//
//	history.key         random per-install key
//	settings.json       retention settings (not secret)
//	index.zhi           sealed: version metadata, last restore outcome
//	versions/<id>.zhv   sealed: manifest {path -> blob name, mode, size}
//	blobs/<name>.zhb    sealed: file content, named by HMAC of the plaintext
//	pending.json        a restore waiting for its health confirmation
//	staging-*/ backup-* restore working folders

const (
	dirName      = ".history"
	indexFile    = "index.zhi"
	versionDir   = "versions"
	blobDir      = "blobs"
	settingsFile = "settings.json"
	pendingFile  = "pending.json"
)

// Change is one object that differs between a version and its predecessor.
type Change struct {
	Path  string `json:"path"`
	Area  string `json:"area"`
	Kind  string `json:"kind"` // added | changed | removed
	Label string `json:"label"`
}

// Meta describes one version.
type Meta struct {
	ID      int64    `json:"id"`
	Time    int64    `json:"time"`
	Actor   string   `json:"actor"`
	Trigger string   `json:"trigger"` // api | api-v1 | baseline | external | pre-update | pre-restore | restore | manual
	Summary string   `json:"summary"`
	Hash    string   `json:"hash"`
	Files   int      `json:"files"`
	Bytes   int64    `json:"bytes"` // plaintext size of the version
	Changes []Change `json:"changes"`
}

// RestoreRecord is the outcome of the last restore, shown by the UI.
type RestoreRecord struct {
	At        int64  `json:"at"`
	From      int64  `json:"from"`  // version restored
	Pre       int64  `json:"pre"`   // safety snapshot taken before
	Scope     string `json:"scope"` // all or an area id
	Actor     string `json:"actor"`
	Result    string `json:"result"` // pending | confirmed | rolled_back | failed
	Detail    string `json:"detail,omitempty"`
	Restarted bool   `json:"restarted"`
}

type index struct {
	NextID      int64          `json:"nextId"`
	Versions    []Meta         `json:"versions"`
	LastRestore *RestoreRecord `json:"lastRestore,omitempty"`
}

type manifestEntry struct {
	Blob string `json:"b"`
	Mode uint32 `json:"m"`
	Size int64  `json:"s"`
}

type manifest map[string]manifestEntry

// Settings are the retention settings.
type Settings struct {
	Enabled   bool `json:"enabled"`
	KeepCount int  `json:"keepCount"` // newest N versions are kept
	KeepDays  int  `json:"keepDays"`  // versions younger than this are kept
	MaxMiB    int  `json:"maxMiB"`    // size cap of the whole store
}

// DefaultSettings are used until the admin changes them.
func DefaultSettings() Settings {
	return Settings{Enabled: true, KeepCount: 100, KeepDays: 30, MaxMiB: 200}
}

// Validate enforces sane bounds.
func (s Settings) Validate() error {
	if s.KeepCount < minProtected || s.KeepCount > 10000 {
		return fmt.Errorf("keepCount must be between %d and 10000", minProtected)
	}
	if s.KeepDays < 1 || s.KeepDays > 3650 {
		return errors.New("keepDays must be between 1 and 3650")
	}
	if s.MaxMiB < 10 || s.MaxMiB > 102400 {
		return errors.New("maxMiB must be between 10 and 102400")
	}
	return nil
}

// minProtected is how many of the newest versions pruning never removes.
const minProtected = 5

func (m *Manager) dir(parts ...string) string {
	return filepath.Join(append([]string{m.opt.ConfDir, dirName}, parts...)...)
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------------------------------------------------------- index

func (m *Manager) loadIndexLocked() (*index, error) {
	if m.idx != nil {
		return m.idx, nil
	}
	idx := &index{NextID: 1}
	raw, err := os.ReadFile(m.dir(indexFile))
	switch {
	case err == nil:
		plain, err := m.seal.open("index", "index", raw)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(plain, idx); err != nil {
			return nil, fmt.Errorf("history index damaged: %w", err)
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	if idx.NextID < 1 {
		idx.NextID = 1
	}
	m.idx = idx
	return idx, nil
}

func (m *Manager) saveIndexLocked() error {
	plain, err := json.Marshal(m.idx)
	if err != nil {
		return err
	}
	sealed, err := m.seal.seal("index", "index", plain)
	if err != nil {
		return err
	}
	return writeAtomic(m.dir(indexFile), sealed, 0o600)
}

// ---------------------------------------------------------------- manifests and blobs

func (m *Manager) manifestPath(id int64) string {
	return m.dir(versionDir, strconv.FormatInt(id, 10)+".zhv")
}

func (m *Manager) blobPath(name string) string { return m.dir(blobDir, name+".zhb") }

func (m *Manager) loadManifest(id int64) (manifest, error) {
	raw, err := os.ReadFile(m.manifestPath(id))
	if err != nil {
		return nil, fmt.Errorf("version %d is not available", id)
	}
	plain, err := m.seal.open("manifest", strconv.FormatInt(id, 10), raw)
	if err != nil {
		return nil, err
	}
	var mf manifest
	if err := json.Unmarshal(plain, &mf); err != nil {
		return nil, fmt.Errorf("version %d manifest damaged: %w", id, err)
	}
	return mf, nil
}

func (m *Manager) saveManifest(id int64, mf manifest) error {
	plain, err := json.Marshal(mf)
	if err != nil {
		return err
	}
	sealed, err := m.seal.seal("manifest", strconv.FormatInt(id, 10), plain)
	if err != nil {
		return err
	}
	return writeAtomic(m.manifestPath(id), sealed, 0o600)
}

func (m *Manager) putBlob(name string, data []byte) error {
	p := m.blobPath(name)
	if _, err := os.Stat(p); err == nil {
		return nil //content addressed: already stored
	}
	sealed, err := m.seal.seal("blob", name, data)
	if err != nil {
		return err
	}
	return writeAtomic(p, sealed, 0o600)
}

// getBlob reads, authenticates and re-verifies a blob against its name.
func (m *Manager) getBlob(name string) ([]byte, error) {
	if !validBlobName(name) {
		return nil, ErrTampered
	}
	raw, err := os.ReadFile(m.blobPath(name))
	if err != nil {
		return nil, fmt.Errorf("stored content %s.. is missing", name[:8])
	}
	plain, err := m.seal.open("blob", name, raw)
	if err != nil {
		return nil, err
	}
	if m.seal.name(plain) != name {
		return nil, ErrTampered
	}
	return plain, nil
}

func validBlobName(n string) bool {
	if len(n) != 64 {
		return false
	}
	for _, c := range n {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// loadState rebuilds the entries of a version.
func (m *Manager) loadState(id int64) (State, error) {
	mf, err := m.loadManifest(id)
	if err != nil {
		return nil, err
	}
	st := make(State, len(mf))
	for p, me := range mf {
		data, err := m.getBlob(me.Blob)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		st[p] = Entry{Path: p, Mode: me.Mode, Data: data}
	}
	return st, nil
}

// ---------------------------------------------------------------- retention

// pruneLocked applies the retention rules and removes unreferenced blobs.
//
// A version is kept when it is among the newest KeepCount OR younger than
// KeepDays. Then the size cap removes the oldest versions until the store fits.
// Never removed: the newest minProtected versions and any version a pending or
// running restore depends on.
func (m *Manager) pruneLocked() {
	idx, err := m.loadIndexLocked()
	if err != nil || len(idx.Versions) == 0 {
		return
	}
	set := m.settings
	protected := m.protectedLocked()
	now := m.now()
	n := len(idx.Versions)
	removable := func(i int) bool {
		v := idx.Versions[i]
		return i < n-minProtected && !protected[v.ID]
	}
	var drop []int64
	dropped := map[int64]bool{}
	for i, v := range idx.Versions {
		if !removable(i) {
			continue
		}
		keepByCount := i >= n-set.KeepCount
		keepByAge := now.Sub(time.Unix(v.Time, 0)) < time.Duration(set.KeepDays)*24*time.Hour
		if !keepByCount && !keepByAge {
			drop = append(drop, v.ID)
			dropped[v.ID] = true
		}
	}
	// size cap
	sizes, refs := m.blobUsage(idx, dropped)
	total := int64(0)
	for _, s := range sizes {
		total += s
	}
	for _, s := range refs.versionBytes {
		total += s
	}
	limit := int64(set.MaxMiB) << 20
	for i := 0; total > limit && i < n; i++ {
		v := idx.Versions[i]
		if dropped[v.ID] || !removable(i) {
			continue
		}
		dropped[v.ID] = true
		drop = append(drop, v.ID)
		total -= refs.versionBytes[v.ID]
		for b := range refs.blobsOf[v.ID] {
			refs.count[b]--
			if refs.count[b] == 0 {
				total -= sizes[b]
			}
		}
	}
	if len(drop) > 0 {
		kept := idx.Versions[:0:0]
		for _, v := range idx.Versions {
			if !dropped[v.ID] {
				kept = append(kept, v)
			}
		}
		idx.Versions = kept
		if err := m.saveIndexLocked(); err != nil {
			return
		}
		for _, id := range drop {
			os.Remove(m.manifestPath(id))
		}
	}
	m.gcBlobsLocked()
}

type usage struct {
	count        map[string]int
	blobsOf      map[int64]map[string]bool
	versionBytes map[int64]int64
}

// blobUsage returns the on-disk size of every blob and how the versions
// (excluding already dropped ones) reference them.
func (m *Manager) blobUsage(idx *index, dropped map[int64]bool) (map[string]int64, *usage) {
	u := &usage{count: map[string]int{}, blobsOf: map[int64]map[string]bool{}, versionBytes: map[int64]int64{}}
	sizes := map[string]int64{}
	for _, v := range idx.Versions {
		if fi, err := os.Stat(m.manifestPath(v.ID)); err == nil {
			u.versionBytes[v.ID] = fi.Size()
		}
		mf, err := m.loadManifest(v.ID)
		if err != nil {
			continue
		}
		set := map[string]bool{}
		for _, me := range mf {
			set[me.Blob] = true
		}
		u.blobsOf[v.ID] = set
		if dropped[v.ID] {
			continue
		}
		for b := range set {
			u.count[b]++
			if _, ok := sizes[b]; !ok {
				if fi, err := os.Stat(m.blobPath(b)); err == nil {
					sizes[b] = fi.Size()
				}
			}
		}
	}
	for id := range dropped {
		delete(u.versionBytes, id)
	}
	return sizes, u
}

// gcBlobsLocked deletes blobs no remaining version references (also leftovers
// of an interrupted capture).
func (m *Manager) gcBlobsLocked() {
	idx := m.idx
	if idx == nil {
		return
	}
	used := map[string]bool{}
	for _, v := range idx.Versions {
		mf, err := m.loadManifest(v.ID)
		if err != nil {
			return //do not delete anything when a manifest cannot be read
		}
		for _, me := range mf {
			used[me.Blob] = true
		}
	}
	ents, err := os.ReadDir(m.dir(blobDir))
	if err != nil {
		return
	}
	for _, e := range ents {
		name := strings.TrimSuffix(e.Name(), ".zhb")
		if strings.HasSuffix(e.Name(), ".tmp") || (!used[name] && strings.HasSuffix(e.Name(), ".zhb")) {
			os.Remove(m.dir(blobDir, e.Name()))
		}
	}
}

// protectedLocked is the set of version ids pruning must keep.
func (m *Manager) protectedLocked() map[int64]bool {
	p := map[int64]bool{}
	for id := range m.hold {
		p[id] = true
	}
	if pend := m.readPending(); pend != nil {
		p[pend.Pre], p[pend.From] = true, true
	}
	return p
}

// StoreBytes returns the bytes the store occupies on disk.
func (m *Manager) StoreBytes() int64 {
	var total int64
	filepath.WalkDir(m.dir(), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, e := d.Info(); e == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total
}

func sortMetaDesc(v []Meta) {
	sort.Slice(v, func(i, j int) bool { return v[i].ID > v[j].ID })
}
