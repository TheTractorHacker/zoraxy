package confhistory

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// maxFileBytes is the largest single file captured or restored.
	maxFileBytes = 16 << 20
	// maxStateBytes bounds the whole captured state (zip bomb / runaway dir guard).
	maxStateBytes = 128 << 20
	// maxEntries bounds the number of captured files.
	maxEntries = 20000
)

// Entry is one captured file or table export.
type Entry struct {
	Path string `json:"p"`
	Mode uint32 `json:"m"`
	Data []byte `json:"d"`
}

// State is a set of entries keyed by path.
type State map[string]Entry

// KV is the part of the sys.db API the history needs. database.Database
// satisfies it.
type KV interface {
	TableExists(table string) bool
	NewTable(table string) error
	Write(table, key string, value interface{}) error
	Delete(table, key string) error
	ListTable(table string) ([][][]byte, error)
}

// collect reads the live configuration. skipped lists files left out (too big).
func (m *Manager) collect() (State, []string, error) {
	st := State{}
	var skipped []string
	var total int64
	confDir := m.opt.ConfDir

	addFile := func(abs, rel string, info fs.FileInfo) error {
		if !m.reg.ValidFile(rel) || !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > maxFileBytes {
			skipped = append(skipped, rel)
			return nil
		}
		total += info.Size()
		if total > maxStateBytes || len(st) >= maxEntries {
			return errTooLarge
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			if os.IsNotExist(err) { //removed while we were walking
				return nil
			}
			return err
		}
		st[rel] = Entry{Path: rel, Mode: uint32(info.Mode().Perm()), Data: data}
		return nil
	}

	for _, root := range m.reg.Roots() {
		abs := filepath.Join(confDir, filepath.FromSlash(root.Path))
		fi, err := os.Lstat(abs)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if fi.Mode().IsRegular() {
			if err := addFile(abs, root.Path, fi); err != nil {
				return nil, nil, err
			}
			continue
		}
		if !fi.IsDir() {
			continue
		}
		err = filepath.WalkDir(abs, func(file string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				rel, _ := filepath.Rel(abs, file)
				if rel != "." && len(strings.Split(filepath.ToSlash(rel), "/")) >= root.MaxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(confDir, file)
			if err != nil {
				return err
			}
			return addFile(file, filepath.ToSlash(rel), info)
		})
		if err != nil {
			return nil, nil, err
		}
	}

	if m.opt.DB != nil {
		for _, tb := range m.reg.Tables() {
			data, err := m.dumpTable(tb.Name)
			if err != nil {
				return nil, nil, err
			}
			if data == nil {
				continue
			}
			st[dbPrefix+tb.Name] = Entry{Path: dbPrefix + tb.Name, Mode: 0o600, Data: data}
		}
	}
	sort.Strings(skipped)
	return st, skipped, nil
}

// dumpTable exports a table as one canonical JSON object {key: value}. Values
// that are not valid JSON are left out (sys.db only stores JSON).
func (m *Manager) dumpTable(name string) ([]byte, error) {
	if !m.opt.DB.TableExists(name) {
		return nil, nil
	}
	rows, err := m.opt.DB.ListTable(name)
	if err != nil {
		return nil, err
	}
	obj := make(map[string]json.RawMessage, len(rows))
	for _, kv := range rows {
		if len(kv) != 2 || !json.Valid(kv[1]) {
			continue
		}
		obj[string(kv[0])] = json.RawMessage(append([]byte(nil), kv[1]...))
	}
	if len(obj) == 0 {
		return nil, nil
	}
	return json.Marshal(obj) //map keys are sorted: stable bytes
}
