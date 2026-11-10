package ruleset

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

/*
	store.go

	Persistence: JSON files under <conf>/ruleset/

	  global.json          {"version":1,"rules":[...]}
	  sites/<site>.json    {"version":1,"site":"example.com","rules":[...]}   (file name = percent-encoded site key)
	  lists.json           {"version":1,"lists":[...]}

	Files are written atomically (temp file in the same folder, fsync, rename), mode 0600. The folder is a
	Fleet scope ("ruleset") and is picked up by the change history like the rest of conf/.
*/

const (
	fileVersion = 1
	maxFileSize = 8 << 20
)

type setFile struct {
	Version int    `json:"version"`
	Site    string `json:"site,omitempty"`
	Rules   []Rule `json:"rules"`
}

type listsFile struct {
	Version int     `json:"version"`
	Lists   []*List `json:"lists"`
}

// siteFileName encodes a site key so it is safe as a file name on every platform
func siteFileName(site string) string {
	var b strings.Builder
	for i := 0; i < len(site); i++ {
		c := site[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' && i > 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02x", c)
		}
	}
	return b.String() + ".json"
}

func siteFromFileName(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".json")
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if name[i] == '%' {
			if i+2 >= len(name) {
				return "", false
			}
			var v int
			if _, err := fmt.Sscanf(name[i+1:i+3], "%02x", &v); err != nil {
				return "", false
			}
			b.WriteByte(byte(v))
			i += 2
			continue
		}
		b.WriteByte(name[i])
	}
	return b.String(), true
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ruleset-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(name) }
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// save writes the files of the given scopes ("global", "site:<key>", "lists")
func (e *Engine) save(st *state, scopes []string) error {
	for _, sc := range scopes {
		switch {
		case sc == "global":
			js, _ := json.MarshalIndent(setFile{Version: fileVersion, Rules: nonNil(st.global)}, "", "  ")
			if len(st.global) == 0 {
				if err := os.Remove(filepath.Join(e.dir, "global.json")); err != nil && !os.IsNotExist(err) {
					return err
				}
				continue
			}
			if err := writeAtomic(filepath.Join(e.dir, "global.json"), js); err != nil {
				return err
			}
		case sc == "lists":
			js, _ := json.MarshalIndent(listsFile{Version: fileVersion, Lists: st.lists}, "", "  ")
			if len(st.lists) == 0 {
				if err := os.Remove(filepath.Join(e.dir, "lists.json")); err != nil && !os.IsNotExist(err) {
					return err
				}
				continue
			}
			if err := writeAtomic(filepath.Join(e.dir, "lists.json"), js); err != nil {
				return err
			}
		case strings.HasPrefix(sc, "site:"):
			site := strings.TrimPrefix(sc, "site:")
			path := filepath.Join(e.dir, "sites", siteFileName(site))
			rules := st.sites[site]
			if len(rules) == 0 {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					return err
				}
				continue
			}
			js, _ := json.MarshalIndent(setFile{Version: fileVersion, Site: site, Rules: rules}, "", "  ")
			if err := writeAtomic(path, js); err != nil {
				return err
			}
		}
	}
	return nil
}

func nonNil(r []Rule) []Rule {
	if r == nil {
		return []Rule{}
	}
	return r
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("file is larger than %d bytes", maxFileSize)
	}
	return data, nil
}

// Open loads the rule sets from dir (missing = empty). Files that cannot be read are skipped and listed in
// LoadErrors; rules that no longer validate are kept but inactive (see RuleInfo.Error).
func Open(dir string) (*Engine, error) {
	e := newEngine(dir)
	if err := e.Reload(); err != nil {
		return e, err
	}
	return e, nil
}

// Reload re-reads the files (after a Fleet apply or a restore)
func (e *Engine) Reload() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := &state{sites: map[string][]Rule{}}
	var errs []string
	if data, err := readLimited(filepath.Join(e.dir, "global.json")); err == nil {
		var f setFile
		if err := json.Unmarshal(data, &f); err != nil {
			errs = append(errs, "global.json: "+err.Error())
		} else {
			st.global = capRules(f.Rules)
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, "global.json: "+err.Error())
	}
	if data, err := readLimited(filepath.Join(e.dir, "lists.json")); err == nil {
		var f listsFile
		if err := json.Unmarshal(data, &f); err != nil {
			errs = append(errs, "lists.json: "+err.Error())
		} else {
			seen := map[string]bool{}
			for _, l := range f.Lists {
				if l == nil || seen[l.Name] || len(st.lists) >= MaxLists {
					continue
				}
				if err := l.Validate(); err != nil {
					errs = append(errs, "list "+l.Name+": "+err.Error())
					continue
				}
				seen[l.Name] = true
				st.lists = append(st.lists, l)
			}
			sort.Slice(st.lists, func(i, j int) bool { return st.lists[i].Name < st.lists[j].Name })
		}
	} else if !os.IsNotExist(err) {
		errs = append(errs, "lists.json: "+err.Error())
	}
	entries, _ := os.ReadDir(filepath.Join(e.dir, "sites"))
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") || len(st.sites) >= MaxSites {
			continue
		}
		data, err := readLimited(filepath.Join(e.dir, "sites", ent.Name()))
		if err != nil {
			errs = append(errs, "sites/"+ent.Name()+": "+err.Error())
			continue
		}
		var f setFile
		if err := json.Unmarshal(data, &f); err != nil {
			errs = append(errs, "sites/"+ent.Name()+": "+err.Error())
			continue
		}
		site, ok := siteFromFileName(ent.Name())
		if !ok || f.Site != site || site == "" {
			errs = append(errs, "sites/"+ent.Name()+": the file name does not match the site in the file")
			continue
		}
		if len(f.Rules) > 0 {
			st.sites[site] = capRules(f.Rules)
		}
	}
	e.LoadErrors = errs
	e.st = st
	e.snap.Store(e.build(st))
	return nil
}

func capRules(r []Rule) []Rule {
	if len(r) > MaxRulesPerSet {
		r = r[:MaxRulesPerSet]
	}
	seen := map[string]bool{}
	out := make([]Rule, 0, len(r))
	for _, x := range r {
		if x.ID == "" || seen[x.ID] {
			x.ID = newID()
		}
		seen[x.ID] = true
		out = append(out, x)
	}
	return out
}

// Dir returns the storage folder
func (e *Engine) Dir() string { return e.dir }
