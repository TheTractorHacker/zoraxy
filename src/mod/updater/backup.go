package updater

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const keepBackups = 10

// BackupDir is where pre-update backups are written: <conf>/../backups.
func BackupDir(confDir string) string {
	abs, err := filepath.Abs(confDir)
	if err != nil {
		abs = confDir
	}
	return filepath.Join(filepath.Dir(abs), "backups")
}

// CreateBackup zips the conf directory, the database (file or directory) and
// the uuid file into <conf>/../backups/zoraxy-pre-update-<ts>.zip. Entries are
// stored as conf/..., sys.db... and sys.uuid. Missing optional items (db,
// uuid) are skipped; a missing conf directory is an error. The archive is
// written to a temporary name and renamed on success so a failure never
// leaves a partial backup behind.
func CreateBackup(confDir, dbPath, uuidPath string, now time.Time) (string, error) {
	if st, err := os.Stat(confDir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("conf directory %q is not readable", confDir)
	}
	dir := BackupDir(confDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	final := filepath.Join(dir, "zoraxy-pre-update-"+now.UTC().Format("20060102-150405")+".zip")
	tmp := final + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	zw := zip.NewWriter(f)
	fail := func(err error) (string, error) {
		zw.Close()
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := addTree(zw, confDir, "conf"); err != nil {
		return fail(err)
	}
	if dbPath != "" {
		if _, err := os.Stat(dbPath); err == nil {
			if err := addTree(zw, dbPath, filepath.Base(dbPath)); err != nil {
				return fail(err)
			}
		}
	}
	if uuidPath != "" {
		if _, err := os.Stat(uuidPath); err == nil {
			if err := addTree(zw, uuidPath, filepath.Base(uuidPath)); err != nil {
				return fail(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return "", err
	}
	pruneBackups(dir)
	return final, nil
}

func addTree(zw *zip.Writer, src, prefix string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		name := prefix
		if rel != "." {
			name = prefix + "/" + filepath.ToSlash(rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			_, err := zw.Create(name + "/")
			return err
		}
		if !info.Mode().IsRegular() {
			return nil // skip sockets, symlinks, devices
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = name
		hdr.Method = zip.Deflate
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
}

func pruneBackups(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "zoraxy-pre-update-") && strings.HasSuffix(e.Name(), ".zip") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // timestamp in name sorts chronologically
	for len(names) > keepBackups {
		os.Remove(filepath.Join(dir, names[0]))
		names = names[1:]
	}
}

// treeSize returns the total size of regular files below p (best effort).
func treeSize(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if i, err := d.Info(); err == nil {
				n += i.Size()
			}
		}
		return nil
	})
	return n
}

// manifest maps relative file paths below root to their SHA-256, skipping the
// updater's own state directory and logs.
func manifest(root string) map[string]string {
	m := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if rel == "updater" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if h, err := fileSHA256(p); err == nil {
			m[filepath.ToSlash(rel)] = h
		}
		return nil
	})
	return m
}

// diffManifests describes what changed between two manifests.
func diffManifests(before, after map[string]string) (added, modified, removed []string) {
	for k, v := range after {
		if old, ok := before[k]; !ok {
			added = append(added, k)
		} else if old != v {
			modified = append(modified, k)
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(modified)
	sort.Strings(removed)
	return
}
