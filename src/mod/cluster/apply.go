package cluster

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// StateDirName is the node-local working folder inside the conf folder. It
// holds staging data, backups and sync state and is never part of a snapshot.
const StateDirName = ".cluster"

// keepBackups is how many backups of replaced state are retained.
const keepBackups = 3

type rootOp struct {
	root      string
	dst, bak  string
	backedUp  bool
	installed bool
}

// Applied is the result of ApplyPayload and allows undoing it.
type Applied struct {
	ops       []rootOp
	BackupDir string
}

// Rollback restores the state from before ApplyPayload.
func (a *Applied) Rollback() error {
	if a == nil {
		return nil
	}
	var errs []string
	for i := len(a.ops) - 1; i >= 0; i-- {
		op := a.ops[i]
		if op.installed {
			if err := os.RemoveAll(op.dst); err != nil {
				errs = append(errs, err.Error())
				continue
			}
		}
		if op.backedUp {
			if err := os.Rename(op.bak, op.dst); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return errors.New("rollback incomplete: " + strings.Join(errs, "; "))
	}
	return nil
}

// Applier replaces the managed parts of a conf folder with a payload.
type Applier struct {
	ConfDir string
	// beforeInstall is a test hook invoked before each root is installed.
	beforeInstall func(root string) error
}

// ApplyPayload stages the payload next to the live config, then swaps each
// managed root in with renames (the previous version is kept as a backup).
// If anything fails, everything already swapped is restored. The caller can
// also call Rollback on the result, for example when reloading fails.
func (ap *Applier) ApplyPayload(p *Payload, tag string) (*Applied, error) {
	if err := ValidatePayload(p); err != nil {
		return nil, err
	}
	stateDir := filepath.Join(ap.ConfDir, StateDirName)
	staging := filepath.Join(stateDir, "staging-"+tag)
	backup := filepath.Join(stateDir, "backup-"+tag)
	os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return nil, err
	}

	for _, f := range p.Files {
		dst := filepath.Join(staging, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		// never create executable files from a snapshot
		perm := os.FileMode(f.Mode&0o666) | 0o600
		if err := os.WriteFile(dst, f.Data, perm); err != nil {
			return nil, err
		}
	}

	applied := &Applied{BackupDir: backup}
	for _, root := range p.Roots {
		if ap.beforeInstall != nil {
			if err := ap.beforeInstall(root); err != nil {
				applied.Rollback()
				return nil, err
			}
		}
		op := rootOp{
			root: root,
			dst:  filepath.Join(ap.ConfDir, filepath.FromSlash(root)),
			bak:  filepath.Join(backup, filepath.FromSlash(root)),
		}
		src := filepath.Join(staging, filepath.FromSlash(root))
		applied.ops = append(applied.ops, op)
		idx := len(applied.ops) - 1
		if _, err := os.Lstat(op.dst); err == nil {
			if err := os.Rename(op.dst, op.bak); err != nil {
				applied.Rollback()
				return nil, fmt.Errorf("backup of %s failed: %w", root, err)
			}
			applied.ops[idx].backedUp = true
		}
		if _, err := os.Lstat(src); err == nil {
			if err := os.Rename(src, op.dst); err != nil {
				applied.Rollback()
				return nil, fmt.Errorf("install of %s failed: %w", root, err)
			}
			applied.ops[idx].installed = true
		}
	}
	pruneBackups(stateDir)
	return applied, nil
}

// pruneBackups keeps the newest keepBackups backup folders.
func pruneBackups(stateDir string) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "backup-") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keepBackups {
		os.RemoveAll(filepath.Join(stateDir, names[0]))
		names = names[1:]
	}
}

// BackupTag returns a sortable tag for staging and backup folders.
func BackupTag(now time.Time) string {
	return now.UTC().Format("20060102T150405.000")
}
