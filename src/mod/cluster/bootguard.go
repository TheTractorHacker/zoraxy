package cluster

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

/*
	Boot guard

	A snapshot can be valid JSON and still keep the node from starting
	(Zoraxy restarts itself to load new files). Before the restart the
	follower writes pending.json. If the next start does not reach the
	healthy point (MarkHealthy) and the process starts again, for example
	under systemd or a container restart policy, the previous files are
	restored and the offending snapshot is remembered as rejected.
*/

// HealthyAfter is how long a start must survive before the applied
// snapshot is confirmed.
const HealthyAfter = 20 * time.Second

type pendingApply struct {
	BackupDir  string         `json:"backupDir"`
	Roots      []string       `json:"roots"`
	Hash       string         `json:"hash"`
	Version    int64          `json:"version"`
	Attempts   int            `json:"attempts"`
	PrevStatus followerStatus `json:"prevStatus"`
}

func (m *Manager) pendingFile() string {
	return filepath.Join(m.opt.ConfDir, StateDirName, "pending.json")
}

func (m *Manager) writePending(p pendingApply) {
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(m.pendingFile()), 0o700)
	os.WriteFile(m.pendingFile(), b, 0o600)
}

// bootGuard runs at startup, before any module reads the config files.
func (m *Manager) bootGuard() {
	b, err := os.ReadFile(m.pendingFile())
	if err != nil {
		return
	}
	var p pendingApply
	if json.Unmarshal(b, &p) != nil {
		os.Remove(m.pendingFile())
		return
	}
	if p.Attempts < 1 {
		p.Attempts++
		m.writePending(p)
		return
	}
	// The first start with the new files never confirmed healthy: undo it.
	if err := restoreBackup(m.opt.ConfDir, p.BackupDir, p.Roots); err != nil {
		m.opt.Logf("[cluster] rollback of snapshot %d failed: %v", p.Version, err)
		return
	}
	os.Remove(m.pendingFile())
	m.status = p.PrevStatus
	m.status.RejectedHash = p.Hash
	m.status.LastResult = "error"
	m.status.LastError = fmt.Sprintf("snapshot version %d prevented a clean start and was rolled back", p.Version)
	m.saveStatusLocked()
	m.opt.Logf("[cluster] snapshot version %d prevented a clean start; previous configuration restored", p.Version)
}

// MarkHealthy confirms the applied snapshot after a successful start. Call it
// once the node is up (a delay of HealthyAfter is recommended).
func (m *Manager) MarkHealthy() {
	os.Remove(m.pendingFile())
}

func restoreBackup(confDir, backupDir string, roots []string) error {
	for _, root := range roots {
		dst := filepath.Join(confDir, filepath.FromSlash(root))
		bak := filepath.Join(backupDir, filepath.FromSlash(root))
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
		if _, err := os.Lstat(bak); err == nil {
			if err := os.Rename(bak, dst); err != nil {
				return err
			}
		}
	}
	return nil
}
