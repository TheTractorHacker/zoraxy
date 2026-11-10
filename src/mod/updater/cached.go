package updater

import (
	"os"
	"strings"
	"time"
)

// CachedState is the update state as of the last successful release list download.
type CachedState struct {
	Cached          bool      // a release list for this repository is on disk
	FetchedAt       time.Time // when it was downloaded
	UpdateAvailable bool
	Latest          string // tag of the newest release on the channel
	Current         string // tag or version of the running build
	Channel         string
}

// CachedState answers "is an update available?" from the release list cached on disk. It never touches the
// network and never refreshes the cache, so it is safe for read-only pages (the security overview).
func (m *Manager) CachedState() CachedState {
	var c releaseCache
	out := CachedState{Channel: m.st.settings().Channel}
	if m.st.readJSON(releaseCacheFile, &c) != nil || c.Repo != m.cfg.Repo || len(c.Body) == 0 {
		return out
	}
	rels, err := parseReleases(c.Body)
	if err != nil {
		return out
	}
	r, cur, err := m.resolveFrom(rels)
	if err != nil {
		return out
	}
	out.Cached, out.FetchedAt = true, c.FetchedAt
	out.UpdateAvailable = r.newer && r.hasAssets
	out.Latest = r.rel.Tag
	out.Current = cur.Tag
	if out.Current == "" {
		out.Current = cur.Version
	}
	return out
}

// BackupInfo summarises the pre-update backups on disk
type BackupInfo struct {
	Count  int
	Latest time.Time
}

// Backups lists the pre-update backups (zoraxy-pre-update-*.zip) without reading them.
func (m *Manager) Backups() (BackupInfo, error) {
	return ScanBackups(BackupDir(m.cfg.ConfDir))
}

// ScanBackups counts the pre-update backups in dir and finds the newest one by modification time.
// A missing folder is not an error: it just means there are none.
func ScanBackups(dir string) (BackupInfo, error) {
	var info BackupInfo
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return info, nil
		}
		return info, err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "zoraxy-pre-update-") || !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		info.Count++
		if fi.ModTime().After(info.Latest) {
			info.Latest = fi.ModTime()
		}
	}
	return info, nil
}
