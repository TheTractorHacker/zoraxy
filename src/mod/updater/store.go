package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// store keeps the updater's small state files in <conf>/updater/.
type store struct {
	dir string
	mu  sync.Mutex
}

func newStore(confDir string) *store { return &store{dir: filepath.Join(confDir, "updater")} }

func (s *store) path(name string) string { return filepath.Join(s.dir, name) }

func (s *store) ensure() error { return os.MkdirAll(s.dir, 0o755) }

func (s *store) writeJSON(name string, v any) error {
	if err := s.ensure(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path(name + ".tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(name))
}

func (s *store) readJSON(name string, v any) error {
	b, err := os.ReadFile(s.path(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Settings are the persisted user choices.
type Settings struct {
	Channel     string `json:"channel"`
	BackupFirst bool   `json:"backup_first"`
}

func (s *store) settings() Settings {
	st := Settings{Channel: ChannelStable, BackupFirst: true}
	var f Settings
	if s.readJSON("settings.json", &f) == nil {
		if ValidChannel(f.Channel) {
			st.Channel = f.Channel
		}
		st.BackupFirst = f.BackupFirst
	}
	return st
}

func (s *store) saveSettings(st Settings) error { return s.writeJSON("settings.json", st) }

// Installed records which release the running executable was installed from.
// It is only trusted while SHA256 equals the hash of the running executable.
type Installed struct {
	Tag       string     `json:"tag"`
	Published time.Time  `json:"published"`
	SHA256    string     `json:"sha256"`
	Previous  *Installed `json:"previous,omitempty"`
}

func (s *store) installed() *Installed {
	var i Installed
	if s.readJSON("installed.json", &i) != nil || i.Tag == "" {
		return nil
	}
	return &i
}

func (s *store) saveInstalled(i *Installed) error {
	if i == nil {
		err := os.Remove(s.path("installed.json"))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	// Bound the previous-chain depth.
	depth := 0
	for c := i; c != nil; c = c.Previous {
		if depth++; depth > 4 {
			c.Previous = nil
			break
		}
	}
	return s.writeJSON("installed.json", i)
}

// Pending marks an installed-but-unconfirmed update.
type Pending struct {
	Tag           string     `json:"tag"`
	PrevTag       string     `json:"prev_tag"`
	Exe           string     `json:"exe"`
	PrevBinary    string     `json:"prev_binary"`
	Args          []string   `json:"args"`
	Method        string     `json:"method"`
	BackupFile    string     `json:"backup_file,omitempty"`
	PrevInstalled *Installed `json:"prev_installed,omitempty"`
	Started       time.Time  `json:"started"`
	Deadline      time.Time  `json:"deadline"`
	Attempts      int        `json:"attempts"`
	PID           int        `json:"pid"`
}

const pendingFile = "pending.json"

func (s *store) pending() *Pending {
	var p Pending
	if s.readJSON(pendingFile, &p) != nil || p.Exe == "" {
		return nil
	}
	return &p
}

func (s *store) savePending(p *Pending) error { return s.writeJSON(pendingFile, p) }

var errClaimed = errors.New("pending update already handled")

// claimPending atomically takes ownership of the marker so that only one of
// the in-process guard, the watchdog and the health confirmation acts on it.
func (s *store) claimPending() error {
	err := os.Rename(s.path(pendingFile), s.path(pendingFile+".claimed"))
	if err != nil {
		if os.IsNotExist(err) {
			return errClaimed
		}
		return err
	}
	return nil
}

func (s *store) releasePendingClaim() { os.Remove(s.path(pendingFile + ".claimed")) }

// HistoryEntry is one line of the update history.
type HistoryEntry struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"` // app_update | db_update | rollback | auto_rollback
	From   string    `json:"from,omitempty"`
	To     string    `json:"to,omitempty"`
	Result string    `json:"result"` // installed | success | failed | rolled_back
	Detail string    `json:"detail,omitempty"`
}

const maxHistory = 100

func (s *store) history() []HistoryEntry {
	var h []HistoryEntry
	_ = s.readJSON("history.json", &h)
	return h
}

func (s *store) addHistory(e HistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.history()
	h = append(h, e)
	if len(h) > maxHistory {
		h = h[len(h)-maxHistory:]
	}
	_ = s.writeJSON("history.json", h)
}

// audit appends one line to audit.log.
func (s *store) audit(ts time.Time, actor, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ensure() != nil {
		return
	}
	f, err := os.OpenFile(s.path("audit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	if actor == "" {
		actor = "system"
	}
	fmt.Fprintf(f, "%s [%s] %s\n", ts.UTC().Format(time.RFC3339), actor, msg)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
