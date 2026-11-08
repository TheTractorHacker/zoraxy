package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootGuardRollsBackSnapshotThatBreaksStartup(t *testing.T) {
	p := newPair(t, false)
	os.MkdirAll(filepath.Join(p.fDir, "proxy"), 0o755)
	os.WriteFile(filepath.Join(p.fDir, "proxy", "local.config"), []byte(`{"local":true}`), 0o600)
	// Reload succeeds (the real one restarts the process)
	p.follower.opt.Reload = func() error { return nil }
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p.fDir, "proxy/a.config") == "<missing>" {
		t.Fatal("snapshot not applied")
	}
	hash := p.follower.status.AppliedHash

	// first start after the apply: only counts the attempt
	_, err := NewManager(Options{ConfDir: p.fDir, NodeID: "follower-1"})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, p.fDir, "proxy/a.config") == "<missing>" {
		t.Fatal("first start must keep the new configuration")
	}

	// the process died before it was confirmed healthy and starts again
	m3, err := NewManager(Options{ConfDir: p.fDir, NodeID: "follower-1"})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, p.fDir, "proxy/local.config") != `{"local":true}` || readFile(t, p.fDir, "proxy/a.config") != "<missing>" {
		t.Fatal("previous configuration not restored")
	}
	st := m3.Status()
	if st.AppliedVersion != 0 || st.LastResult != "error" || !strings.Contains(st.LastError, "rolled back") {
		t.Fatalf("status after boot rollback: %+v", st)
	}
	if m3.status.RejectedHash != hash {
		t.Fatal("rejected snapshot not remembered")
	}
	if _, err := os.Stat(m3.pendingFile()); err == nil {
		t.Fatal("pending marker left behind")
	}
}

func TestBootGuardConfirmedHealthyKeepsSnapshot(t *testing.T) {
	p := newPair(t, false)
	p.follower.opt.Reload = func() error { return nil }
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	m2, _ := NewManager(Options{ConfDir: p.fDir, NodeID: "follower-1"})
	m2.MarkHealthy()
	NewManager(Options{ConfDir: p.fDir, NodeID: "follower-1"})
	if readFile(t, p.fDir, "proxy/a.config") == "<missing>" {
		t.Fatal("a healthy start must keep the snapshot")
	}
}

func TestRejectedSnapshotNotReappliedUntilPrimaryChanges(t *testing.T) {
	p := newPair(t, false)
	p.follower.opt.Reload = func() error { return nil }
	p.sync(t)
	NewManager(Options{ConfDir: p.fDir, NodeID: "follower-1"})
	m3, _ := NewManager(Options{ConfDir: p.fDir, NodeID: "follower-1", Now: p.fClock.Now})
	frole := RoleFollower
	m3.Update(ConfigUpdate{Role: &frole, Secret: strPtr(testSecret), PrimaryURL: strPtr(p.server.URL)})
	defer m3.Stop()
	err := m3.SyncOnce(t.Context(), false)
	if err == nil || !strings.Contains(err.Error(), "previously prevented") {
		t.Fatalf("rejected snapshot was applied again: %v", err)
	}
	// a new primary state is accepted
	os.WriteFile(filepath.Join(p.pDir, "access", "fix.json"), []byte(`{}`), 0o600)
	p.pClock.Add(1e9)
	m3.opt.Reload = func() error { return nil }
	if err := m3.SyncOnce(t.Context(), false); err != nil {
		t.Fatalf("changed snapshot refused: %v", err)
	}
}

func TestValidateHookRejectsBeforeAnythingIsWritten(t *testing.T) {
	p := newPair(t, false)
	p.follower.opt.Validate = func(pl *Payload) error { return errors.New("schema mismatch") }
	os.MkdirAll(filepath.Join(p.fDir, "proxy"), 0o755)
	os.WriteFile(filepath.Join(p.fDir, "proxy", "local.config"), []byte(`{"local":true}`), 0o600)
	err := p.sync(t)
	if err == nil || !strings.Contains(err.Error(), "schema mismatch") {
		t.Fatalf("validation error not reported: %v", err)
	}
	if readFile(t, p.fDir, "proxy/local.config") != `{"local":true}` || readFile(t, p.fDir, "proxy/a.config") != "<missing>" {
		t.Fatal("files touched despite validation failure")
	}
	if p.reloads.Load() != 0 {
		t.Fatal("reload ran despite validation failure")
	}
}
