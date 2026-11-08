package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func TestApplyReplacesRootsAndKeepsNodeLocalData(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	writeTree(t, src)
	writeTree(t, dst)
	// follower specific differences
	os.WriteFile(filepath.Join(dst, "proxy", "a.config"), []byte(`{"old":1}`), 0o600)
	os.WriteFile(filepath.Join(dst, "proxy", "stale.config"), []byte(`{"stale":1}`), 0o600)
	os.WriteFile(filepath.Join(dst, "sys.uuid"), []byte("FOLLOWER-UUID"), 0o600)
	os.WriteFile(filepath.Join(dst, "auth_users.json"), []byte("FOLLOWER-ADMIN"), 0o600)

	p, _ := CollectFiles(src, false)
	ap := &Applier{ConfDir: dst}
	if _, err := ap.ApplyPayload(p, BackupTag(time.Now())); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dst, "proxy/a.config"); got != `{"RootOrMatchingDomain":"a.example.com"}` {
		t.Fatalf("a.config not replaced: %s", got)
	}
	if readFile(t, dst, "proxy/stale.config") != "<missing>" {
		t.Fatal("deleted-on-primary config survived on the follower")
	}
	if readFile(t, dst, "sys.uuid") != "FOLLOWER-UUID" {
		t.Fatal("sys.uuid modified")
	}
	if readFile(t, dst, "auth_users.json") != "FOLLOWER-ADMIN" {
		t.Fatal("follower admin data was touched")
	}
	if readFile(t, dst, "webui/webui.key") != "WEBUI-TLS-PRIVATE-KEY" {
		t.Fatal("webui cert touched")
	}
	// certs untouched when not synced
	if readFile(t, dst, "certs/a.pem") != "CERT-A" {
		t.Fatal("certs touched although sync certificates is off")
	}
	// the old state was kept as backup
	bk, _ := filepath.Glob(filepath.Join(dst, StateDirName, "backup-*", "proxy", "stale.config"))
	if len(bk) != 1 {
		t.Fatal("previous config not backed up")
	}
}

func TestApplyFailureRollsBackEverything(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	writeTree(t, src)
	writeTree(t, dst)
	os.WriteFile(filepath.Join(dst, "proxy", "a.config"), []byte(`{"keep":"me"}`), 0o600)
	os.WriteFile(filepath.Join(dst, "trusted_proxies.json"), []byte(`["keep"]`), 0o600)

	p, _ := CollectFiles(src, false)
	count := 0
	ap := &Applier{ConfDir: dst, beforeInstall: func(root string) error {
		count++
		if count == 5 { // fail after four roots were already swapped
			return errors.New("injected failure")
		}
		return nil
	}}
	if _, err := ap.ApplyPayload(p, BackupTag(time.Now())); err == nil {
		t.Fatal("expected failure")
	}
	if readFile(t, dst, "proxy/a.config") != `{"keep":"me"}` || readFile(t, dst, "trusted_proxies.json") != `["keep"]` {
		t.Fatal("state not restored after failed apply")
	}
	for _, root := range baseRoots {
		if _, err := os.Lstat(filepath.Join(dst, root)); err != nil {
			t.Errorf("root %s lost after rollback: %v", root, err)
		}
	}
}

func TestApplyRollbackAfterSuccess(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	writeTree(t, src)
	os.MkdirAll(filepath.Join(dst, "proxy"), 0o755)
	os.WriteFile(filepath.Join(dst, "proxy", "orig.config"), []byte(`{}`), 0o600)

	p, _ := CollectFiles(src, false)
	applied, err := (&Applier{ConfDir: dst}).ApplyPayload(p, BackupTag(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, dst, "proxy/orig.config") != "<missing>" {
		t.Fatal("apply did not replace the proxy folder")
	}
	if err := applied.Rollback(); err != nil {
		t.Fatal(err)
	}
	if readFile(t, dst, "proxy/orig.config") != `{}` {
		t.Fatal("rollback did not restore the original proxy folder")
	}
	if readFile(t, dst, "redirect/r1.json") != "<missing>" {
		t.Fatal("rollback left newly installed roots behind")
	}
}

func TestApplyRejectsMaliciousPayload(t *testing.T) {
	dst := t.TempDir()
	files := []FileEntry{{Path: "../../outside.config", Data: []byte("{}")}}
	p := &Payload{Roots: ManagedRoots(false), Files: files, ContentHash: HashFiles(files)}
	if _, err := (&Applier{ConfDir: dst}).ApplyPayload(p, "t"); err == nil {
		t.Fatal("path traversal accepted")
	}
	// an executable bit in the snapshot is never honoured
	files = []FileEntry{{Path: "access/x.json", Mode: 0o777, Data: []byte("{}")}}
	p = &Payload{Roots: ManagedRoots(false), Files: files, ContentHash: HashFiles(files)}
	if _, err := (&Applier{ConfDir: dst}).ApplyPayload(p, "t2"); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dst, "access", "x.json"))
	if fi.Mode().Perm()&0o111 != 0 {
		t.Fatal("snapshot produced an executable file")
	}
}

func TestBackupsArePruned(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	writeTree(t, src)
	p, _ := CollectFiles(src, false)
	for i := 0; i < 6; i++ {
		tag := BackupTag(time.Unix(1_700_000_000+int64(i), 0))
		if _, err := (&Applier{ConfDir: dst}).ApplyPayload(p, tag); err != nil {
			t.Fatal(err)
		}
	}
	bk, _ := filepath.Glob(filepath.Join(dst, StateDirName, "backup-*"))
	if len(bk) != keepBackups {
		t.Fatalf("want %d backups got %d", keepBackups, len(bk))
	}
}
