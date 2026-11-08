package updater

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreflight(t *testing.T) {
	f := newFixture(t)
	pf := f.m.RunPreflight(1 << 20)
	if pf.AppBlocked != "" {
		t.Fatalf("unexpected block: %s (%+v)", pf.AppBlocked, pf.Checks)
	}
	if pf.Method != "manual" || pf.Executable != f.exe {
		t.Errorf("method=%s exe=%s", pf.Method, pf.Executable)
	}

	f.env["INVOCATION_ID"] = "abc"
	if got := f.m.RunPreflight(0).Method; got != "systemd" {
		t.Errorf("want systemd, got %s", got)
	}

	f.free = 1 << 20
	if pf := f.m.RunPreflight(50 << 20); pf.AppBlocked == "" || !strings.Contains(pf.AppBlocked, "free") {
		t.Errorf("low disk must block: %q", pf.AppBlocked)
	}
	f.free = 10 << 30

	f.build(func(c *Config) { c.InDocker = true })
	if pf := f.m.RunPreflight(0); pf.Method != "docker" || !strings.Contains(pf.AppBlocked, "Docker") {
		t.Errorf("docker must disable: %+v", pf)
	}

	f.build(func(c *Config) { c.GOOS = "windows" })
	if pf := f.m.RunPreflight(0); pf.AppBlocked == "" {
		t.Error("non-linux must be blocked")
	}

	f.build(func(c *Config) { c.ConfDir = filepath.Join(f.root, "missing") })
	if pf := f.m.RunPreflight(0); pf.AppBlocked == "" || pf.DBBlocked == "" {
		t.Error("missing conf must block")
	}
}

func TestPreflightNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions are not enforced for root")
	}
	f := newFixture(t)
	must(t, os.Chmod(filepath.Dir(f.exe), 0o555))
	t.Cleanup(func() { os.Chmod(filepath.Dir(f.exe), 0o755) })
	pf := f.m.RunPreflight(0)
	if !strings.Contains(pf.AppBlocked, "Cannot write") {
		t.Errorf("unwritable binary dir must block, got %q", pf.AppBlocked)
	}
}

func TestBackupContents(t *testing.T) {
	f := newFixture(t)
	p, err := CreateBackup(f.conf, filepath.Join(f.root, "sys.db"), filepath.Join(f.root, "sys.uuid"), time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC))
	must(t, err)
	if filepath.Base(p) != "zoraxy-pre-update-20260506-070809.zip" || filepath.Dir(p) != filepath.Join(f.root, "backups") {
		t.Fatalf("unexpected backup path %s", p)
	}
	zr, err := zip.OpenReader(p)
	must(t, err)
	defer zr.Close()
	got := map[string]bool{}
	for _, e := range zr.File {
		got[e.Name] = true
	}
	for _, want := range []string{"conf/proxy/a.json", "conf/version", "sys.db", "sys.uuid"} {
		if !got[want] {
			t.Errorf("backup lacks %s (has %v)", want, got)
		}
	}
	if left, _ := filepath.Glob(p + ".partial"); len(left) != 0 {
		t.Error("partial file left behind")
	}
	// directory-style database (leveldb) is included recursively
	must(t, os.Remove(filepath.Join(f.root, "sys.db")))
	must(t, os.MkdirAll(filepath.Join(f.root, "sys.db"), 0o755))
	must(t, os.WriteFile(filepath.Join(f.root, "sys.db", "000001.log"), []byte("x"), 0o644))
	p2, err := CreateBackup(f.conf, filepath.Join(f.root, "sys.db"), "", time.Now())
	must(t, err)
	zr2, _ := zip.OpenReader(p2)
	defer zr2.Close()
	found := false
	for _, e := range zr2.File {
		found = found || e.Name == "sys.db/000001.log"
	}
	if !found {
		t.Error("directory database not backed up")
	}
	if _, err := CreateBackup(filepath.Join(f.root, "nope"), "", "", time.Now()); err == nil {
		t.Error("missing conf must fail")
	}
}

func TestBackupPrune(t *testing.T) {
	f := newFixture(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < keepBackups+3; i++ {
		_, err := CreateBackup(f.conf, "", "", base.Add(time.Duration(i)*time.Minute))
		must(t, err)
	}
	ents, _ := os.ReadDir(BackupDir(f.conf))
	if len(ents) != keepBackups {
		t.Errorf("want %d backups, have %d", keepBackups, len(ents))
	}
}

func TestInstallRotation(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "zoraxy")
	os.WriteFile(exe, []byte("v0"), 0o755)
	for i := 1; i <= 5; i++ {
		nb := filepath.Join(dir, "new")
		os.WriteFile(nb, []byte("v"+string(rune('0'+i))), 0o600)
		must(t, installBinary(exe, nb, 3))
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	if read(exe) != "v5" || read(prevSlot(exe, 0)) != "v4" || read(prevSlot(exe, 1)) != "v3" || read(prevSlot(exe, 2)) != "v2" {
		t.Errorf("rotation wrong: %s %s %s %s", read(exe), read(prevSlot(exe, 0)), read(prevSlot(exe, 1)), read(prevSlot(exe, 2)))
	}
	if _, err := os.Stat(prevSlot(exe, 3)); err == nil {
		t.Error("more than 3 previous binaries kept")
	}
	must(t, restorePrevious(exe))
	if read(exe) != "v4" || read(prevSlot(exe, 0)) != "v3" || read(exe+".rolledback") != "v5" {
		t.Errorf("restore wrong: %s %s %s", read(exe), read(prevSlot(exe, 0)), read(exe+".rolledback"))
	}
	if err := restorePrevious(filepath.Join(dir, "other")); err == nil {
		t.Error("restore without prev must fail")
	}
}

func TestUpdateHappyPath(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.5-rc5-grpcfix.1", false, time.Hour, "NEW-BINARY"))

	res, err := f.m.Check(context.Background(), true)
	must(t, err)
	if !res.UpdateAvailable || res.Latest.Tag != "v3.3.5-rc5-grpcfix.1" || res.Latest.Notes == "" || res.AssetSize != int64(len("NEW-BINARY")) {
		t.Fatalf("check: %+v", res)
	}

	must(t, f.m.RunApp(context.Background(), RunOptions{Backup: true, Actor: "tester"}))
	if f.readExe() != "NEW-BINARY" {
		t.Fatalf("binary not replaced: %q", f.readExe())
	}
	if b, _ := os.ReadFile(f.exe + ".prev"); string(b) != oldBinary {
		t.Errorf("prev binary: %q", b)
	}
	if st, _ := os.Stat(f.exe); st.Mode().Perm()&0o111 == 0 {
		t.Error("new binary not executable")
	}
	if f.restarts != 1 || f.spawned != 1 {
		t.Errorf("restarts=%d watchdogs=%d", f.restarts, f.spawned)
	}
	if f.leftoverTemp() != nil {
		t.Errorf("temp files left: %v", f.leftoverTemp())
	}
	if zips, _ := filepath.Glob(filepath.Join(f.root, "backups", "zoraxy-pre-update-*.zip")); len(zips) != 1 {
		t.Errorf("expected one backup, got %v", zips)
	}
	p := f.m.st.pending()
	if p == nil || p.Tag != "v3.3.5-rc5-grpcfix.1" || p.PrevBinary != f.exe+".prev" || p.Exe != f.exe {
		t.Fatalf("pending marker: %+v", p)
	}
	if f.m.Status().State != "restarting" {
		t.Errorf("state %s", f.m.Status().State)
	}
	// Preflight blocks a second update while unconfirmed.
	if f.m.RunPreflight(0).AppBlocked == "" {
		t.Error("pending update must block another update")
	}

	// New process comes up healthy.
	f.m.MarkHealthy()
	if f.m.st.pending() != nil {
		t.Error("marker must be removed")
	}
	h := f.m.History()
	if len(h) != 2 || h[1].Result != "success" || h[0].Result != "installed" {
		t.Errorf("history: %+v", h)
	}
	// Audit trail exists.
	if b, _ := os.ReadFile(filepath.Join(f.conf, "updater", "audit.log")); !strings.Contains(string(b), "[tester]") || !strings.Contains(string(b), "confirmed healthy") {
		t.Errorf("audit log: %s", b)
	}

	// Now the installed record identifies the running build; no update, forward only.
	f.m.cacheRes = nil
	res, err = f.m.Check(context.Background(), true)
	must(t, err)
	if res.UpdateAvailable || !res.Current.Known || res.Current.Tag != "v3.3.5-rc5-grpcfix.1" {
		t.Errorf("after update: %+v", res)
	}
	f.unbusy()
	if err := f.m.RunApp(context.Background(), RunOptions{}); err == nil || !strings.Contains(err.Error(), "nothing to install") {
		t.Error("updating to the same release must be refused")
	}
}

func TestForwardOnly(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.5-x.1", false, 10*24*time.Hour, "NEW1"))
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	f.m.MarkHealthy()
	f.unbusy()
	// only an older release is on offer now
	f.gh.set(f.release("v3.3.5-x.1", false, 10*24*time.Hour, "NEW1"), f.release("v3.3.4-hot.1", false, time.Hour, "OLDER"))
	err := f.m.RunApp(context.Background(), RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "nothing to install") {
		t.Fatalf("expected forward-only refusal, got %v", err)
	}
	if f.readExe() != "NEW1" {
		t.Error("binary must be untouched")
	}
}

func TestUpdateFailuresLeaveBinaryUntouched(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*fakeRelease)
		wantErr string
	}{
		{"tampered binary", func(r *fakeRelease) { r.TamperBinary = true }, "checksum mismatch"},
		{"tampered sums", func(r *fakeRelease) { r.TamperSums = true }, "signature verification FAILED"},
		{"wrong signing key", func(r *fakeRelease) { r.WrongKey = true }, "signature verification FAILED"},
		{"replayed sums signed for another tag", func(r *fakeRelease) { r.SignedTag = "v3.3.5-old.1" }, "does not match release tag"},
		{"legacy sums without release header", func(r *fakeRelease) { r.NoHeader = true }, "release header"},
		{"missing signature asset", func(r *fakeRelease) { r.NoSig = true }, "not signed"},
		{"missing platform asset", func(r *fakeRelease) { r.NoBinary = true }, "no asset"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			r := f.release("v3.3.6-x.1", false, time.Hour, "NEW")
			c.mut(&r)
			f.gh.set(r)
			err := f.m.RunApp(context.Background(), RunOptions{Backup: false})
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
			if f.readExe() != oldBinary {
				t.Error("running binary was modified")
			}
			if _, e := os.Stat(f.exe + ".prev"); e == nil {
				t.Error("no prev should be created on failure")
			}
			if f.leftoverTemp() != nil {
				t.Errorf("temp left: %v", f.leftoverTemp())
			}
			if f.restarts != 0 || f.m.st.pending() != nil {
				t.Error("must not restart or leave a marker")
			}
			if s := f.m.Status(); s.State != "failed" || s.Error == "" || f.m.Busy() {
				t.Errorf("status: %+v busy=%v", s, f.m.Busy())
			}
		})
	}
}

// A validly signed older build (lower signed build number) must not be
// installable over a newer one, even if GitHub metadata claims it is newer.
func TestSignedBuildMustIncrease(t *testing.T) {
	f := newFixture(t)
	r1 := f.release("v3.3.6-x.1", false, 10*24*time.Hour, "NEW1")
	r1.Build = 50
	f.gh.set(r1)
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	f.m.MarkHealthy()
	f.unbusy()
	if inst := f.m.st.installed(); inst == nil || inst.Build != 50 {
		t.Fatalf("installed build not recorded: %+v", inst)
	}
	r2 := f.release("v3.3.7-x.1", false, time.Hour, "NEW2")
	r2.Build = 49 // replayed/older signed content
	f.gh.set(r2)
	err := f.m.RunApp(context.Background(), RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "build") {
		t.Fatalf("expected build downgrade refusal, got %v", err)
	}
	if f.readExe() != "NEW1" {
		t.Error("binary must be untouched")
	}
	f.unbusy()
	r2.Build = 51
	f.gh.set(r2)
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
}

func TestBackupFailureAbortsBeforeDownload(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	// make <conf>/../backups an ordinary file so the backup cannot be created
	must(t, os.WriteFile(filepath.Join(f.root, "backups"), []byte("x"), 0o644))
	err := f.m.RunApp(context.Background(), RunOptions{Backup: true})
	if err == nil || !strings.Contains(err.Error(), "backup failed") {
		t.Fatalf("got %v", err)
	}
	if f.gh.hit("/dl/v3.3.6-x.1/"+testAsset) != 0 {
		t.Error("binary was downloaded despite backup failure")
	}
	if f.readExe() != oldBinary {
		t.Error("binary modified")
	}
}

func TestSmokeFailureAborts(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	f.smoke = func(context.Context, string) (string, error) { return "", errors.New("exec format error") }
	err := f.m.RunApp(context.Background(), RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "smoke test") {
		t.Fatalf("got %v", err)
	}
	f.smoke = func(context.Context, string) (string, error) { return "Zoraxy - Version 9.9.9", nil }
	if err := f.m.RunApp(context.Background(), RunOptions{}); err == nil || !strings.Contains(err.Error(), "unexpected version") {
		t.Fatalf("version mismatch must fail, got %v", err)
	}
	if f.readExe() != oldBinary || f.restarts != 0 {
		t.Error("binary changed or restarted")
	}
}

func TestRestartFailureReverts(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	f.build(func(c *Config) {
		c.Hooks.Restart = func(string, []string) error { return errors.New("exec denied") }
	})
	err := f.m.RunApp(context.Background(), RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "restart failed") {
		t.Fatalf("got %v", err)
	}
	if f.readExe() != oldBinary {
		t.Errorf("old binary must be restored, have %q", f.readExe())
	}
	if f.m.st.pending() != nil || f.m.st.installed() != nil {
		t.Error("marker/installed record must be cleared")
	}
}

func TestDockerRefusesUpdate(t *testing.T) {
	f := newFixture(t)
	f.build(func(c *Config) { c.InDocker = true })
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	if err := f.m.RunApp(context.Background(), RunOptions{}); err == nil || !strings.Contains(err.Error(), "Docker") {
		t.Fatalf("got %v", err)
	}
	if err := f.m.RunRollback(context.Background(), RunOptions{}); err == nil {
		t.Error("rollback must be refused in docker")
	}
}

func TestOnlyOneRunningUpdate(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	gate := make(chan struct{})
	f.smoke = func(context.Context, string) (string, error) { <-gate; return "Zoraxy 3.3.6", nil }
	must(t, f.m.StartApp(RunOptions{}))
	if err := f.m.StartApp(RunOptions{}); !errors.Is(err, errBusy) {
		t.Errorf("second start: %v", err)
	}
	if err := f.m.StartDB(RunOptions{}); !errors.Is(err, errBusy) {
		t.Errorf("db during app: %v", err)
	}
	close(gate)
	deadline := time.Now().Add(5 * time.Second)
	for f.m.Status().State != "restarting" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.m.Status().State != "restarting" {
		t.Fatalf("state %s err %s", f.m.Status().State, f.m.Status().Error)
	}
}

func TestManualRollback(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	f.m.MarkHealthy()
	f.unbusy()

	must(t, f.m.RunRollback(context.Background(), RunOptions{Actor: "tester"}))
	if f.readExe() != oldBinary {
		t.Errorf("not rolled back: %q", f.readExe())
	}
	if f.restarts != 2 {
		t.Errorf("restarts=%d", f.restarts)
	}
	if f.m.st.installed() != nil {
		t.Error("installed record of the abandoned release must be dropped")
	}
	h := f.m.History()
	if last := h[len(h)-1]; last.Action != "rollback" || last.Result != "success" {
		t.Errorf("history: %+v", h)
	}
	f.unbusy()
	if err := f.m.RunRollback(context.Background(), RunOptions{}); err == nil {
		t.Error("second rollback has nothing to restore")
	}
}

func TestGuardRollsBackWhenNotHealthy(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	f.build(func(c *Config) { c.HealthyTimeout = 150 * time.Millisecond })
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	if f.restarts != 1 {
		t.Fatal("setup")
	}
	// "New process" starts: the guard arms and nobody confirms health.
	f.m.StartGuard()
	deadline := time.Now().Add(3 * time.Second)
	for f.restartCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if f.restartCount() != 2 {
		t.Fatal("guard did not restart after rollback")
	}
	if f.readExe() != oldBinary {
		t.Errorf("binary not restored: %q", f.readExe())
	}
	if f.m.st.pending() != nil || f.m.st.installed() != nil {
		t.Error("state must be cleaned")
	}
	h := f.m.History()
	if last := h[len(h)-1]; last.Action != "auto_rollback" || last.Result != "rolled_back" {
		t.Errorf("history: %+v", h)
	}
}

func TestGuardHealthyDisarms(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	f.build(func(c *Config) { c.HealthyTimeout = 150 * time.Millisecond })
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	f.m.StartGuard()
	f.m.MarkHealthy()
	time.Sleep(400 * time.Millisecond)
	if f.readExe() != "NEW" || f.restartCount() != 1 {
		t.Errorf("healthy update must stay: exe=%q restarts=%d", f.readExe(), f.restarts)
	}
}

func TestGuardCrashLoop(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	for i := 0; i < maxStartAttempts; i++ {
		f.m.StartGuard() // each crash + supervisor restart counts one attempt
		if f.readExe() != "NEW" {
			t.Fatalf("rolled back too early at attempt %d", i+1)
		}
	}
	f.m.StartGuard()
	if f.readExe() != oldBinary {
		t.Error("crash loop must trigger rollback")
	}
}

func TestGuardNoPendingIsNoop(t *testing.T) {
	f := newFixture(t)
	f.m.StartGuard()
	f.m.MarkHealthy()
	if f.restarts != 0 {
		t.Error("nothing should happen")
	}
}

func TestWatchdogRollsBack(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	must(t, f.m.RunApp(context.Background(), RunOptions{}))
	p := f.m.st.pending()
	p.Method = "systemd" // do not try to relaunch a process in the test
	p.PID = 0
	p.Deadline = time.Now().Add(-time.Minute)
	must(t, f.m.st.savePending(p))
	if code := RunWatchdog(f.m.st.path(pendingFile), func(string, ...any) {}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if f.readExe() != oldBinary {
		t.Error("watchdog did not restore the previous binary")
	}
	// Healthy case: marker gone, returns immediately without touching anything.
	if code := RunWatchdog(f.m.st.path(pendingFile), func(string, ...any) {}); code != 0 {
		t.Fatal("watchdog with no marker must exit 0")
	}
}

func TestDatabaseUpdate(t *testing.T) {
	f := newFixture(t)
	t.Chdir(f.root)
	runs := 0
	f.build(func(c *Config) {
		c.ConfDir = "./conf"
		c.Migrate = func() error {
			runs++
			os.WriteFile("conf/version", []byte("336"), 0o644)
			os.WriteFile("conf/proxy/new.json", []byte("{}"), 0o644)
			return nil
		}
	})
	must(t, f.m.RunDB(context.Background(), RunOptions{Backup: true}))
	logs := ""
	for _, l := range f.m.Status().Log {
		logs += l.Text + "\n"
	}
	for _, want := range []string{`"335" -> "336"`, "added    conf/proxy/new.json", "modified conf/version"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q:\n%s", want, logs)
		}
	}
	if zips, _ := filepath.Glob(filepath.Join(f.root, "backups", "*.zip")); len(zips) != 1 {
		t.Errorf("backup missing: %v", zips)
	}
	// Idempotent: second run reports no changes.
	must(t, f.m.RunDB(context.Background(), RunOptions{}))
	logs = ""
	for _, l := range f.m.Status().Log {
		logs += l.Text + "\n"
	}
	if !strings.Contains(logs, "No changes") || runs != 2 {
		t.Errorf("second run: runs=%d log:\n%s", runs, logs)
	}
	// Migration that panics (as upstream migrations do on bad input) becomes an error.
	f.build(func(c *Config) { c.ConfDir = "./conf"; c.Migrate = func() error { panic("bad version file") } })
	if err := f.m.RunDB(context.Background(), RunOptions{}); err == nil || !strings.Contains(err.Error(), "bad version file") {
		t.Errorf("got %v", err)
	}
	if f.m.Busy() {
		t.Error("must not stay busy after failure")
	}
}

func TestDatabaseBlockedWhenConfDiffers(t *testing.T) {
	f := newFixture(t)
	t.Chdir(f.root)
	f.build(func(c *Config) { c.Migrate = func() error { return nil } }) // ConfDir is the absolute temp path != ./conf? same dir!
	f.build(func(c *Config) { c.ConfDir = f.conf + "/proxy"; c.Migrate = func() error { return nil } })
	if pf := f.m.RunPreflight(0); pf.DBBlocked == "" {
		t.Error("custom -conf must disable DB migration")
	}
	f.build(func(c *Config) { c.Migrate = nil })
	if pf := f.m.RunPreflight(0); pf.DBBlocked == "" {
		t.Error("missing migrate func must disable")
	}
}

func TestSettings(t *testing.T) {
	f := newFixture(t)
	s := f.m.Settings()
	if s.Channel != ChannelStable || !s.BackupFirst {
		t.Fatalf("defaults: %+v", s)
	}
	must(t, f.m.SetChannel(ChannelBeta))
	must(t, f.m.SetBackupFirst(false))
	f.build(nil)
	if s := f.m.Settings(); s.Channel != ChannelBeta || s.BackupFirst {
		t.Errorf("not persisted: %+v", s)
	}
	if f.m.SetChannel("nightly") == nil {
		t.Error("invalid channel accepted")
	}
}

func TestBetaChannelPicksPrerelease(t *testing.T) {
	f := newFixture(t)
	f.gh.set(f.release("v3.3.6-s.1", false, 48*time.Hour, "S"), f.release("v3.3.6-b.2", true, time.Hour, "B"))
	res, err := f.m.Check(context.Background(), true)
	must(t, err)
	if res.Latest.Tag != "v3.3.6-s.1" {
		t.Errorf("stable: %s", res.Latest.Tag)
	}
	must(t, f.m.SetChannel(ChannelBeta))
	res, err = f.m.Check(context.Background(), false) // cache is per channel
	must(t, err)
	if res.Latest.Tag != "v3.3.6-b.2" {
		t.Errorf("beta: %s", res.Latest.Tag)
	}
}

func TestPlatformAssetSelection(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64", "arm", "386", "riscv64", "mipsle"} {
		f := newFixture(t)
		f.build(func(c *Config) { c.GOARCH = arch })
		r := f.release("v3.3.6-x.1", false, time.Hour, "NEW")
		r.NoBinary = true
		r.ArchAssets = []string{AssetName("linux", arch)}
		f.gh.set(r)
		res, err := f.m.Check(context.Background(), true)
		must(t, err)
		if res.AssetName != "zoraxy_linux_"+arch || !res.UpdateAvailable {
			t.Errorf("%s: %+v", arch, res)
		}
	}
	f := newFixture(t)
	f.build(func(c *Config) { c.GOARCH = "s390x" })
	f.gh.set(f.release("v3.3.6-x.1", false, time.Hour, "NEW"))
	res, err := f.m.Check(context.Background(), true)
	must(t, err)
	if res.UpdateAvailable || !strings.Contains(res.Reason, "no asset") {
		t.Errorf("unsupported arch: %+v", res)
	}
}

func TestRefuseNonHTTPS(t *testing.T) {
	f := newFixture(t)
	f.build(func(c *Config) { c.AllowHTTP = false })
	if _, err := f.m.Check(context.Background(), true); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Errorf("http must be refused by default, got %v", err)
	}
}
