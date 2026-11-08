package updater

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RunOptions are the per-run choices.
type RunOptions struct {
	Backup bool
	Actor  string
}

// StartApp starts an application update in the background.
func (m *Manager) StartApp(opts RunOptions) error {
	if err := m.reserve("app"); err != nil {
		return err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		_ = m.runApp(ctx, opts, true)
	}()
	return nil
}

// StartDB starts a database migration in the background.
func (m *Manager) StartDB(opts RunOptions) error {
	if err := m.reserve("db"); err != nil {
		return err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		_ = m.runDB(ctx, opts, true)
	}()
	return nil
}

// StartRollback starts a rollback to the previous binary in the background.
func (m *Manager) StartRollback(opts RunOptions) error {
	if err := m.reserve("rollback"); err != nil {
		return err
	}
	go func() {
		_ = m.runRollback(context.Background(), opts, true)
	}()
	return nil
}

// reserve is used by the Start* helpers so the HTTP handler gets a synchronous
// "busy" answer; the Run* functions then call begin with reserved=true.
func (m *Manager) reserve(op string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return errBusy
	}
	m.running = true
	m.status = Status{State: "running", Op: op, Started: m.cfg.Hooks.Now()}
	return nil
}

func (m *Manager) beginOp(op, actor string, reserved bool) error {
	if reserved {
		m.mu.Lock()
		m.status.Op = op
		m.mu.Unlock()
		m.audit(actor, "operation started: "+op)
		return nil
	}
	return m.begin(op, actor)
}

// RunApp performs the full application update synchronously (used by tests).
func (m *Manager) RunApp(ctx context.Context, opts RunOptions) error {
	return m.runApp(ctx, opts, false)
}

// RunDB performs the database migration synchronously.
func (m *Manager) RunDB(ctx context.Context, opts RunOptions) error {
	return m.runDB(ctx, opts, false)
}

// RunRollback performs a manual rollback synchronously.
func (m *Manager) RunRollback(ctx context.Context, opts RunOptions) error {
	return m.runRollback(ctx, opts, false)
}

func (m *Manager) runApp(ctx context.Context, opts RunOptions, reserved bool) (err error) {
	a := opts.Actor
	if err := m.beginOp("app", a, reserved); err != nil {
		return err
	}
	restarting := false
	defer func() { m.finish(a, err, restarting) }()

	// 1. Preflight
	m.stage(a, "Preflight checks")
	pf := m.RunPreflight(0)
	// Busy is expected here: we are the running operation.
	pf.AppBlocked = firstFail(pf)
	if pf.AppBlocked != "" {
		return fmt.Errorf("preflight failed: %s", pf.AppBlocked)
	}

	// 2. Resolve release
	m.stage(a, "Looking up the latest release")
	r, cur, err := m.resolve(ctx)
	if err != nil {
		return fmt.Errorf("release lookup failed: %w", err)
	}
	if !r.newer {
		return fmt.Errorf("nothing to install: %s", r.reason)
	}
	if !r.hasAssets {
		return fmt.Errorf("%s", r.reason)
	}
	m.logf(a, "Target release %s (%s, %d bytes), running %s", r.rel.Tag, r.asset.Name, r.asset.Size, cur.label())
	if pf2 := m.RunPreflight(r.asset.Size); firstFail(pf2) != "" {
		return fmt.Errorf("preflight failed: %s", firstFail(pf2))
	}
	tag, _ := ParseTag(r.rel.Tag)
	exe := pf.Executable
	exeDir := filepath.Dir(exe)

	// 3. Backup
	backupFile := ""
	if opts.Backup {
		m.stage(a, "Backing up configuration")
		backupFile, err = CreateBackup(m.cfg.ConfDir, m.cfg.DBPath, m.cfg.UUIDPath, m.cfg.Hooks.Now())
		if err != nil {
			return fmt.Errorf("backup failed, update aborted: %w", err)
		}
		m.logf(a, "Backup written to %s", backupFile)
	} else {
		m.logf(a, "Backup skipped by request")
	}

	// 4. Download + verify
	m.stage(a, "Downloading signature files")
	sums, err := m.src.fetchSmall(ctx, r.sums)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", SumsAsset, err)
	}
	sig, err := m.src.fetchSmall(ctx, r.sig)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", SigAsset, err)
	}
	if err := VerifySums(m.cfg.PubKey, sums, sig); err != nil {
		return err
	}
	m.logf(a, "SHA256SUMS signature is valid")
	installedBuild := 0
	if cur.Known {
		if inst := m.st.installed(); inst != nil {
			installedBuild = inst.Build
		}
	}
	hdr, err := CheckSumsHeader(sums, r.rel.Tag, installedBuild)
	if err != nil {
		return err
	}
	m.logf(a, "Signed release header: tag %s build %d", hdr.Tag, hdr.Build)

	m.stage(a, "Downloading "+r.asset.Name)
	tmp, err := os.CreateTemp(exeDir, ".zoraxy-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	os.Remove(tmpPath) // download() recreates it exclusively with mode 0600
	installed := false
	defer func() {
		if !installed {
			os.Remove(tmpPath)
		}
	}()
	sum, n, err := m.src.download(ctx, r.asset, tmpPath, m.progress)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	m.logf(a, "Downloaded %d bytes", n)
	if err := VerifyBinarySum(sums, r.asset.Name, sum); err != nil {
		return err
	}
	m.logf(a, "Binary checksum matches the signed SHA256SUMS")

	// 5. Smoke test
	m.stage(a, "Smoke test")
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	out, err := m.cfg.Hooks.Smoke(ctx, tmpPath)
	if err != nil {
		return fmt.Errorf("smoke test failed: %w (%s)", err, out)
	}
	if !strings.Contains(out, tag.BaseVersion()) {
		return fmt.Errorf("smoke test: unexpected version output %q (wanted %s)", out, tag.BaseVersion())
	}
	m.logf(a, "New binary reports: %s", out)

	// 6. Install
	m.stage(a, "Installing")
	prevInst := m.st.installed()
	if cur.Known {
		// the installed record describes the binary we are about to keep as .prev
	} else {
		prevInst = nil
	}
	if err := installBinary(exe, tmpPath, m.cfg.KeepPrev); err != nil {
		return fmt.Errorf("install failed (running binary untouched): %w", err)
	}
	installed = true
	newSHA := fmt.Sprintf("%x", sum)
	newInst := &Installed{Tag: r.rel.Tag, Published: r.rel.Published, SHA256: newSHA, Build: hdr.Build, Previous: prevInst}
	now := m.cfg.Hooks.Now()
	pend := &Pending{
		Tag: r.rel.Tag, PrevTag: cur.label(), Exe: exe, PrevBinary: prevSlot(exe, 0), Args: m.cfg.Args,
		Method: m.RestartMethod(), BackupFile: backupFile, PrevInstalled: prevInst,
		Started: now, Deadline: now.Add(m.cfg.HealthyTimeout),
	}
	revert := func(cause error) error {
		if rerr := restorePrevious(exe); rerr != nil {
			return fmt.Errorf("%w; ALSO failed to restore the previous binary: %v", cause, rerr)
		}
		_ = m.st.saveInstalled(prevInst)
		_ = m.st.claimPending()
		m.st.releasePendingClaim()
		m.logf(a, "Previous binary restored")
		return cause
	}
	if err := m.st.saveInstalled(newInst); err != nil {
		return revert(fmt.Errorf("cannot record installed release: %w", err))
	}
	if err := m.st.savePending(pend); err != nil {
		return revert(fmt.Errorf("cannot write pending-update marker: %w", err))
	}
	m.st.addHistory(HistoryEntry{Time: now, Action: "app_update", From: cur.label(), To: r.rel.Tag, Result: "installed", Detail: "awaiting restart and health confirmation"})
	m.logf(a, "Installed %s; previous binary kept as %s", r.rel.Tag, prevSlot(exe, 0))

	// 7. Watchdog + restart
	m.stage(a, "Restarting")
	if err := m.cfg.Hooks.SpawnWatchdog(prevSlot(exe, 0), m.st.path(pendingFile)); err != nil {
		m.logf(a, "WARNING: rollback watchdog could not be started (%v); relying on the in-process guard", err)
	} else {
		m.logf(a, "Rollback watchdog started (deadline %ds)", int(m.cfg.HealthyTimeout.Seconds()))
	}
	restarting = true
	m.finish(a, nil, true) // publish the "restarting" state before we may disappear
	m.logf(a, "Restarting via %s method", pend.Method)
	if d := m.cfg.Hooks.RestartDelay; d > 0 {
		time.Sleep(d)
	}
	if rerr := m.cfg.Hooks.Restart(exe, m.cfg.Args); rerr != nil {
		restarting = false
		m.st.addHistory(HistoryEntry{Time: m.cfg.Hooks.Now(), Action: "app_update", From: cur.label(), To: r.rel.Tag, Result: "failed", Detail: "restart failed: " + rerr.Error()})
		return revert(fmt.Errorf("restart failed: %w", rerr))
	}
	return nil
}

// firstFail returns the first failing preflight reason, ignoring "busy".
func firstFail(pf Preflight) string {
	for _, c := range pf.Checks {
		if c.Status == StatusFail {
			return c.Detail
		}
	}
	return ""
}

func (m *Manager) runDB(ctx context.Context, opts RunOptions, reserved bool) (err error) {
	a := opts.Actor
	if err := m.beginOp("db", a, reserved); err != nil {
		return err
	}
	defer func() { m.finish(a, err, false) }()

	m.stage(a, "Preflight checks")
	pf := m.RunPreflight(0)
	if pf.DBBlocked != "" && pf.DBBlocked != "Another update operation is running." {
		return fmt.Errorf("preflight failed: %s", pf.DBBlocked)
	}
	if opts.Backup {
		m.stage(a, "Backing up configuration")
		f, berr := CreateBackup(m.cfg.ConfDir, m.cfg.DBPath, m.cfg.UUIDPath, m.cfg.Hooks.Now())
		if berr != nil {
			return fmt.Errorf("backup failed, migration aborted: %w", berr)
		}
		m.logf(a, "Backup written to %s", f)
	} else {
		m.logf(a, "Backup skipped by request")
	}

	m.stage(a, "Running migrations")
	verFile := filepath.Join(m.cfg.ConfDir, "version")
	vBefore := readTrim(verFile)
	before := manifest(m.cfg.ConfDir)
	merr := runGuarded(m.cfg.Migrate)
	after := manifest(m.cfg.ConfDir)
	vAfter := readTrim(verFile)
	if merr != nil {
		m.st.addHistory(HistoryEntry{Time: m.cfg.Hooks.Now(), Action: "db_update", Result: "failed", Detail: merr.Error()})
		return fmt.Errorf("migration failed: %w (restore from the backup if the data looks wrong)", merr)
	}
	added, modified, removed := diffManifests(before, after)
	m.logf(a, "Schema version file: %q -> %q", vBefore, vAfter)
	if len(added)+len(modified)+len(removed) == 0 {
		m.logf(a, "No changes: the database/config is already up to date.")
	}
	for _, p := range added {
		m.logf(a, "added    conf/%s", p)
	}
	for _, p := range modified {
		m.logf(a, "modified conf/%s", p)
	}
	for _, p := range removed {
		m.logf(a, "removed  conf/%s", p)
	}
	m.st.addHistory(HistoryEntry{Time: m.cfg.Hooks.Now(), Action: "db_update", From: vBefore, To: vAfter, Result: "success",
		Detail: fmt.Sprintf("%d added, %d modified, %d removed", len(added), len(modified), len(removed))})
	return nil
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

// runGuarded runs fn, converting a panic (the migrations panic on bad input) into an error.
func runGuarded(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn()
}

func (m *Manager) runRollback(ctx context.Context, opts RunOptions, reserved bool) (err error) {
	a := opts.Actor
	if err := m.beginOp("rollback", a, reserved); err != nil {
		return err
	}
	restarting := false
	defer func() { m.finish(a, err, restarting) }()

	m.stage(a, "Rolling back to the previous version")
	if m.RestartMethod() == "docker" {
		return fmt.Errorf("rollback is disabled in Docker")
	}
	exe, err := m.exePath()
	if err != nil {
		return err
	}
	if m.st.pending() != nil {
		return fmt.Errorf("an update is awaiting health confirmation; it will roll back automatically")
	}
	cur, _ := m.current()
	inst := m.st.installed()
	if err := restorePrevious(exe); err != nil {
		return err
	}
	var prevInst *Installed
	if cur.Known && inst != nil {
		prevInst = inst.Previous
	}
	_ = m.st.saveInstalled(prevInst)
	to := "previous binary"
	if prevInst != nil {
		to = prevInst.Tag
	}
	m.st.addHistory(HistoryEntry{Time: m.cfg.Hooks.Now(), Action: "rollback", From: cur.label(), To: to, Result: "success", Detail: "manual rollback"})
	m.logf(a, "Previous binary restored (%s); the displaced binary is kept as %s.rolledback", to, exe)
	m.cacheMu.Lock()
	m.cacheRes = nil
	m.cacheMu.Unlock()

	restarting = true
	m.finish(a, nil, true)
	m.logf(a, "Restarting")
	if d := m.cfg.Hooks.RestartDelay; d > 0 {
		time.Sleep(d)
	}
	if rerr := m.cfg.Hooks.Restart(exe, m.cfg.Args); rerr != nil {
		restarting = false
		return fmt.Errorf("binary restored but restart failed: %w (restart Zoraxy manually)", rerr)
	}
	return nil
}
