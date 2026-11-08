package updater

import (
	"fmt"
	"os"
	"path/filepath"
)

// Check statuses.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
)

// PreflightCheck is one line of the preflight panel.
type PreflightCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Preflight is the result of the environment checks.
type Preflight struct {
	Checks     []PreflightCheck `json:"checks"`
	Method     string           `json:"restart_method"`
	Executable string           `json:"executable"`
	// AppBlocked / DBBlocked are non-empty when the matching button must be
	// disabled; the text is the reason shown to the user.
	AppBlocked string `json:"app_blocked"`
	DBBlocked  string `json:"db_blocked"`
	RollbackOK bool   `json:"rollback_available"`
	Busy       bool   `json:"busy"`
	Pending    bool   `json:"pending_confirmation"`
}

func writableDir(dir string) error {
	f, err := os.CreateTemp(dir, ".zoraxy-wtest-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// RunPreflight checks whether an update can be performed. assetSize is the
// size of the release binary if known (0 = unknown).
func (m *Manager) RunPreflight(assetSize int64) Preflight {
	pf := Preflight{Method: m.RestartMethod(), Busy: m.Busy()}
	add := func(id, label, status, detail string) {
		pf.Checks = append(pf.Checks, PreflightCheck{id, label, status, detail})
	}
	var appFail []string
	fail := func(id, label, detail string) {
		add(id, label, StatusFail, detail)
		appFail = append(appFail, detail)
	}

	// Platform
	if !platformSupported || m.cfg.GOOS != "linux" {
		fail("platform", "Platform", fmt.Sprintf("Releases are published for Linux only (this is %s/%s).", m.cfg.GOOS, m.cfg.GOARCH))
	} else {
		add("platform", "Platform", StatusOK, AssetName(m.cfg.GOOS, m.cfg.GOARCH))
	}

	// Executable
	exe, err := m.exePath()
	var exeDir string
	if err != nil {
		fail("exe", "Running binary", "Cannot determine the running binary path: "+err.Error())
	} else {
		pf.Executable = exe
		exeDir = filepath.Dir(exe)
		add("exe", "Running binary", StatusOK, exe)
		if err := writableDir(exeDir); err != nil {
			fail("exe_writable", "Binary directory writable", fmt.Sprintf("Cannot write to %s (%v). Fix the directory permissions for the service user.", exeDir, err))
		} else {
			add("exe_writable", "Binary directory writable", StatusOK, exeDir)
		}
	}

	// conf
	confOK := true
	if st, err := os.Stat(m.cfg.ConfDir); err != nil || !st.IsDir() {
		confOK = false
		fail("conf", "Config directory writable", fmt.Sprintf("Config directory %s does not exist.", m.cfg.ConfDir))
	} else if err := writableDir(m.cfg.ConfDir); err != nil {
		confOK = false
		fail("conf", "Config directory writable", fmt.Sprintf("Cannot write to %s (%v).", m.cfg.ConfDir, err))
	} else {
		add("conf", "Config directory writable", StatusOK, m.cfg.ConfDir)
	}

	// Backup location: <conf>/../backups, created on demand.
	bdir := BackupDir(m.cfg.ConfDir)
	probe := bdir
	if _, err := os.Stat(probe); err != nil {
		probe = filepath.Dir(bdir)
	}
	if err := writableDir(probe); err != nil {
		add("backup_dir", "Backup directory writable", StatusWarn, fmt.Sprintf("Cannot write to %s (%v); \"back up first\" will fail and abort the update.", probe, err))
	} else {
		add("backup_dir", "Backup directory writable", StatusOK, bdir)
	}

	// Restart method
	switch pf.Method {
	case "docker":
		fail("restart", "Restart method", "Running in Docker: in-app updating is disabled. Pull a new image and recreate the container instead.")
	case "systemd":
		add("restart", "Restart method", StatusOK, "systemd: the process re-executes the new binary in place (same PID); if that fails it exits with status 75 and relies on Restart=on-failure/always.")
	default:
		add("restart", "Restart method", StatusOK, "manual: the process re-executes the new binary in place.")
	}

	// Disk space
	need := uint64(assetSize) * 2
	if assetSize <= 0 {
		need = 128 << 20
	}
	if exeDir != "" {
		if free, err := m.cfg.Hooks.FreeSpace(exeDir); err != nil {
			add("disk", "Disk space", StatusWarn, "Could not determine free space: "+err.Error())
		} else if free < need {
			fail("disk", "Disk space", fmt.Sprintf("Only %d MiB free next to the binary, need about %d MiB.", free>>20, need>>20))
		} else {
			add("disk", "Disk space", StatusOK, fmt.Sprintf("%d MiB free, need about %d MiB", free>>20, need>>20))
		}
	}

	// A previous update that was never confirmed healthy.
	if m.st.pending() != nil {
		fail("pending", "Previous update", "A previous update is still waiting for health confirmation.")
	}

	// Rollback availability
	if exe != "" {
		if _, err := os.Stat(prevSlot(exe, 0)); err == nil {
			pf.RollbackOK = true
		}
	}
	pf.Pending = m.st.pending() != nil

	if len(appFail) > 0 {
		pf.AppBlocked = appFail[0]
	}
	if pf.Busy {
		pf.AppBlocked = "Another update operation is running."
	}

	// Database migration
	switch {
	case pf.Busy:
		pf.DBBlocked = "Another update operation is running."
	case m.cfg.Migrate == nil:
		pf.DBBlocked = "Database migration is not available in this build."
	case !confOK:
		pf.DBBlocked = "The config directory is not writable."
	}
	return pf
}
