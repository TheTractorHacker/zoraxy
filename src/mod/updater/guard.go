package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// maxStartAttempts is how many times a freshly installed binary may be started
// without confirming health before it is rolled back (crash-loop protection).
const maxStartAttempts = 3

// watchdogGrace is how long after the marker deadline the out-of-process
// watchdog waits, so that the in-process guard normally acts first.
const watchdogGrace = 20 * time.Second

// StartGuard must be called very early in main(). If an update is pending it
// counts this start attempt and arms a timer that rolls back to the previous
// binary unless MarkHealthy is called first. It never touches the network.
func (m *Manager) StartGuard() {
	p := m.st.pending()
	if p == nil {
		return
	}
	p.Attempts++
	p.PID = os.Getpid()
	_ = m.st.savePending(p)
	m.audit("", fmt.Sprintf("pending update %s: start attempt %d, awaiting health confirmation", p.Tag, p.Attempts))
	if p.Attempts > maxStartAttempts {
		m.audit("", "start attempts exhausted, rolling back")
		m.rollbackPending("crash loop: new version did not stay up", true)
		return
	}
	wait := p.Deadline.Sub(m.cfg.Hooks.Now())
	if wait < 0 {
		wait = 0
	}
	time.AfterFunc(wait, func() {
		m.rollbackPending(fmt.Sprintf("not healthy within %ds", int(m.cfg.HealthyTimeout.Seconds())), true)
	})
}

// MarkHealthy confirms the new version is serving (admin HTTP listener up and
// proxy router initialised). It clears the pending marker, which disarms the
// guard and the watchdog. Safe to call on every start.
func (m *Manager) MarkHealthy() {
	p := m.st.pending()
	if p == nil {
		return
	}
	if err := m.st.claimPending(); err != nil {
		return // someone (guard/watchdog) is already rolling back
	}
	m.st.releasePendingClaim()
	m.st.addHistory(HistoryEntry{Time: m.cfg.Hooks.Now(), Action: "app_update", From: p.PrevTag, To: p.Tag, Result: "success", Detail: "new version confirmed healthy"})
	m.audit("", fmt.Sprintf("update to %s confirmed healthy", p.Tag))
}

// rollbackPending restores the previous binary recorded in the marker. When
// restart is true the restored binary is started in place.
func (m *Manager) rollbackPending(reason string, restart bool) {
	p := m.st.pending()
	if p == nil {
		return
	}
	if err := rollbackFromPending(m.st, p, reason, m.cfg.Hooks.Now(), m.audit); err != nil {
		return
	}
	if restart {
		_ = m.cfg.Hooks.Restart(p.Exe, p.Args)
	}
}

// rollbackFromPending is shared by the in-process guard and the watchdog.
func rollbackFromPending(st *store, p *Pending, reason string, now time.Time, audit func(actor, msg string)) error {
	if err := st.claimPending(); err != nil {
		return err // already confirmed healthy or rolled back elsewhere
	}
	defer st.releasePendingClaim()
	audit("", fmt.Sprintf("AUTO-ROLLBACK from %s to %s: %s", p.Tag, p.PrevTag, reason))
	if err := restorePrevious(p.Exe); err != nil {
		audit("", "AUTO-ROLLBACK failed: "+err.Error())
		st.addHistory(HistoryEntry{Time: now, Action: "auto_rollback", From: p.Tag, To: p.PrevTag, Result: "failed", Detail: err.Error()})
		return err
	}
	_ = st.saveInstalled(p.PrevInstalled)
	st.addHistory(HistoryEntry{Time: now, Action: "auto_rollback", From: p.Tag, To: p.PrevTag, Result: "rolled_back", Detail: reason})
	return nil
}

// RunWatchdog is the out-of-process rollback watchdog (`-updater_watchdog
// <pending.json>`). It polls until the marker disappears (healthy) or the
// deadline passes; then it terminates the unhealthy process, restores the
// previous binary and, unless a supervisor will do it, starts it again.
// It returns the process exit code.
func RunWatchdog(markerPath string, logf func(string, ...any)) int {
	st := &store{dir: filepath.Dir(markerPath)}
	audit := func(actor, msg string) {
		st.audit(time.Now(), "watchdog", msg)
		logf("[updater-watchdog] %s", msg)
	}
	for {
		p := st.pending()
		if p == nil {
			return 0 // confirmed healthy (or handled by the in-process guard)
		}
		if time.Now().After(p.Deadline.Add(watchdogGrace)) {
			audit("", "deadline passed without health confirmation")
			if err := rollbackFromPending(st, p, "watchdog: not healthy before deadline", time.Now(), audit); err != nil {
				return 0
			}
			terminate(p.PID, 10*time.Second)
			if p.Method != "systemd" {
				// No supervisor will relaunch it: start the restored binary.
				if _, err := spawnDetached(p.Exe, p.Args, st.path("watchdog.log")); err != nil {
					audit("", "could not start the restored binary: "+err.Error())
					return 1
				}
				audit("", "restored binary started")
			} else {
				audit("", "restored binary in place; waiting for systemd to restart the service")
			}
			return 0
		}
		time.Sleep(2 * time.Second)
	}
}
