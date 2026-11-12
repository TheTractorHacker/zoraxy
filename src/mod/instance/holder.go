package instance

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HolderLine is one plain sentence about the process holding a lock, with the next step, for example:
//
//	held by PID 3479504 (zoraxy, started 2h 5m ago), state: FROZEN (stopped, probably Ctrl+Z or SIGSTOP). Resume it: kill -CONT 3479504, or stop it: kill -9 3479504
//
// It is pure text from a ProcInfo, so it is unit tested without /proc. unit is the service name
// administrators use (normally "zoraxy").
func HolderLine(p ProcInfo, unit string) string {
	unit = strings.TrimSuffix(unit, ".service")
	if unit == "" {
		unit = "zoraxy"
	}
	pid := strconv.Itoa(p.Pid)
	if !p.Visible {
		n := Sanitize(p.Note)
		if n == "" {
			n = "details not readable"
		}
		return fmt.Sprintf("held by PID %d (%s). Run 'sudo ./zoraxy -doctor' to see more.", p.Pid, n)
	}
	started := ""
	if p.Age > 0 {
		started = ", started " + FormatAge(p.Age) + " ago"
	}
	head := fmt.Sprintf("held by PID %d (%s%s)", p.Pid, p.ExeBase(), started)
	switch {
	case p.Stopped() && p.State == 'T':
		return head + ", state: FROZEN (stopped, probably Ctrl+Z or SIGSTOP). Resume it: kill -CONT " + pid + ", or stop it: kill -9 " + pid
	case p.Stopped():
		return head + ", state: stopped by a debugger or tracer. Detach the debugger, or stop it: kill -9 " + pid
	case p.State == 'Z':
		return head + ", state: zombie (already exited; its parent has not collected it, it holds nothing)"
	case p.Unit != "":
		return head + ", running under systemd service " + Sanitize(p.Unit) + ". Stop it: sudo systemctl stop " + Sanitize(strings.TrimSuffix(p.Unit, ".service"))
	}
	return head + ", state: " + strings.SplitN(p.StateWord(), " (", 2)[0] + ", " + p.Where() + ". Stop it: kill " + pid + " (or sudo systemctl stop " + unit + " if it is the service)"
}

// LockHolderSummary names the process that holds the lock on path (a database file or directory), or
// returns "" when that cannot be determined (not Linux, /proc unreadable, permission denied, nobody
// holds it any more, only this process holds it). It never fails and never blocks for long.
func LockHolderSummary(path string) string {
	m, err := FindLockHolders(path)
	if err != nil {
		return ""
	}
	for _, pid := range m.Pids {
		if pid <= 0 || pid == os.Getpid() {
			continue
		}
		s := HolderLine(Describe(pid), "zoraxy")
		if m.Approximate {
			s += " (matched by inode only: likely, not certain)"
		}
		return s
	}
	return ""
}

// WatchLockWait is called while something waits for the lock on path (opening the database). After a
// short grace period it reports, through NotifyStatus, who holds the lock, and keeps the line fresh,
// so "systemctl status" under Type=notify says why the service is not ready yet. Call the returned
// function as soon as the wait is over. It is a cheap no-op when NOTIFY_SOCKET is unset.
func WatchLockWait(path string) (stop func()) {
	if !NotifyEnabled() {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once
	go func() {
		began := time.Now()
		t := time.NewTimer(1500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			holder := ""
			if m, err := FindLockHolders(path); err == nil {
				for _, pid := range m.Pids {
					if pid > 0 && pid != os.Getpid() {
						holder = fmt.Sprintf(" held by PID %d", pid)
						if p := Describe(pid); p.Stopped() {
							holder += " (FROZEN, probably Ctrl+Z: kill -CONT or kill -9 it)"
						}
						break
					}
				}
			}
			NotifyStatus(fmt.Sprintf("Waiting for the database lock%s (%ds)", holder, int(time.Since(began).Seconds())))
			t.Reset(5 * time.Second)
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}
