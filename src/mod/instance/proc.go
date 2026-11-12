package instance

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// ClockTicks is USER_HZ, 100 on every Linux Zoraxy targets.
const ClockTicks = 100

// ProcInfo is what we know about one process.
type ProcInfo struct {
	Pid       int
	PPid      int
	Comm      string // kernel name, max 15 chars
	Exe       string // executable path (empty when /proc/<pid>/exe is not readable)
	Cmdline   []string
	State     byte   // R S D T t Z I X ...
	Unit      string // "zoraxy.service", or "" when not under a service
	Scope     string // "session-3.scope", or ""
	CgroupRaw string
	Age       time.Duration // 0 when unknown
	Uid       int           // -1 when unknown
	Visible   bool          // false when /proc/<pid> could not be read (gone or permission denied)
	Note      string        // what could not be read
}

// Stopped reports T (stopped by a signal) or t (stopped by a tracer).
func (p ProcInfo) Stopped() bool { return p.State == 'T' || p.State == 't' }

// StateWord is a short human reading of the state letter.
func (p ProcInfo) StateWord() string {
	switch p.State {
	case 'R':
		return "running"
	case 'S':
		return "sleeping (normal, waiting for work)"
	case 'D':
		return "uninterruptible sleep (usually waiting on disk or network storage)"
	case 'T':
		return "stopped (frozen, probably Ctrl+Z or SIGSTOP)"
	case 't':
		return "stopped by a debugger or tracer"
	case 'Z':
		return "zombie (exited, waiting to be collected by its parent)"
	case 'I':
		return "idle"
	case 'X':
		return "dead"
	case 0:
		return "unknown"
	}
	return string(p.State)
}

// ParseStat parses /proc/<pid>/stat. The comm field is wrapped in parentheses and may itself contain
// spaces and parentheses, so it spans from the first '(' to the LAST ')'.
func ParseStat(text string) (comm string, state byte, ppid int, startTicks uint64, err error) {
	l := strings.Index(text, "(")
	r := strings.LastIndex(text, ")")
	if l < 0 || r < l {
		return "", 0, 0, 0, fmt.Errorf("malformed stat")
	}
	comm = text[l+1 : r]
	rest := strings.Fields(text[r+1:])
	if len(rest) < 1 || len(rest[0]) == 0 {
		return comm, 0, 0, 0, fmt.Errorf("stat has no state")
	}
	state = rest[0][0]
	if len(rest) > 1 {
		ppid, _ = strconv.Atoi(rest[1])
	}
	if len(rest) > 19 {
		startTicks, _ = strconv.ParseUint(rest[19], 10, 64)
	}
	return comm, state, ppid, startTicks, nil
}

// ParseCmdline splits /proc/<pid>/cmdline (NUL separated).
func ParseCmdline(text string) []string {
	text = strings.TrimRight(text, "\x00")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\x00")
}

// ParseBtime reads the boot time (unix seconds) from /proc/stat.
func ParseBtime(text string) int64 {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "btime ") {
			v, _ := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64)
			return v
		}
	}
	return 0
}

// ParseStatusUid reads the real uid from /proc/<pid>/status, -1 if absent.
func ParseStatusUid(text string) int {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line[4:])
			if len(f) > 0 {
				if v, err := strconv.Atoi(f[0]); err == nil {
					return v
				}
			}
		}
	}
	return -1
}

// ParseCgroup reduces /proc/<pid>/cgroup to the owning systemd service or scope.
// Handles cgroup v2 ("0::/path") and v1 ("1:name=systemd:/path").
func ParseCgroup(text string) (unit, scope, raw string) {
	var chosen string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" || strings.Contains(parts[1], "name=systemd") {
			chosen = parts[2]
			break
		}
		if chosen == "" {
			chosen = parts[2]
		}
	}
	raw = chosen
	for _, el := range strings.Split(path.Clean("/"+chosen), "/") {
		switch {
		case strings.HasSuffix(el, ".service") && !strings.HasPrefix(el, "user@") && unit == "":
			unit = el
		case strings.HasSuffix(el, ".scope") && scope == "":
			scope = el
		}
	}
	return
}

// ExeBase returns the best executable name: the exe link, else argv[0], else comm.
func (p ProcInfo) ExeBase() string {
	switch {
	case p.Exe != "":
		return strings.TrimSuffix(path.Base(p.Exe), " (deleted)")
	case len(p.Cmdline) > 0:
		return path.Base(p.Cmdline[0])
	}
	return p.Comm
}

// IsZoraxyName reports whether an executable name looks like Zoraxy ("zoraxy", "zoraxy_linux_amd64", ...).
func IsZoraxyName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "zoraxy")
}

// Where describes where the process lives in plain words.
func (p ProcInfo) Where() string {
	switch {
	case p.Unit != "":
		return "systemd service " + p.Unit
	case strings.HasPrefix(p.Scope, "session-"):
		return "a login session (" + p.Scope + "), so it was started by hand from a terminal or ssh"
	case p.Scope != "":
		return "scope " + p.Scope
	case p.CgroupRaw != "" && p.CgroupRaw != "/":
		return "cgroup " + p.CgroupRaw
	}
	return "unknown (cgroup not readable)"
}

// FormatAge renders a duration as "3d 4h", "12m", "40s".
func FormatAge(d time.Duration) string {
	if d <= 0 {
		return "unknown"
	}
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// Describe returns a one-line summary such as
// "PID 123 (zoraxy), state: stopped (frozen, probably Ctrl+Z or SIGSTOP), running for 3m, owner: ...".
func (p ProcInfo) Describe() string {
	if !p.Visible {
		n := p.Note
		if n == "" {
			n = "not readable"
		}
		return fmt.Sprintf("PID %d (%s)", p.Pid, n)
	}
	return fmt.Sprintf("PID %d (%s), state: %s, running for %s, owner: %s", p.Pid, p.ExeBase(), p.StateWord(), FormatAge(p.Age), p.Where())
}

// Explain gives a plain sentence plus the exact commands for the next step.
// intendedUnit is the service name admins should use (normally "zoraxy").
func (p ProcInfo) Explain(intendedUnit string) (sentence string, commands []string) {
	unit := strings.TrimSuffix(intendedUnit, ".service")
	if unit == "" {
		unit = "zoraxy"
	}
	pid := strconv.Itoa(p.Pid)
	if !p.Visible {
		return fmt.Sprintf("PID %d holds the lock but its details cannot be read (it is gone, or owned by another user: run -doctor with sudo).", p.Pid),
			[]string{"sudo ./zoraxy -doctor"}
	}
	switch {
	case p.Stopped():
		s := fmt.Sprintf("PID %d (%s) is frozen (state %c), probably by Ctrl+Z or SIGSTOP. A frozen process keeps its ports open but never answers, so connections pile up and the lock it holds blocks every other Zoraxy.", p.Pid, p.ExeBase(), p.State)
		return s, []string{
			"sudo kill -CONT " + pid + "    # resume it (it carries on, queued connections are served)",
			"sudo pkill -9 -P " + pid + " ; sudo kill -9 " + pid + "    # or kill it and its plugins (the database recovers cleanly)",
			"sudo systemctl restart " + unit + "    # then start the managed service",
		}
	case p.State == 'Z':
		return fmt.Sprintf("PID %d is a zombie: it already exited, its parent (PID %d) has not collected it. It no longer holds anything.", p.Pid, p.PPid),
			[]string{"sudo kill -9 " + strconv.Itoa(p.PPid) + "    # only if the parent is stuck"}
	case p.State == 'D':
		return fmt.Sprintf("PID %d is in uninterruptible sleep, normally waiting on slow or hung storage. It cannot be killed until the I/O returns.", p.Pid),
			[]string{"cat /proc/" + pid + "/stack    # needs root, shows where it waits", "dmesg | tail -50"}
	case p.Unit != "":
		return fmt.Sprintf("PID %d is the running instance and belongs to %s.", p.Pid, p.Unit),
			[]string{"systemctl status " + p.Unit, "sudo systemctl restart " + p.Unit}
	case strings.HasPrefix(p.Scope, "session-"):
		return fmt.Sprintf("PID %d was started by hand (login session %s), not by systemd. It dies with that session, and it blocks the service from starting.", p.Pid, p.Scope),
			[]string{
				"sudo kill " + pid + "    # graceful stop (use Ctrl+C in its terminal, never Ctrl+Z)",
				"sudo systemctl restart " + unit,
			}
	}
	return fmt.Sprintf("PID %d is running outside systemd.", p.Pid),
		[]string{"sudo kill " + pid + "    # graceful stop", "sudo systemctl restart " + unit}
}
