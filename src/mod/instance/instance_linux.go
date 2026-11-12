//go:build linux

package instance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Supported reports whether this build can read /proc.
const Supported = true

// procRoot is a var so tests can aim the readers at fixture trees.
var procRoot = "/proc"

// ErrNoHolder means nobody holds a lock on the file (or it could not be determined).
var ErrNoHolder = errors.New("no process holds a lock on this file")

func readProc(root, rel string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, rel))
	return string(b), err
}

// FindLockHolders returns every pid holding a flock/POSIX lock on path (matched by device and inode
// through /proc/locks). A directory (LevelDB style database) is checked through its LOCK file.
// The file is only stat'ed, never opened, so this cannot take or disturb the lock.
func FindLockHolders(path string) (LockMatch, error) {
	return findLockHolders(procRoot, path)
}

func findLockHolders(root, path string) (LockMatch, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return LockMatch{}, err
	}
	if fi.IsDir() {
		fi, err = os.Stat(filepath.Join(path, "LOCK"))
		if err != nil {
			return LockMatch{}, ErrNoHolder
		}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return LockMatch{}, errors.New("stat not available")
	}
	text, err := readProc(root, "locks")
	if err != nil {
		return LockMatch{}, fmt.Errorf("cannot read /proc/locks: %w", err)
	}
	maj, min := DevMajorMinor(uint64(st.Dev))
	m := MatchLocks(ParseProcLocks(text), maj, min, uint64(st.Ino))
	if len(m.Pids) == 0 {
		return m, ErrNoHolder
	}
	return m, nil
}

// FindLockHolder returns the first known holder pid of the lock on path. approximate is true when
// the match used the inode alone.
func FindLockHolder(path string) (pid int, approximate bool, err error) {
	m, err := FindLockHolders(path)
	if err != nil {
		return 0, false, err
	}
	for _, p := range m.Pids {
		if p > 0 {
			return p, m.Approximate, nil
		}
	}
	return 0, m.Approximate, errors.New("a lock exists but the kernel did not report a usable pid (another pid namespace, or an OFD lock)")
}

// Describe reads /proc/<pid>/{stat,cmdline,cgroup,status,exe}. It never fails: a process that vanished
// or cannot be read comes back with Visible=false and a Note.
func Describe(pid int) ProcInfo { return describeAt(procRoot, pid, time.Now()) }

func describeAt(root string, pid int, now time.Time) ProcInfo {
	p := ProcInfo{Pid: pid, Uid: -1}
	dir := strconv.Itoa(pid)
	stat, err := readProc(root, filepath.Join(dir, "stat"))
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			p.Note = "process no longer exists"
		case errors.Is(err, os.ErrPermission):
			p.Note = "permission denied"
		default:
			p.Note = err.Error()
		}
		return p
	}
	comm, state, ppid, start, err := ParseStat(stat)
	if err != nil {
		p.Note = "unreadable stat"
		return p
	}
	p.Visible, p.Comm, p.State, p.PPid = true, comm, state, ppid
	if c, err := readProc(root, filepath.Join(dir, "cmdline")); err == nil {
		p.Cmdline = ParseCmdline(c)
	}
	if exe, err := os.Readlink(filepath.Join(root, dir, "exe")); err == nil {
		p.Exe = exe
	}
	if cg, err := readProc(root, filepath.Join(dir, "cgroup")); err == nil {
		p.Unit, p.Scope, p.CgroupRaw = ParseCgroup(cg)
	}
	if st, err := readProc(root, filepath.Join(dir, "status")); err == nil {
		p.Uid = ParseStatusUid(st)
	}
	if bt, err := readProc(root, "stat"); err == nil {
		if btime := ParseBtime(bt); btime > 0 && start > 0 {
			started := time.Unix(btime, 0).Add(time.Duration(start) * time.Second / ClockTicks)
			if now.After(started) {
				p.Age = now.Sub(started)
			}
		}
	}
	return p
}

// ListZoraxyProcesses finds processes whose executable looks like Zoraxy, excluding exclude (normally self).
// Unreadable processes are skipped; unreadable counts how many /proc entries could not be inspected.
func ListZoraxyProcesses(exclude int) (found []ProcInfo, unreadable int) {
	return listZoraxy(procRoot, exclude, time.Now())
}

func listZoraxy(root string, exclude int, now time.Time) (found []ProcInfo, unreadable int) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, 0
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == exclude {
			continue
		}
		p := describeAt(root, pid, now)
		if !p.Visible {
			if p.Note == "permission denied" {
				unreadable++
			}
			continue
		}
		if p.Exe == "" && len(p.Cmdline) == 0 && !IsZoraxyName(p.Comm) {
			unreadable++ //another user's process: exe link is hidden, cmdline empty
			continue
		}
		if IsZoraxyName(p.ExeBase()) {
			found = append(found, p)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Pid < found[j].Pid })
	return
}

// ListenSocket is a LISTEN socket plus the processes that own it (empty when not visible to us).
type ListenSocket struct {
	Sock
	Owners []int
}

// ListenSockets reads /proc/net/tcp{,6} and maps each LISTEN socket to its owner pids via /proc/<pid>/fd.
// hidden counts LISTEN sockets whose owner could not be determined (needs root for other users' processes).
func ListenSockets() (socks []ListenSocket, hidden int, err error) {
	return listenSockets(procRoot)
}

func listenSockets(root string) ([]ListenSocket, int, error) {
	var all []Sock
	got := false
	for _, f := range []struct {
		name string
		v6   bool
	}{{"net/tcp", false}, {"net/tcp6", true}} {
		t, err := readProc(root, f.name)
		if err != nil {
			continue
		}
		got = true
		for _, s := range ParseProcNetTCP(t, f.v6) {
			if s.Listening() {
				all = append(all, s)
			}
		}
	}
	if !got {
		return nil, 0, errors.New("cannot read /proc/net/tcp")
	}
	owners := map[uint64][]int{}
	ents, _ := os.ReadDir(root)
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(root, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			tgt, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if ino, ok := ParseSocketLink(tgt); ok {
				if l := owners[ino]; len(l) == 0 || l[len(l)-1] != pid {
					owners[ino] = append(owners[ino], pid)
				}
			}
		}
	}
	out := make([]ListenSocket, 0, len(all))
	hidden := 0
	for _, s := range all {
		ls := ListenSocket{Sock: s, Owners: owners[s.Inode]}
		if len(ls.Owners) == 0 {
			hidden++
		}
		out = append(out, ls)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Addr() < out[j].Addr()
	})
	return out, hidden, nil
}

// UnitStatus is what systemctl reports about a unit.
type UnitStatus struct {
	Available bool // systemctl exists and answered
	Exists    bool // the unit file is loaded
	Active    string
	Sub       string
	MainPID   int
	Type      string
	Fragment  string
}

// QueryUnit asks systemctl about a unit. It never fails: without systemctl, or without a systemd
// running, Available is false.
func QueryUnit(name string) UnitStatus {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return UnitStatus{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "show", name, "--no-pager", "-p", "LoadState,ActiveState,SubState,MainPID,Type,FragmentPath").Output()
	if err != nil && len(out) == 0 {
		return UnitStatus{}
	}
	return ParseSystemctlShow(string(out))
}

// ParseSystemctlShow parses "systemctl show" key=value output.
func ParseSystemctlShow(text string) UnitStatus {
	u := UnitStatus{Available: true}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			u.Exists = v == "loaded"
		case "ActiveState":
			u.Active = v
		case "SubState":
			u.Sub = v
		case "MainPID":
			u.MainPID, _ = strconv.Atoi(v)
		case "Type":
			u.Type = v
		case "FragmentPath":
			u.Fragment = v
		}
	}
	return u
}
