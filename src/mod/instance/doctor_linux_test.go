//go:build linux

package instance

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func frozenA() ProcInfo {
	return ProcInfo{Pid: 100, PPid: 90, Comm: "zoraxy", Exe: "/opt/zoraxy/zoraxy", State: 'T', Visible: true, Scope: "session-4.scope", Age: 5 * time.Minute}
}
func waitingB() ProcInfo {
	return ProcInfo{Pid: 200, PPid: 1, Comm: "zoraxy", Exe: "/opt/zoraxy/zoraxy", State: 'S', Visible: true, Unit: "zoraxy.service", Age: 20 * time.Second}
}

func probeFor(procs []ProcInfo, holders []int, socks []ListenSocket, unit UnitStatus) Probe {
	by := map[int]ProcInfo{}
	for _, p := range procs {
		by[p.Pid] = p
	}
	return Probe{
		LockHolders: func(string) (LockMatch, error) {
			if len(holders) == 0 {
				return LockMatch{}, ErrNoHolder
			}
			return LockMatch{Pids: holders}, nil
		},
		Describe: func(pid int) ProcInfo {
			if p, ok := by[pid]; ok {
				return p
			}
			return ProcInfo{Pid: pid, Note: "process no longer exists"}
		},
		ListZoraxy: func(int) ([]ProcInfo, int) { return procs, 0 },
		Sockets:    func() ([]ListenSocket, int, error) { return socks, 0, nil },
		Unit:       func(string) UnitStatus { return unit },
		OpensFile:  func(int, string) (bool, bool) { return true, true }, //every listed process has the database open
	}
}

func sock(port int, rx, tx uint64, owners ...int) ListenSocket {
	return ListenSocket{Sock: Sock{IP: []byte{0, 0, 0, 0}, Port: port, State: StateListen, RxQ: rx, TxQ: tx, Inode: uint64(port)}, Owners: owners}
}

var opts = DoctorOptions{DBPath: "./sys.db", Unit: "zoraxy", Self: 1, Ports: []PortSpec{{8000, "admin (-port)", true}, {443, "HTTPS inbound", false}, {80, "HTTP inbound", false}}}

func TestDoctorIncident(t *testing.T) {
	// the real incident: A frozen holding the lock and the sockets, B blocked on the lock, unit active
	r := RunDoctor(opts, probeFor(
		[]ProcInfo{frozenA(), waitingB()}, []int{100},
		[]ListenSocket{sock(8000, 0, 4096, 100), sock(443, 4097, 4096, 100), sock(80, 0, 4096, 100)},
		UnitStatus{Available: true, Exists: true, Active: "active", Sub: "running", MainPID: 200, Type: "simple"}))
	out := r.String()
	if r.ExitCode() != 1 {
		t.Fatal("must exit 1")
	}
	for _, want := range []string{
		"PID 100 (zoraxy), state: stopped (frozen, probably Ctrl+Z or SIGSTOP)",
		"[holds the database lock]",
		"connections are piling up, nothing is accepting",
		"accept queue 4097/4096",
		"kill -CONT 100", "kill -9 100",
		"most likely blocked waiting for the database lock",
		"PID 200",
		"main process (PID 200) listens on no port",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q\n%s", want, out)
		}
	}
	t.Log("\n" + out)
}

func TestDoctorHealthy(t *testing.T) {
	ok := ProcInfo{Pid: 300, Comm: "zoraxy", Exe: "/opt/zoraxy/zoraxy", State: 'S', Visible: true, Unit: "zoraxy.service", Age: time.Hour}
	r := RunDoctor(opts, probeFor([]ProcInfo{ok}, []int{300},
		[]ListenSocket{sock(8000, 0, 4096, 300), sock(443, 1, 4096, 300)},
		UnitStatus{Available: true, Exists: true, Active: "active", Sub: "running", MainPID: 300, Type: "notify"}))
	if r.ExitCode() != 0 {
		t.Fatalf("healthy system flagged:\n%s", r.String())
	}
	if !strings.Contains(r.String(), "Verdict: healthy") {
		t.Fatal(r.String())
	}
}

func TestDoctorNothingRunningNoSystemd(t *testing.T) {
	r := RunDoctor(opts, probeFor(nil, nil, nil, UnitStatus{}))
	if r.ExitCode() != 0 || !strings.Contains(r.String(), "systemctl not available") || !strings.Contains(r.String(), "none found") {
		t.Fatalf("\n%s", r.String())
	}
}

func TestDoctorForeignPortOwner(t *testing.T) {
	nginx := ProcInfo{Pid: 55, Comm: "nginx", Exe: "/usr/sbin/nginx", State: 'S', Visible: true}
	r := RunDoctor(opts, probeFor([]ProcInfo{}, nil, []ListenSocket{sock(443, 0, 511, 55)}, UnitStatus{}))
	_ = nginx
	// Describe for 55 returns "no longer exists" with the fixture; owner is not zoraxy either way
	if r.ExitCode() != 1 || !strings.Contains(r.String(), "not by Zoraxy") {
		t.Fatalf("\n%s", r.String())
	}
}

func TestDoctorLockHeldNotByService(t *testing.T) {
	hand := ProcInfo{Pid: 100, Comm: "zoraxy", Exe: "/x/zoraxy", State: 'S', Visible: true, Scope: "session-4.scope"}
	r := RunDoctor(opts, probeFor([]ProcInfo{hand}, []int{100},
		[]ListenSocket{sock(8000, 0, 4096, 100)},
		UnitStatus{Available: true, Exists: true, Active: "active", Sub: "running", MainPID: 200}))
	if r.ExitCode() != 1 || !strings.Contains(r.String(), "outside the service") || !strings.Contains(r.String(), "started by hand") {
		t.Fatalf("\n%s", r.String())
	}
}

func TestDoctorHiddenThingsReported(t *testing.T) {
	p := probeFor(nil, nil, nil, UnitStatus{})
	p.ListZoraxy = func(int) ([]ProcInfo, int) { return nil, 3 }
	p.Sockets = func() ([]ListenSocket, int, error) { return nil, 2, nil }
	r := RunDoctor(opts, p)
	if !strings.Contains(r.String(), "Could not see") || !strings.Contains(r.String(), "run with sudo") {
		t.Fatalf("\n%s", r.String())
	}
}

// ---- fixture /proc tree ----

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDescribeAndListFromFixtureTree(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "stat"), "cpu 1\nbtime 1000\n")
	writeFile(t, filepath.Join(root, "100/stat"), "100 (zoraxy) T 90 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 6000 0 0")
	writeFile(t, filepath.Join(root, "100/cmdline"), "sudo\x00./zoraxy\x00")
	writeFile(t, filepath.Join(root, "100/cgroup"), "0::/user.slice/user-1000.slice/session-4.scope\n")
	writeFile(t, filepath.Join(root, "100/status"), "Name:\tzoraxy\nUid:\t0\t0\t0\t0\n")
	os.Symlink("/opt/zoraxy/zoraxy", filepath.Join(root, "100/exe"))
	writeFile(t, filepath.Join(root, "200/stat"), "200 (ngi nx) S 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 7000 0 0")
	writeFile(t, filepath.Join(root, "300/stat"), "garbage")
	writeFile(t, filepath.Join(root, "self-not-a-pid"), "x")

	now := time.Unix(1000+6000/ClockTicks+125, 0)
	p := describeAt(root, 100, now)
	if !p.Visible || !p.Stopped() || p.Unit != "" || p.Scope != "session-4.scope" || p.Uid != 0 || p.Age != 125*time.Second || p.ExeBase() != "zoraxy" {
		t.Fatalf("%+v", p)
	}
	if g := describeAt(root, 999, now); g.Visible || g.Note != "process no longer exists" {
		t.Fatalf("%+v", g)
	}
	if g := describeAt(root, 300, now); g.Visible || g.Note != "unreadable stat" {
		t.Fatalf("%+v", g)
	}
	found, _ := listZoraxy(root, 0, now)
	if len(found) != 1 || found[0].Pid != 100 {
		t.Fatalf("%+v", found)
	}
	if found, _ := listZoraxy(root, 100, now); len(found) != 0 {
		t.Fatal("self must be excluded")
	}
	if found, n := listZoraxy(filepath.Join(root, "missing"), 0, now); found != nil || n != 0 {
		t.Fatal("missing /proc")
	}
}

func TestFindLockHoldersFixture(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "sys.db")
	writeFile(t, db, "x")
	fi, _ := os.Stat(db)
	maj, min, ino := statIDs(t, fi)
	locks := "1: FLOCK  ADVISORY  WRITE 4321 " + hex2(maj) + ":" + hex2(min) + ":" + itoa(ino) + " 0 EOF\n"
	writeFile(t, filepath.Join(root, "locks"), locks)
	m, err := findLockHolders(root, db)
	if err != nil || len(m.Pids) != 1 || m.Pids[0] != 4321 || m.Approximate {
		t.Fatalf("%+v %v", m, err)
	}
	// no lock lines
	writeFile(t, filepath.Join(root, "locks"), "")
	if _, err := findLockHolders(root, db); err != ErrNoHolder {
		t.Fatalf("%v", err)
	}
	// /proc/locks unreadable
	if _, err := findLockHolders(filepath.Join(root, "nope"), db); err == nil || err == ErrNoHolder {
		t.Fatalf("%v", err)
	}
	// db missing
	if _, err := findLockHolders(root, filepath.Join(root, "absent.db")); err == nil {
		t.Fatal("missing file must error")
	}
	// directory without LOCK
	if _, err := findLockHolders(root, root); err != ErrNoHolder {
		t.Fatalf("%v", err)
	}
}

func TestListenSocketsFixture(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "net/tcp"), tcpFixture)
	writeFile(t, filepath.Join(root, "net/tcp6"), tcp6Fixture)
	if err := os.MkdirAll(filepath.Join(root, "100/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Symlink("socket:[5001]", filepath.Join(root, "100/fd/7"))
	os.Symlink("/dev/null", filepath.Join(root, "100/fd/0"))
	socks, hidden, err := listenSockets(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 4 {
		t.Fatalf("%d listening sockets", len(socks))
	}
	if hidden != 3 {
		t.Fatalf("hidden %d", hidden)
	}
	var s443 *ListenSocket
	for i := range socks {
		if socks[i].Port == 443 {
			s443 = &socks[i]
		}
	}
	if s443 == nil || len(s443.Owners) != 1 || s443.Owners[0] != 100 || !s443.QueueFull() {
		t.Fatalf("%+v", s443)
	}
	if _, _, err := listenSockets(filepath.Join(root, "nope")); err == nil {
		t.Fatal("missing /proc/net must error")
	}
}

func TestParseSystemctlShow(t *testing.T) {
	u := ParseSystemctlShow("Type=notify\nMainPID=812\nLoadState=loaded\nActiveState=activating\nSubState=start\nFragmentPath=/etc/systemd/system/zoraxy.service\n")
	if !u.Exists || u.Active != "activating" || u.MainPID != 812 || u.Type != "notify" || u.Sub != "start" {
		t.Fatalf("%+v", u)
	}
	if u := ParseSystemctlShow("LoadState=not-found\nActiveState=inactive\n"); u.Exists {
		t.Fatal("not-found is not an existing unit")
	}
}

// holdersFromFdinfo against the real /proc: this test process takes a flock and must be found
// without going through /proc/locks.
func TestHoldersFromFdinfoRealProc(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Skip("flock unavailable: ", err)
	}
	fi, _ := f.Stat()
	st := fi.Sys().(*syscall.Stat_t)
	m := holdersFromFdinfo("/proc", st, []int{os.Getpid(), 1})
	if len(m.Pids) != 1 || m.Pids[0] != os.Getpid() || !m.ViaFdinfo {
		t.Fatalf("%+v", m)
	}
	// a file nobody locked
	g, _ := os.CreateTemp(t.TempDir(), "free")
	defer g.Close()
	gi, _ := g.Stat()
	if m := holdersFromFdinfo("/proc", gi.Sys().(*syscall.Stat_t), []int{os.Getpid()}); len(m.Pids) != 0 {
		t.Fatalf("unlocked file reported held: %+v", m)
	}
}

func TestDoctorNotAccusingOtherDatabasesPluginsZombies(t *testing.T) {
	holder := ProcInfo{Pid: 100, PPid: 1, Comm: "zoraxy", Exe: "/x/zoraxy", State: 'S', Visible: true, Scope: "session-4.scope"}
	other := ProcInfo{Pid: 300, PPid: 1, Comm: "zoraxy", Exe: "/live/zoraxy", State: 'S', Visible: true, Unit: "zoraxy.service"}
	plugin := ProcInfo{Pid: 301, PPid: 300, Comm: "plugin", Exe: "/live/plugins/zoraxy_waf", State: 'S', Visible: true}
	zombie := ProcInfo{Pid: 400, PPid: 1, Comm: "zoraxy", Exe: "/x/zoraxy", State: 'Z', Visible: true}
	hidden := ProcInfo{Pid: 500, PPid: 1, Comm: "zoraxy", Exe: "/y/zoraxy", State: 'S', Visible: true}
	p := probeFor([]ProcInfo{holder, other, plugin, zombie, hidden}, []int{100}, []ListenSocket{sock(8000, 0, 4096, 100)}, UnitStatus{})
	p.OpensFile = func(pid int, _ string) (bool, bool) {
		if pid == 500 {
			return false, false //cannot read its descriptors
		}
		return false, true //opens a different database
	}
	r := RunDoctor(opts, p)
	out := r.String()
	if r.ExitCode() != 0 {
		t.Fatalf("falsely accused:\n%s", out)
	}
	if strings.Contains(out, "PID 301") {
		t.Fatalf("a plugin was listed as an instance:\n%s", out)
	}
	if !strings.Contains(out, "whether PID 300, PID 500") && !strings.Contains(out, "whether PID 500") {
		t.Logf("%s", out)
	}
}

func TestIsZoraxyName(t *testing.T) {
	for n, want := range map[string]bool{"zoraxy": true, "Zoraxy": true, "zoraxy_linux_amd64": true, "zoraxy-fork": true, "zoraxy.exe": true,
		"Zoraxy Cloudflare WAF plugin": false, "zoraxyfoo": false, "nginx": false} {
		if IsZoraxyName(n) != want {
			t.Errorf("%q want %v", n, want)
		}
	}
}
