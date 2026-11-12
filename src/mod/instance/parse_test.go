package instance

import (
	"strings"
	"testing"
	"time"
)

const locksFixture = `1: POSIX  ADVISORY  WRITE 2386 00:19:1250 0 EOF
2: FLOCK  ADVISORY  WRITE 3479504 fd:01:5678 0 EOF
2: -> FLOCK  ADVISORY  WRITE 3479999 fd:01:5678 0 EOF
3: OFDLCK ADVISORY  READ -1 08:01:99 0 EOF
garbage line
4: FLOCK  ADVISORY  WRITE abc fd:01:5 0 EOF
5: FLOCK  ADVISORY  WRITE 77 zz:01:5 0 EOF
`

func TestParseProcLocks(t *testing.T) {
	es := ParseProcLocks(locksFixture)
	if len(es) != 3 {
		t.Fatalf("want 3 entries (waiter and garbage skipped), got %d: %+v", len(es), es)
	}
	if es[1].Pid != 3479504 || es[1].Major != 0xfd || es[1].Minor != 1 || es[1].Inode != 5678 || es[1].Kind != "FLOCK" || !es[1].Write {
		t.Fatalf("bad entry %+v", es[1])
	}
	if es[2].Pid != -1 {
		t.Fatalf("OFD pid should be -1: %+v", es[2])
	}
	if len(ParseProcLocks("")) != 0 {
		t.Fatal("empty text")
	}
}

func TestMatchLocks(t *testing.T) {
	es := ParseProcLocks(locksFixture)
	m := MatchLocks(es, 0xfd, 1, 5678)
	if len(m.Pids) != 1 || m.Pids[0] != 3479504 || m.Approximate {
		t.Fatalf("exact: %+v", m)
	}
	m = MatchLocks(es, 0x1, 0x1, 5678) //wrong device, same inode
	if len(m.Pids) != 1 || !m.Approximate {
		t.Fatalf("approx: %+v", m)
	}
	if m := MatchLocks(es, 0xfd, 1, 1); len(m.Pids) != 0 {
		t.Fatalf("none: %+v", m)
	}
	//the same pid twice (two fds) is reported once
	dup := append(es, es[1])
	if m := MatchLocks(dup, 0xfd, 1, 5678); len(m.Pids) != 1 {
		t.Fatalf("dup: %+v", m)
	}
}

func TestDevMajorMinor(t *testing.T) {
	// /dev/sda1: 8:1 -> st_dev 0x801 ; fd:01 -> 0xfd01
	if a, b := DevMajorMinor(0x801); a != 8 || b != 1 {
		t.Fatalf("%d:%d", a, b)
	}
	if a, b := DevMajorMinor(0xfd01); a != 0xfd || b != 1 {
		t.Fatalf("%d:%d", a, b)
	}
	// minor above 255 uses the high bits: major 259 minor 3 = (259&0xfff)<<8 | 3 | ... glibc makedev
	dev := uint64(259)<<8 | 3
	if a, b := DevMajorMinor(dev); a != 259 || b != 3 {
		t.Fatalf("%d:%d", a, b)
	}
}

func TestParseStatWeirdComm(t *testing.T) {
	cases := []struct {
		in    string
		comm  string
		state byte
		ppid  int
	}{
		{"123 (zoraxy) S 1 123 123 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 8 0 4242 1000 1 18446744073709551615", "zoraxy", 'S', 1},
		{"456 (my (evil) name) T 77 456 456 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5000 0 0", "my (evil) name", 'T', 77},
		{"789 (a b c) t 5 789 789 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0", "a b c", 't', 5},
	}
	for _, c := range cases {
		comm, st, pp, _, err := ParseStat(c.in)
		if err != nil || comm != c.comm || st != c.state || pp != c.ppid {
			t.Errorf("%q => %q %c %d %v", c.in, comm, st, pp, err)
		}
	}
	_, _, _, ticks, _ := ParseStat(cases[0].in)
	if ticks != 4242 {
		t.Errorf("starttime %d", ticks)
	}
	for _, bad := range []string{"", "no parens", "1 (x", "1 (x)", "1 )x( S"} {
		if _, _, _, _, err := ParseStat(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestParseCgroup(t *testing.T) {
	cases := []struct{ in, unit, scope string }{
		{"0::/system.slice/zoraxy.service\n", "zoraxy.service", ""},
		{"0::/user.slice/user-1000.slice/session-3.scope\n", "", "session-3.scope"},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope\n", "", "app-x.scope"},
		{"12:cpu:/foo\n1:name=systemd:/system.slice/zoraxy.service\n", "zoraxy.service", ""},
		{"0::/\n", "", ""},
		{"", "", ""},
		{"junk", "", ""},
	}
	for _, c := range cases {
		u, s, _ := ParseCgroup(c.in)
		if u != c.unit || s != c.scope {
			t.Errorf("%q => %q %q", c.in, u, s)
		}
	}
}

func TestMiscParsers(t *testing.T) {
	if got := ParseCmdline("sudo\x00./zoraxy\x00-port=:8000\x00"); len(got) != 3 || got[1] != "./zoraxy" {
		t.Fatalf("%v", got)
	}
	if ParseCmdline("") != nil {
		t.Fatal("empty cmdline")
	}
	if ParseBtime("cpu 1 2\nbtime 1700000000\n") != 1700000000 {
		t.Fatal("btime")
	}
	if ParseStatusUid("Name:\tx\nUid:\t1000\t1000\t1000\t1000\n") != 1000 || ParseStatusUid("") != -1 {
		t.Fatal("uid")
	}
	for in, want := range map[string]int{":8000": 8000, "127.0.0.1:8000": 8000, "8000": 8000, "": 0, "[::1]:99": 99} {
		if PortFromListenAddr(in) != want {
			t.Errorf("%q", in)
		}
	}
	if !IsZoraxyName("zoraxy_linux_amd64") || IsZoraxyName("nginx") {
		t.Fatal("name")
	}
	if FormatAge(0) != "unknown" || FormatAge(90*time.Second) != "1m" || FormatAge(30*time.Hour) != "30h 0m" || FormatAge(72*time.Hour) != "3d 0h" {
		t.Fatal("age")
	}
}

const tcpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00001000:00001001 00:00000000 00000000     0        0 5001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F40 00000000:0000 0A 00000080:00000000 00:00000000 00000000  1000        0 5002 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F40 0100007F:D000 01 00000000:00000000 00:00000000 00000000  1000        0 5003 1 0000000000000000 100 0 0 10 0
   bad row
`

const tcp6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000080:00000000 00:00000000 00000000     0        0 5004 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F40 00000000000000000000000000000000:0000 0A 00000080:00000000 00:00000000 00000000     0        0 5005 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNetTCP(t *testing.T) {
	s4 := ParseProcNetTCP(tcpFixture, false)
	if len(s4) != 3 {
		t.Fatalf("%d rows", len(s4))
	}
	if s4[0].Port != 443 || !s4[0].Listening() || s4[0].TxQ != 4096 || s4[0].RxQ != 4097 || !s4[0].QueueFull() || s4[0].Inode != 5001 {
		t.Fatalf("%+v", s4[0])
	}
	if s4[1].IP.String() != "127.0.0.1" || s4[1].Port != 8000 || s4[1].QueueFull() || s4[1].Uid != 1000 {
		t.Fatalf("%+v", s4[1])
	}
	if s4[2].Listening() {
		t.Fatal("ESTABLISHED row must not be listening")
	}
	s6 := ParseProcNetTCP(tcp6Fixture, true)
	if len(s6) != 2 || s6[0].Port != 80 || s6[0].IP.String() != "::" {
		t.Fatalf("%+v", s6)
	}
	if s6[1].IP.String() != "::1" {
		t.Fatalf("ipv6 loopback decoded as %s", s6[1].IP)
	}
	if got := s6[1].Addr(); got != "[::1]:8000" {
		t.Fatal(got)
	}
	if ino, ok := ParseSocketLink("socket:[12345]"); !ok || ino != 12345 {
		t.Fatal("socket link")
	}
	if _, ok := ParseSocketLink("pipe:[1]"); ok {
		t.Fatal("pipe is not a socket")
	}
}

func TestExplain(t *testing.T) {
	stopped := ProcInfo{Pid: 42, Comm: "zoraxy", Exe: "/opt/zoraxy/zoraxy", State: 'T', Visible: true, Scope: "session-9.scope"}
	s, cmds := stopped.Explain("zoraxy")
	if !strings.Contains(s, "frozen") || !strings.Contains(s, "Ctrl+Z") {
		t.Fatal(s)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"kill -CONT 42", "kill -9 42", "pkill -9 -P 42", "systemctl restart zoraxy"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if d := stopped.Describe(); !strings.Contains(d, "PID 42 (zoraxy)") || !strings.Contains(d, "stopped") || !strings.Contains(d, "login session") {
		t.Fatal(d)
	}
	svc := ProcInfo{Pid: 7, Comm: "zoraxy", State: 'S', Visible: true, Unit: "zoraxy.service"}
	if _, c := svc.Explain("zoraxy"); !strings.Contains(strings.Join(c, " "), "systemctl restart zoraxy.service") {
		t.Fatal(c)
	}
	hand := ProcInfo{Pid: 8, Comm: "zoraxy", State: 'S', Visible: true, Scope: "session-1.scope"}
	if s, _ := hand.Explain("zoraxy"); !strings.Contains(s, "by hand") {
		t.Fatal(s)
	}
	gone := ProcInfo{Pid: 9, Note: "process no longer exists"}
	if s, _ := gone.Explain("zoraxy"); !strings.Contains(s, "cannot be read") {
		t.Fatal(s)
	}
	if !strings.Contains(gone.Describe(), "no longer exists") {
		t.Fatal(gone.Describe())
	}
	for _, st := range []byte{'D', 'Z', 'R', 't'} {
		p := ProcInfo{Pid: 1, PPid: 2, State: st, Visible: true}
		if s, _ := p.Explain("zoraxy"); s == "" {
			t.Errorf("state %c", st)
		}
	}
}
