package instance

import (
	"strings"
	"testing"
	"time"
)

func TestHolderLine(t *testing.T) {
	frozen := ProcInfo{Pid: 3479504, Comm: "zoraxy", Exe: "/opt/zoraxy/zoraxy", State: 'T', Visible: true, Age: 2*time.Hour + 5*time.Minute}
	got := HolderLine(frozen, "zoraxy")
	want := "held by PID 3479504 (zoraxy, started 2h 5m ago), state: FROZEN (stopped, probably Ctrl+Z or SIGSTOP). Resume it: kill -CONT 3479504, or stop it: kill -9 3479504"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	svc := ProcInfo{Pid: 7, Exe: "/x/zoraxy", State: 'S', Visible: true, Unit: "zoraxy.service", Age: time.Minute}
	if g := HolderLine(svc, ""); !strings.Contains(g, "systemd service zoraxy.service") || !strings.Contains(g, "systemctl stop zoraxy") {
		t.Fatal(g)
	}
	hand := ProcInfo{Pid: 8, Exe: "/x/zoraxy", State: 'S', Visible: true, Scope: "session-2.scope"}
	if g := HolderLine(hand, "zoraxy"); !strings.Contains(g, "kill 8") || !strings.Contains(g, "login session") {
		t.Fatal(g)
	}
	if g := HolderLine(ProcInfo{Pid: 9, Note: "permission denied"}, "zoraxy"); !strings.Contains(g, "PID 9 (permission denied)") {
		t.Fatal(g)
	}
	evil := ProcInfo{Pid: 5, Exe: "/x/\x1b[2Jzoraxy", State: 'T', Visible: true}
	if g := HolderLine(evil, "zoraxy"); strings.ContainsRune(g, 0x1b) {
		t.Fatalf("escape leaked: %q", g)
	}
}

func TestLockHolderSummaryDegrades(t *testing.T) {
	if s := LockHolderSummary("/nonexistent/path/sys.db"); s != "" {
		t.Fatalf("unknown file must give an empty summary, got %q", s)
	}
}

func TestWatchLockWaitNoopAndStop(t *testing.T) {
	withSocket(t, "")
	WatchLockWait("/nonexistent")() //no-op
	withSocket(t, "/nonexistent/n.sock")
	stop := WatchLockWait("/nonexistent")
	stop()
	stop() //idempotent
}
