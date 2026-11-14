package instance

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func listenDgram(t *testing.T, addr string) *net.UnixConn {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram not available: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func recv(t *testing.T, c *net.UnixConn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no datagram: %v", err)
	}
	return string(buf[:n])
}

func withSocket(t *testing.T, v string) {
	old := notifySocketEnv
	notifySocketEnv = func() string { return v }
	t.Cleanup(func() { notifySocketEnv = old })
}

func TestNotifyNoopWithoutSocket(t *testing.T) {
	withSocket(t, "")
	if NotifyEnabled() {
		t.Fatal("must be disabled")
	}
	NotifyStatus("x")
	NotifyReady("ok")
	NotifyStopping()
	if err := Notify("READY=1"); err != nil {
		t.Fatal(err)
	}
	withSocket(t, "vsock:1:2") //unknown address form: ignored, never an error
	if err := Notify("READY=1"); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyPathSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ntf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "n.sock")
	c := listenDgram(t, sock)
	withSocket(t, sock)
	NotifyStatus("Waiting for database lock...\nsecond line")
	if got := recv(t, c); got != "STATUS=Waiting for database lock... second line" {
		t.Fatalf("%q", got)
	}
	NotifyReady("Listening")
	if got := recv(t, c); got != "READY=1\nSTATUS=Listening" {
		t.Fatalf("%q", got)
	}
	NotifyStopping()
	if got := recv(t, c); got != "STOPPING=1\nSTATUS=Shutting down" {
		t.Fatalf("%q", got)
	}
}

func TestNotifyAddr(t *testing.T) {
	for in, want := range map[string]string{"/run/systemd/notify": "/run/systemd/notify"} {
		if got, ok := notifyAddr(in); !ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "vsock:1:2", "relative", "@abc", "@/org/freedesktop/systemd1/notify"} {
		if _, ok := notifyAddr(in); ok {
			t.Errorf("%q must be ignored", in)
		}
	}
}

func TestNotifyAbstractSocketIsIgnored(t *testing.T) {
	// abstract sockets are never used (a kernel hazard, see notifyAddr): no send, no error, readiness reported as off
	withSocket(t, "@zoraxy-test-abstract")
	if NotifyEnabled() {
		t.Fatal("an abstract NOTIFY_SOCKET must not count as enabled")
	}
	if err := Notify("READY=1"); err != nil {
		t.Fatalf("must be a silent no-op, got %v", err)
	}
	if NotifyIgnoredReason() == "" {
		t.Fatal("the reason must be explained so it can be logged")
	}
	withSocket(t, "/run/systemd/notify")
	if NotifyIgnoredReason() != "" {
		t.Fatal("a path socket is usable")
	}
}

func TestNotifyDeadSocketReturnsError(t *testing.T) {
	withSocket(t, "/nonexistent/dir/n.sock")
	if err := Notify("READY=1"); err == nil {
		t.Fatal("expected an error for a missing socket")
	}
	NotifyReady("x") //must not panic
}
