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
	for in, want := range map[string]string{"/run/systemd/notify": "/run/systemd/notify", "@abc": "\x00abc"} {
		if got, ok := notifyAddr(in); !ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "vsock:1:2", "relative"} {
		if _, ok := notifyAddr(in); ok {
			t.Errorf("%q must be ignored", in)
		}
	}
}

// Delivery to an abstract socket is skipped by default: on the 7.0.0-42 kernel of the build host a send
// to an abstract unixgram socket never completed (it left an unkillable process). Set
// ZORAXY_TEST_ABSTRACT=1 to run it on a healthy kernel.
func TestNotifyAbstractSocket(t *testing.T) {
	if os.Getenv("ZORAXY_TEST_ABSTRACT") == "" {
		t.Skip("set ZORAXY_TEST_ABSTRACT=1 to deliver to a real abstract socket")
	}
	name := "@zoraxy-test-" + time.Now().Format("150405.000000")
	c := listenDgram(t, "\x00"+name[1:])
	withSocket(t, name)
	if err := Notify("READY=1"); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, c); got != "READY=1" {
		t.Fatalf("%q", got)
	}
}

func TestNotifyDeadSocketReturnsError(t *testing.T) {
	withSocket(t, "/nonexistent/dir/n.sock")
	if err := Notify("READY=1"); err == nil {
		t.Fatal("expected an error for a missing socket")
	}
	NotifyReady("x") //must not panic
}
