package streamproxy_test

import (
	"io"
	"net"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/streamproxy"
)

// freeLoopbackAddr returns a 127.0.0.1:port address that was free a moment ago.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// TestPort2Port relays TCP between two local sockets. It must not depend on any
// external host (fork #250).
func TestPort2Port(t *testing.T) {
	// local echo server as the relay target
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	listenAddr := freeLoopbackAddr(t)
	stopChan := make(chan bool)
	// instances created through a Manager carry the access control wiring
	lg, _ := logger.NewFmtLogger()
	mgr, err := streamproxy.NewStreamProxy(&streamproxy.Options{
		DefaultTimeout:       1,
		AccessControlHandler: func(net.Conn) bool { return true },
		ConfigStore:          t.TempDir(),
		Logger:               lg,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := mgr.NewConfig(&streamproxy.ProxyRelayOptions{Name: "test", ListeningAddr: listenAddr, ProxyAddr: target.Addr().String(), UseTCP: true, Timeout: 1})
	config, err := mgr.GetConfigByUUID(id)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- config.Port2host(listenAddr, target.Addr().String(), stopChan) }()

	// wait until the relay accepts connections
	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err = net.DialTimeout("tcp", listenAddr, time.Second)
		if err == nil {
			break
		}
		select {
		case perr := <-done:
			t.Fatalf("relay exited early: %v", perr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay never started listening: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("relayed echo = %q, err=%v", buf, err)
	}
	conn.Close()

	select {
	case stopChan <- true:
	case <-time.After(5 * time.Second):
		t.Fatal("stop signal was not received")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Port2host returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Port2host did not return after the stop signal")
	}
	if c, err := net.DialTimeout("tcp", listenAddr, time.Second); err == nil {
		c.Close()
		t.Error("relay still accepts connections after stop")
	}
}
