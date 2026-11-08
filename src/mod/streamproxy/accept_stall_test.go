package streamproxy_test

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/streamproxy"
)

// Rejected clients are delayed 300 ms before the close. That delay must not block the accept
// loop, otherwise one blocked client can stall every other client of the relay.
func TestRejectedClientDoesNotStallAcceptLoop(t *testing.T) {
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	var calls int32
	lg, _ := logger.NewFmtLogger()
	mgr, err := streamproxy.NewStreamProxy(&streamproxy.Options{
		DefaultTimeout: 1,
		// reject the first 5 connections, accept the rest
		AccessControlHandler: func(net.Conn) bool { return atomic.AddInt32(&calls, 1) > 5 },
		ConfigStore:          t.TempDir(),
		Logger:               lg,
	})
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := freeLoopbackAddr(t)
	id := mgr.NewConfig(&streamproxy.ProxyRelayOptions{Name: "t", ListeningAddr: listenAddr, ProxyAddr: target.Addr().String(), UseTCP: true, Timeout: 1})
	cfg, _ := mgr.GetConfigByUUID(id)
	stop := make(chan bool, 1)
	go cfg.Port2host(listenAddr, target.Addr().String(), stop)
	defer func() { stop <- true }()

	var conns []net.Conn
	for i := 0; i < 50; i++ {
		if c, err := net.DialTimeout("tcp", listenAddr, 100*time.Millisecond); err == nil {
			conns = append(conns, c)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", listenAddr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	start := time.Now()
	good, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	good.SetDeadline(time.Now().Add(5 * time.Second))
	good.Write([]byte("ok"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(good, buf); err != nil {
		t.Fatalf("allowed client not served: %v", err)
	}
	if d := time.Since(start); d > 600*time.Millisecond {
		t.Fatalf("allowed client waited %v behind rejected clients", d)
	}
}
