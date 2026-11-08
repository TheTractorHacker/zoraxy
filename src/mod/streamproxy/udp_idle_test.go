package streamproxy

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// Regression test for upstream #1207: idle per-client UDP sessions must be
// released after the configured Timeout instead of leaking a socket and a
// goroutine for every client source port.
func TestUDPIdleSessionsAreReleased(t *testing.T) {
	// Echo target
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			target.WriteToUDP(buf[:n], addr)
		}
	}()

	var a, b int64
	inst := &ProxyRelayInstance{
		Timeout:                     1, // 1 second idle timeout
		aTobAccumulatedByteTransfer: &a,
		bToaAccumulatedByteTransfer: &b,
		parent:                      &Manager{Options: &Options{}},
	}

	// Pick a free listen port
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	listenPort := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	listenAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort))

	stop := make(chan bool)
	done := make(chan struct{})
	go func() {
		inst.ForwardUDP(listenAddr, target.LocalAddr().String(), stop)
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)

	const clients = 20
	for i := 0; i < clients; i++ {
		c, err := net.Dial("udp", listenAddr)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("ping"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != "ping" {
			t.Fatalf("client %d did not get echo: %v", i, err)
		}
		c.Close()
	}

	count := func() int {
		n := 0
		inst.udpClientMap.Range(func(k, v any) bool { n++; return true })
		return n
	}
	if got := count(); got != clients {
		t.Fatalf("expected %d live sessions right after traffic, got %d", clients, got)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && count() > 0 {
		time.Sleep(100 * time.Millisecond)
	}
	if got := count(); got != 0 {
		t.Fatalf("idle UDP sessions were never released: %d left", got)
	}

	stop <- true
	<-done
}
