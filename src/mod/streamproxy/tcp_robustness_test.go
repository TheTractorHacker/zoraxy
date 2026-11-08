package streamproxy

import (
	"bufio"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// errConn is a net.Conn whose Read fails with a connection reset style error
type errConn struct {
	net.Conn
	closed atomic.Bool
}

func (e *errConn) Read([]byte) (int, error) { return 0, errors.New("read: connection reset by peer") }
func (e *errConn) Close() error             { e.closed.Store(true); return e.Conn.Close() }

// A read error (connection reset) on one side used to skip wg.Done(), so forward() never
// returned and both sockets were leaked for the lifetime of the process.
func TestForwardReturnsAndClosesOnReadError(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	broken := &errConn{Conn: a1}

	var x, y int64
	c := &ProxyRelayInstance{}
	done := make(chan struct{})
	go func() {
		c.forward(broken, b1, &x, &y)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("forward() hangs after a read error on one side")
	}
	if _, err := b2.Write([]byte("x")); err == nil {
		t.Error("the other side was not closed after the error")
	}
}

// The PROXY header for an IPv6 client must announce TCPv6, not TCPv4.
func TestProxyProtocolHeaderIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	defer ln.Close()

	// a pseudo "client" connection: dial the listener, the accepted side has an IPv6 remote
	go func() { c, _ := net.Dial("tcp", ln.Addr().String()); time.Sleep(time.Second); if c != nil { c.Close() } }()
	src, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	dstLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer dstLn.Close()
	go func() {
		d, _ := net.Dial("tcp", dstLn.Addr().String())
		if d != nil {
			defer d.Close()
			WriteProxyProtocolHeader(d, src, ProxyProtocolV2)
			time.Sleep(time.Second)
		}
	}()
	got, _ := dstLn.Accept()
	defer got.Close()
	got.SetDeadline(time.Now().Add(3 * time.Second))
	hdr, err := proxyproto.Read(bufio.NewReader(got))
	if err != nil {
		t.Fatalf("invalid PROXY header: %v", err)
	}
	if hdr.TransportProtocol != proxyproto.TCPv6 {
		t.Fatalf("transport protocol = %v, want TCPv6", hdr.TransportProtocol)
	}
	if _, ok := hdr.SourceAddr.(*net.TCPAddr); !ok || !hdr.SourceAddr.(*net.TCPAddr).IP.Equal(net.IPv6loopback) {
		t.Fatalf("source addr = %v", hdr.SourceAddr)
	}
}
