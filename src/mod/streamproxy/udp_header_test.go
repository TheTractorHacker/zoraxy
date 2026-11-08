package streamproxy

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// The UDP PROXY v2 header must use the address family of the client, not always UDPv4.
func TestProxyProtocolHeaderUDPIPv6(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("IPv6 loopback not available")
	}
	defer srv.Close()
	out, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	client := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4242}
	if err := WriteProxyProtocolHeaderUDP(out, client, srv.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write header: %v", err)
	}
	buf := make([]byte, 512)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := proxyproto.Read(bufio.NewReader(bytes.NewReader(buf[:n])))
	if err != nil {
		t.Fatalf("invalid header: %v", err)
	}
	if hdr.TransportProtocol != proxyproto.UDPv6 {
		t.Fatalf("transport = %v, want UDPv6", hdr.TransportProtocol)
	}
}
