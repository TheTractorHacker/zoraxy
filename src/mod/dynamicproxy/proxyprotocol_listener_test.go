package dynamicproxy

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/c0va23/go-proxyprotocol"
)

// Upstream #934: Zoraxy behind HAProxy (send-proxy / send-proxy-v2). The listener wrapper used for the TLS
// listener (see StartProxyService) must expose the address from the PROXY header as the client address.
func TestProxyProtocolListenerExposesRealClientAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RemoteAddr))
	})}
	go srv.Serve(proxyproto.NewDefaultListener(ln))
	defer srv.Close()

	// PROXY protocol v2 binary header: signature, ver/cmd=0x21 (PROXY), fam/proto=0x11 (TCP4), len=12,
	// src 203.0.113.7:5555, dst 10.0.0.1:443
	v2 := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0x00, 0x0c, 203, 0, 113, 7, 10, 0, 0, 1, 0x15, 0xb3, 0x01, 0xbb)
	cases := map[string][]byte{
		"v1": []byte("PROXY TCP4 203.0.113.7 10.0.0.1 5555 443\r\n"),
		"v2": v2,
	}
	for name, header := range cases {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write(header)
		c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		c.Close()
		if !strings.HasPrefix(string(buf[:n]), "203.0.113.7:5555") {
			t.Errorf("%s: handler saw remote address %q, want 203.0.113.7:5555", name, string(buf[:n]))
		}
	}
}
