package dpcore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/c0va23/go-proxyprotocol"
)

func TestBuildProxyHeader(t *testing.T) {
	v4s, v4d := netip.MustParseAddrPort("203.0.113.9:51000"), netip.MustParseAddrPort("10.0.0.5:8080")
	v6s, v6d := netip.MustParseAddrPort("[2001:db8::1]:51000"), netip.MustParseAddrPort("[2001:db8::2]:8080")

	got, _ := buildProxyHeader(1, v4s, v4d)
	if string(got) != "PROXY TCP4 203.0.113.9 10.0.0.5 51000 8080\r\n" {
		t.Errorf("v1 tcp4: %q", got)
	}
	got, _ = buildProxyHeader(1, v6s, v6d)
	if string(got) != "PROXY TCP6 2001:db8::1 2001:db8::2 51000 8080\r\n" {
		t.Errorf("v1 tcp6: %q", got)
	}
	//v4 client, v6 upstream: both sides in the v6 family
	got, _ = buildProxyHeader(1, v4s, v6d)
	if string(got) != "PROXY TCP6 ::ffff:203.0.113.9 2001:db8::2 51000 8080\r\n" {
		t.Errorf("v1 mixed: %q", got)
	}
	got, _ = buildProxyHeader(1, netip.AddrPort{}, v4d)
	if string(got) != "PROXY UNKNOWN\r\n" {
		t.Errorf("v1 unknown: %q", got)
	}

	got, _ = buildProxyHeader(2, v4s, v4d)
	want := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0x00, 0x0c, 203, 0, 113, 9, 10, 0, 0, 5, 0xc7, 0x38, 0x1f, 0x90)
	if string(got) != string(want) {
		t.Errorf("v2 tcp4: % x", got)
	}
	got, _ = buildProxyHeader(2, v6s, v6d)
	if len(got) != 16+36 || got[12] != 0x21 || got[13] != 0x21 || got[14] != 0 || got[15] != 36 {
		t.Errorf("v2 tcp6: % x", got)
	}
	got, _ = buildProxyHeader(2, netip.AddrPort{}, v4d)
	if string(got) != string(append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x20, 0x00, 0x00, 0x00)) {
		t.Errorf("v2 local: % x", got)
	}
	if _, err := buildProxyHeader(3, v4s, v4d); err == nil {
		t.Error("unsupported version accepted")
	}
}

// peerEcho is an upstream that only understands PROXY protocol (like HAProxy accept-proxy) and answers with the client
// address it was told about, and with the number of TCP connections it has accepted so far.
func proxyProtoUpstream(t *testing.T, version int) (*url.URL, *int) {
	t.Helper()
	conns := 0
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counting := &countListener{Listener: ln, n: &conns}
	// no fallback: a connection without a valid PROXY header is dropped, as nginx / HAProxy with accept-proxy do
	wrapped := proxyproto.NewListener(counting, proxyprotocol(version))
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.RemoteAddr)
	})}
	go srv.Serve(wrapped)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse("http://" + ln.Addr().String())
	return u, &conns
}

type countListener struct {
	net.Listener
	n *int
}

func (c *countListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		*c.n++
	}
	return conn, err
}

func proxyprotocol(version int) proxyproto.HeaderParserBuilder {
	if version == 1 {
		return proxyproto.HeaderParserBuilderFunc(func(l proxyproto.Logger) proxyproto.HeaderParser { return proxyproto.NewTextHeaderParser(l) })
	}
	return proxyproto.HeaderParserBuilderFunc(func(l proxyproto.Logger) proxyproto.HeaderParser { return proxyproto.NewBinaryHeaderParser(l) })
}

func TestProxyProtocolToUpstream(t *testing.T) {
	for _, version := range []int{1, 2} {
		upstream, conns := proxyProtoUpstream(t, version)
		core := NewDynamicProxyCore(upstream, "", &DpcoreOptions{ProxyProtocolVersion: version})
		for _, client := range []string{"203.0.113.9:51000", "198.51.100.7:40000", "[2001:db8::7]:1234"} {
			req := httptest.NewRequest(http.MethodGet, "http://front.example.com/", nil)
			req.RemoteAddr = client
			rw := httptest.NewRecorder()
			status, err := core.ProxyHTTP(rw, req, &ResponseRewriteRuleSet{ProxyDomain: upstream.Host, OriginalHost: "front.example.com"})
			if err != nil || status != 200 {
				t.Fatalf("v%d client %s: status=%d err=%v", version, client, status, err)
			}
			if got := strings.TrimSpace(rw.Body.String()); got != client {
				t.Errorf("v%d: upstream saw client %q, want %q", version, got, client)
			}
		}
		if *conns != 3 {
			t.Errorf("v%d: %d connections for 3 requests, want one per request (no reuse)", version, *conns)
		}
	}

	//Without the option the PROXY-only upstream rejects the plain connection
	upstream, _ := proxyProtoUpstream(t, 1)
	core := NewDynamicProxyCore(upstream, "", &DpcoreOptions{})
	req := httptest.NewRequest(http.MethodGet, "http://front.example.com/", nil)
	rw := httptest.NewRecorder()
	if status, err := core.ProxyHTTP(rw, req, &ResponseRewriteRuleSet{ProxyDomain: upstream.Host, OriginalHost: "front.example.com"}); err == nil && status == 200 {
		t.Error("PROXY-only upstream accepted a connection without header")
	}
}

/* Upstream mTLS */

func testClientCert(t *testing.T, cn string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestUpstreamClientCertificate(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	upstream.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)

	cert := testClientCert(t, "zoraxy-proxy")
	do := func(opts *DpcoreOptions) (int, string, error) {
		opts.IgnoreTLSVerification = true
		core := NewDynamicProxyCore(target, "", opts)
		req := httptest.NewRequest(http.MethodGet, "http://front.example.com/", nil)
		rw := httptest.NewRecorder()
		status, err := core.ProxyHTTP(rw, req, &ResponseRewriteRuleSet{ProxyDomain: target.Host, OriginalHost: "front.example.com", UseTLS: true})
		return status, rw.Body.String(), err
	}
	status, body, err := do(&DpcoreOptions{ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }})
	if err != nil || status != 200 || body != "zoraxy-proxy" {
		t.Fatalf("with client cert: status=%d body=%q err=%v", status, body, err)
	}
	if status, _, err := do(&DpcoreOptions{}); err == nil && status == 200 {
		t.Fatal("upstream that requires a client certificate accepted a connection without one")
	}
}
