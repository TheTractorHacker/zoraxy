package dpcore

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
)

/*
	h2c.go

	HTTP/2 over cleartext TCP ("prior knowledge" h2c) for upstreams that speak plain
	HTTP/2 only, typically gRPC backends such as NetBird (upstream #1029). Go's
	http.Transport only does HTTP/2 over TLS, so such an upstream got HTTP/1.1 and
	gRPC calls failed.

	Enabled per upstream (Upstream.H2C, default off) for plain http:// upstreams.
	The connection pool lives in one http2.Transport per upstream, requests keep
	their streaming bodies and trailers (gRPC), and requests that need HTTP/1.1
	(Upgrade, e.g. WebSocket) go through the regular transport.
*/

type h2cTransport struct {
	h2 *http2.Transport
	h1 http.RoundTripper
}

func newH2CTransport(h1 http.RoundTripper) *h2cTransport {
	return &h2cTransport{
		h2: &http2.Transport{
			AllowHTTP:          true,
			DisableCompression: true,
			// "TLS" dial that is really a plain TCP connection
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
		h1: h1,
	}
}

func (t *h2cTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// HTTP/2 has no Upgrade mechanism: keep those on HTTP/1.1
	if req.Header.Get("Upgrade") != "" || strings.EqualFold(req.Method, http.MethodConnect) {
		return t.h1.RoundTrip(req)
	}
	return t.h2.RoundTrip(req)
}

// CloseIdleConnections lets http.Client style users and tests release the pooled connections
func (t *h2cTransport) CloseIdleConnections() {
	t.h2.CloseIdleConnections()
	if c, ok := t.h1.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
