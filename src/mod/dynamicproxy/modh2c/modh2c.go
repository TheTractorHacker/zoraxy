package modh2c

/*
	modh2c.go

	This module is a simple h2c roundtripper for dpcore
*/

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

type H2CRoundTripper struct {
}

func NewH2CRoundTripper() *H2CRoundTripper {
	return &H2CRoundTripper{}
}

// Example from https://github.com/thrawn01/h2c-golang-example/blob/master/cmd/client/main.go
func (h2c *H2CRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Keep the caller's context: cancelling a private context when RoundTrip returns would
	// abort the response body that the caller is still reading.
	req = req.Clone(req.Context())

	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	return tr.RoundTrip(req)
}

func (h2c *H2CRoundTripper) CheckServerSupportsH2C(serverURL string) bool {
	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		return false
	}

	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	_, err = tr.RoundTrip(req)
	return err == nil
}
