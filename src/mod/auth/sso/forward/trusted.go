package forward

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// applyTrustedForwarding overrides the scheme and client address of the auth subrequest with the values
// reported by a trusted TLS-terminating proxy (Cloudflare Tunnel, HAProxy, ...) in front of Zoraxy.
// Requests from peers that are not trusted are left exactly as computed from the TCP connection.
func (ar *AuthRouter) applyTrustedForwarding(r, req *http.Request) {
	if ar.options.IsTrustedProxy == nil {
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !ar.options.IsTrustedProxy(host) {
		return
	}
	proto := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get(HeaderXForwardedProto), ",")[0]))
	if proto == "https" || proto == "http" {
		req.Header.Set(HeaderXForwardedProto, proto)
		if orig := req.Header.Get(HeaderXOriginalURL); orig != "" {
			if u, perr := url.Parse(orig); perr == nil {
				u.Scheme = proto
				req.Header.Set(HeaderXOriginalURL, u.String())
			}
		}
	}
	for _, h := range []string{"CF-Connecting-IP", "X-Real-Ip", "X-Forwarded-For"} {
		v, _, _ := strings.Cut(r.Header.Get(h), ",")
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			req.Header.Set(HeaderXForwardedFor, ip.String())
			if req.Header.Get(HeaderXOriginalIP) != "" {
				req.Header.Set(HeaderXOriginalIP, ip.String())
			}
			break
		}
	}
}
