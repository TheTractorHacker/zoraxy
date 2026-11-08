package dpcore

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

/*
	proxyproto.go

	PROXY protocol v1 / v2 for upstream connections, plus client certificates for upstream mTLS.

	When DpcoreOptions.ProxyProtocolVersion is 1 or 2 every new connection to the upstream starts with a
	PROXY header announcing the address of the client of the request that opened it. The header describes a
	connection, but an HTTP connection is normally shared by many requests, so connections of a proxy-protocol
	upstream are never reused (DisableKeepAlives): one connection, one request, one correct header. That costs
	a TCP (and TLS) handshake per request, enable it only for upstreams that need the real client address at
	the connection level (HAProxy / nginx with accept-proxy, Traefik, ...). For TLS upstreams the header is sent
	in clear before the TLS handshake, as the specification requires.

	The announced source is the TCP peer address of the request as seen by Zoraxy (r.RemoteAddr). When
	Zoraxy itself is behind a CDN or load balancer this is that device, not the visitor; use X-Forwarded-For
	for the visitor address in that setup. The stream (TCP / UDP) proxy is not affected.
*/

type proxySourceKey struct{}

// withProxySource stores the client address of a request for the dialer
func withProxySource(ctx context.Context, remoteAddr string) context.Context {
	return context.WithValue(ctx, proxySourceKey{}, remoteAddr)
}

func proxySourceFromContext(ctx context.Context) (netip.AddrPort, bool) {
	s, _ := ctx.Value(proxySourceKey{}).(string)
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().WithZone("").Unmap(), ap.Port()), true
}

var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// buildProxyHeader renders a PROXY header. src is the client, dst the address the upstream connection was made to.
// An invalid src produces the "unknown" (v1) / LOCAL (v2) form, which receivers treat as "use the real connection address".
func buildProxyHeader(version int, src, dst netip.AddrPort) ([]byte, error) {
	known := src.IsValid() && dst.IsValid()
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	bothV4 := known && src.Addr().Is4() && dst.Addr().Is4()
	if known && !bothV4 {
		//Mixed or IPv6: both sides must use the IPv6 family
		src = netip.AddrPortFrom(netip.AddrFrom16(src.Addr().As16()), src.Port())
		dst = netip.AddrPortFrom(netip.AddrFrom16(dst.Addr().As16()), dst.Port())
	}
	switch version {
	case 1:
		if !known {
			return []byte("PROXY UNKNOWN\r\n"), nil
		}
		proto := "TCP6"
		if bothV4 {
			proto = "TCP4"
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", proto, src.Addr(), dst.Addr(), src.Port(), dst.Port())), nil
	case 2:
		hdr := append([]byte{}, proxyV2Signature...)
		if !known {
			return append(hdr, 0x20, 0x00, 0x00, 0x00), nil //LOCAL, AF_UNSPEC, no payload
		}
		var addrs []byte
		var fam byte
		if bothV4 {
			fam = 0x11 //AF_INET, STREAM
			s, d := src.Addr().As4(), dst.Addr().As4()
			addrs = append(addrs, s[:]...)
			addrs = append(addrs, d[:]...)
		} else {
			fam = 0x21 //AF_INET6, STREAM
			s, d := src.Addr().As16(), dst.Addr().As16()
			addrs = append(addrs, s[:]...)
			addrs = append(addrs, d[:]...)
		}
		addrs = binary.BigEndian.AppendUint16(addrs, src.Port())
		addrs = binary.BigEndian.AppendUint16(addrs, dst.Port())
		hdr = append(hdr, 0x21, fam) //version 2, PROXY command
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(addrs)))
		return append(hdr, addrs...), nil
	}
	return nil, errors.New("unsupported PROXY protocol version")
}

// ProxyProtocolDialer wraps a dialer so connections start with a PROXY header (source from the request context, LOCAL / UNKNOWN without one).
// Used by the active health checker, which has no client.
func ProxyProtocolDialer(inner func(ctx context.Context, network, addr string) (net.Conn, error), version int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return proxyProtocolDialer(inner, version)
}

// proxyProtocolDialer wraps a dialer so that new connections start with a PROXY header
func proxyProtocolDialer(inner func(ctx context.Context, network, addr string) (net.Conn, error), version int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := inner(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		src, _ := proxySourceFromContext(ctx)
		var dst netip.AddrPort
		if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			dst = ta.AddrPort()
		}
		hdr, err := buildProxyHeader(version, src, dst)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err = conn.Write(hdr)
		conn.SetWriteDeadline(time.Time{})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("unable to send PROXY header: %w", err)
		}
		return conn, nil
	}
}

// clientCertConfig adds the upstream mTLS client certificate callback to a TLS config
func applyUpstreamClientCert(cfg *tls.Config, get func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) {
	if get != nil {
		cfg.GetClientCertificate = get
	}
}
