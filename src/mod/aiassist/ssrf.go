package aiassist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

/*
	SSRF guard. The configured endpoint is admin supplied, but a stolen session or a CSRF slip
	must not turn the proxy into a scanner of the cloud metadata service or the internal network.

	Rules:
	  - link-local (169.254/16, fe80::/10), cloud metadata addresses, multicast, unspecified: always refused
	  - loopback, private (RFC 1918, ULA), CGNAT: refused unless provider is openai_compatible AND the
	    admin ticked "local model"
	  - the check runs on the address that is actually dialled (after DNS), so DNS names that resolve to a
	    private range and DNS rebinding are covered; every redirect is refused
	  - environment proxies are ignored (they would bypass the check)
*/

var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, OpenStack, DigitalOcean
	netip.MustParseAddr("169.254.170.2"),   // AWS ECS task metadata
	netip.MustParseAddr("100.100.100.200"), // Alibaba
	netip.MustParseAddr("192.0.0.192"),     // Oracle
	netip.MustParseAddr("168.63.129.16"),   // Azure wire server
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")
var zeroNet = netip.MustParsePrefix("0.0.0.0/8")
var reserved = netip.MustParsePrefix("240.0.0.0/4")

// checkIP returns an error when ip must not be contacted.
func checkIP(ip netip.Addr, allowLocal bool) error {
	ip = ip.Unmap()
	for _, m := range metadataAddrs {
		if ip == m {
			return errors.New("the endpoint address is a cloud metadata address and is always refused")
		}
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return errors.New("link-local, multicast and unspecified endpoint addresses are always refused")
	}
	if zeroNet.Contains(ip) || reserved.Contains(ip) {
		return errors.New("reserved endpoint addresses are refused")
	}
	if ip.IsLoopback() || ip.IsPrivate() || cgnat.Contains(ip) {
		if !allowLocal {
			return errors.New("loopback and private endpoint addresses need the OpenAI-compatible provider with the local model box ticked")
		}
	}
	return nil
}

// checkLiteralHost rejects IP literal hosts at settings time (names are checked when dialled).
func checkLiteralHost(host string, allowLocal bool) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return checkIP(ip, allowLocal)
	}
	return nil
}

// lookupIP is replaced in tests.
var lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// newGuardedClient builds an HTTP client that only connects to allowed addresses and never follows redirects.
func newGuardedClient(allowLocal bool, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var ips []netip.Addr
			if ip, perr := netip.ParseAddr(host); perr == nil {
				ips = []netip.Addr{ip}
			} else if ips, err = lookupIP(ctx, host); err != nil {
				return nil, fmt.Errorf("cannot resolve the endpoint host: %w", err)
			}
			if len(ips) == 0 {
				return nil, errors.New("the endpoint host has no address")
			}
			for _, ip := range ips { // every address must be allowed, so a mixed answer cannot be used to slip through
				if err := checkIP(ip, allowLocal); err != nil {
					return nil, err
				}
			}
			var last error
			for _, ip := range ips {
				c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
