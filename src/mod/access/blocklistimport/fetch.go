package blocklistimport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultMaxDownload is the largest response body accepted from a URL source
	DefaultMaxDownload = 32 << 20
	// DefaultFetchTimeout bounds the complete download including redirects
	DefaultFetchTimeout = 30 * time.Second
	maxRedirects        = 3
)

// ErrBlockedTarget is returned when a URL resolves to a non-public address
var ErrBlockedTarget = errors.New("target address is not allowed (private, loopback, link-local or otherwise non-public)")

// Fetcher downloads blocklists from https URLs and refuses to talk to
// non-public networks. Every connection (the first request and every
// redirect hop) goes through the dialer below which resolves the name,
// validates ALL returned addresses and then dials a validated address
// directly, so DNS rebinding between check and use is not possible.
type Fetcher struct {
	MaxBytes int64
	Timeout  time.Duration

	// Test seams. Production leaves them nil.
	Resolve   func(ctx context.Context, host string) ([]netip.Addr, error)
	DialTo    func(ctx context.Context, network, addr string) (net.Conn, error)
	TLSConfig *tls.Config
}

// extraBlocked are special purpose ranges that netip does not classify as private
var extraBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     //"this network"
	netip.MustParsePrefix("100.64.0.0/10"), //carrier grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),  //IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), //benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   //reserved
	netip.MustParsePrefix("64:ff9b::/96"),  //NAT64, can embed any IPv4 address
	netip.MustParsePrefix("2002::/16"),     //6to4, can embed any IPv4 address
	netip.MustParsePrefix("100::/64"),      //discard
	netip.MustParsePrefix("fec0::/10"),     //deprecated site local
}

// IsPublicAddr reports whether an address may be contacted by the fetcher
func IsPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return false
	}
	for _, p := range extraBlocked {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func (f *Fetcher) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if f.Resolve != nil {
		return f.Resolve(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// ValidateURL checks the syntax of a source URL (https only, no credentials)
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	if u.Scheme != "https" {
		return nil, errors.New("only https URLs are allowed")
	}
	if u.User != nil {
		return nil, errors.New("URLs with embedded credentials are not allowed")
	}
	if u.Hostname() == "" {
		return nil, errors.New("URL has no host")
	}
	return u, nil
}

// guardedDial resolves, validates and dials
func (f *Fetcher) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = f.resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	for _, ip := range ips {
		if !IsPublicAddr(ip) {
			return nil, ErrBlockedTarget
		}
	}
	dial := f.DialTo
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	var lastErr error
	for _, ip := range ips {
		c, err := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (f *Fetcher) client() *http.Client {
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	tr := &http.Transport{
		Proxy:                  nil, //a proxy would bypass the dial time address check
		DialContext:            f.guardedDial,
		TLSClientConfig:        f.TLSConfig,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to a non-https URL refused")
			}
			if req.URL.User != nil {
				return errors.New("redirect with credentials refused")
			}
			return nil
		},
	}
}

// Fetch downloads the URL and returns a reader limited to MaxBytes; the
// caller must close it. A body larger than the limit yields ErrTooLarge
// while reading.
func (f *Fetcher) Fetch(ctx context.Context, raw string) (io.ReadCloser, error) {
	u, err := ValidateURL(raw)
	if err != nil {
		return nil, err
	}
	max := f.MaxBytes
	if max <= 0 {
		max = DefaultMaxDownload
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Zoraxy-blocklist-import")
	req.Header.Set("Accept", "text/plain, text/csv, */*;q=0.1")
	cl := f.client()
	resp, err := cl.Do(req)
	if err != nil {
		cl.CloseIdleConnections()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > max {
		resp.Body.Close()
		return nil, ErrTooLarge
	}
	return &limitedBody{rc: resp.Body, left: max}, nil
}

// ErrTooLarge is returned when a download exceeds the size limit
var ErrTooLarge = errors.New("download exceeds the size limit")

type limitedBody struct {
	rc   io.ReadCloser
	left int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.left <= 0 {
		// probe whether more data follows
		var b [1]byte
		n, err := l.rc.Read(b[:])
		if n > 0 {
			return 0, ErrTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.rc.Read(p)
	l.left -= int64(n)
	return n, err
}

func (l *limitedBody) Close() error { return l.rc.Close() }
