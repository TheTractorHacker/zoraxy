package aicrawler

import (
	"context"
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

/*
	Refreshing the published range lists. Only ever started by the admin pressing the button.

	SSRF guard (the URL is not admin supplied, but the guard stays on anyway):
	  - only the exact https URLs of Sources() (compared after parsing: scheme, host, port, path, no userinfo, no query)
	  - the address that is actually dialled must be public: loopback, private, link-local, CGNAT, multicast,
	    unspecified, reserved, cloud metadata and IPv6 transition ranges are refused (checked after DNS, so DNS
	    rebinding and names that resolve to internal addresses are covered)
	  - redirects are never followed, environment proxies are ignored (they would bypass the dial check)
	  - at most MaxBytes of body, at most Timeout in total, HTTP 200 only
*/

const (
	fetchMaxBytes = 2 << 20
	fetchTimeout  = 15 * time.Second
)

// Fetcher downloads the lists
type Fetcher struct {
	Client   *http.Client
	Sources  []Source // the allow-list
	MaxBytes int64

	allowPrivate bool // tests only: the httptest server listens on loopback
}

// NewFetcher builds the guarded fetcher for the built-in allow-list
func NewFetcher() *Fetcher {
	f := &Fetcher{Sources: Sources(), MaxBytes: fetchMaxBytes}
	f.Client = newGuardedClient(fetchTimeout, func() bool { return f.allowPrivate }, nil)
	return f
}

var (
	cgnat      = netip.MustParsePrefix("100.64.0.0/10")
	zeroNet    = netip.MustParsePrefix("0.0.0.0/8")
	reservedV4 = netip.MustParsePrefix("240.0.0.0/4")
	metadata   = []netip.Addr{
		netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("169.254.170.2"), netip.MustParseAddr("100.100.100.200"),
		netip.MustParseAddr("192.0.0.192"), netip.MustParseAddr("168.63.129.16"), netip.MustParseAddr("fd00:ec2::254"),
	}
	v6Transition = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("::/96"),
	}
)

// checkPublicIP returns an error when ip must not be contacted
func checkPublicIP(ip netip.Addr) error {
	ip = ip.Unmap()
	for _, m := range metadata {
		if ip == m {
			return errors.New("cloud metadata address refused")
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip) || zeroNet.Contains(ip) || reservedV4.Contains(ip) {
		return errors.New("non-public address refused")
	}
	if ip.Is6() {
		for _, p := range v6Transition {
			if p.Contains(ip) {
				return errors.New("IPv6 transition address refused")
			}
		}
	}
	return nil
}

// lookupIP is replaced in tests
var lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func newGuardedClient(timeout time.Duration, allowPrivate func() bool, lookup func(ctx context.Context, host string) ([]netip.Addr, error)) *http.Client {
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
			} else {
				lk := lookup
				if lk == nil {
					lk = lookupIP
				}
				if ips, err = lk(ctx, host); err != nil {
					return nil, fmt.Errorf("cannot resolve %s: %w", host, err)
				}
			}
			if len(ips) == 0 {
				return nil, errors.New("no address")
			}
			for _, ip := range ips { // every address must be public, so a mixed answer cannot be used to slip through
				if allowPrivate != nil && allowPrivate() {
					continue
				}
				if err := checkPublicIP(ip); err != nil {
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
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// allowed reports whether rawURL is exactly one of the allow-listed URLs
func (f *Fetcher) allowed(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return false
	}
	for _, s := range f.Sources {
		a, err := url.Parse(s.URL)
		if err != nil {
			continue
		}
		if strings.EqualFold(a.Host, u.Host) && a.Path == u.Path && a.Scheme == u.Scheme {
			return true
		}
	}
	return false
}

// Fetch downloads and parses one list. The URL must be on the allow-list.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) ([]string, error) {
	if !f.allowed(rawURL) {
		return nil, errors.New("this address is not on the allow-list of range sources")
	}
	max := f.MaxBytes
	if max <= 0 {
		max = fetchMaxBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Zoraxy-ai-crawler-ranges")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the server answered HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > max {
		return nil, errors.New("the answer is larger than the limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("reading the answer failed: %w", err)
	}
	if int64(len(body)) > max {
		return nil, errors.New("the answer is larger than the limit")
	}
	return ParseRangeJSON(body)
}

// RefreshResult is the outcome for one source
type RefreshResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Count int    `json:"count,omitempty"`
	Error string `json:"error,omitempty"`
}

// Refresh fetches the listed sources (empty = all) one after the other. A failed source keeps the data it had.
func (s *RangeStore) Refresh(ctx context.Context, f *Fetcher, ids []string) []RefreshResult {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []RefreshResult
	for _, src := range f.Sources {
		if len(want) > 0 && !want[src.ID] {
			continue
		}
		res := RefreshResult{ID: src.ID}
		list, err := f.Fetch(ctx, src.URL)
		if err == nil {
			err = s.SetPrefixes(src.ID, list, time.Now())
			res.Count = len(list)
		}
		if err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
		out = append(out, res)
	}
	return out
}
