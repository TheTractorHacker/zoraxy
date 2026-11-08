// Package sablier implements the client side of Sablier's reverse proxy plugin contract
// (https://sablierapp.dev, fork #120 / upstream #564), natively and without a plugin.
//
// A rule gated by Sablier asks the Sablier server before every proxied request (with a short cache of the "ready" answer):
//
//	GET {url}/api/strategies/dynamic?session_duration=5m&names=a&names=b&display_name=..&theme=..&refresh_frequency=5s
//	GET {url}/api/strategies/blocking?session_duration=5m&group=g&timeout=30s
//
// The response header X-Sablier-Session-Status is "ready" when the workload is up: the request is proxied normally. Anything
// else is answered with Sablier's body (the waiting page for the dynamic strategy) and its status, Content-Type and no-store.
package sablier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	StrategyDynamic  = "dynamic"
	StrategyBlocking = "blocking"

	StatusHeader = "X-Sablier-Session-Status"
	StatusReady  = "ready"

	DefaultSessionDuration = 5 * time.Minute
	DefaultReadyCache      = 3 * time.Second
	MaxReadyCache          = 60 * time.Second
	DefaultBlockingTimeout = 60 * time.Second
	MaxBlockingTimeout     = 10 * time.Minute
	DefaultRequestTimeout  = 5 * time.Second
	maxBodyBytes           = 1 << 20
)

// Config is the per-rule Sablier configuration (stored in the proxy rule JSON)
type Config struct {
	Enabled bool
	URL     string //Base URL of the Sablier server, e.g. http://sablier:10000

	Strategy        string   //"dynamic" (waiting page, default) or "blocking" (hold the request until ready or timeout)
	Names           []string //Containers / services to start (exclusive with Group)
	Group           string   //Sablier group to start
	SessionDuration string   //Go duration, how long the workload stays up after the last request (default 5m)

	DisplayName      string `json:",omitempty"` //Dynamic: name shown on the waiting page
	Theme            string `json:",omitempty"` //Dynamic: waiting page theme
	RefreshFrequency string `json:",omitempty"` //Dynamic: how often the waiting page polls (Go duration)
	ShowDetails      bool   `json:",omitempty"` //Dynamic: show instance details
	BlockingTimeout  string `json:",omitempty"` //Blocking: how long Sablier waits for the workload (default 1m)

	ReadyCacheSeconds     int      `json:",omitempty"` //How long a "ready" answer is trusted, 0 = default (3 s), max 60. Use -1 to disable
	RequestTimeoutSeconds int      `json:",omitempty"` //Timeout of the call to Sablier (default 5 s; blocking: timeout + 5 s)
	FailOpen              bool     `json:",omitempty"` //Proxy the request when Sablier is unreachable or misbehaves (default: fail closed with 503)
	BypassPaths           []string `json:",omitempty"` //Path prefixes that skip the gate (health checks, public files)
	AllowMetadataAddress  bool     `json:",omitempty"` //Allow a Sablier URL on link-local / cloud metadata addresses (blocked by default)
}

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@/\-]{0,127}$`)
	themeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$`)
)

// blockedPrefixes are never reachable unless AllowMetadataAddress: link-local (cloud metadata 169.254.169.254, fe80::/10),
// "this network", and the well known metadata addresses outside link-local.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.100.100.200/32"), //Alibaba Cloud metadata
	netip.MustParsePrefix("192.0.0.192/32"),     //Oracle Cloud metadata (legacy)
	netip.MustParsePrefix("fd00:ec2::254/128"),  //AWS IPv6 metadata
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("ff00::/8"),
}

func blockedIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	a = a.Unmap()
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseDur(field, v string, min, max time.Duration) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 30s or 5m", field)
	}
	if d < min || d > max {
		return 0, fmt.Errorf("%s must be between %s and %s", field, min, max)
	}
	return d, nil
}

func hasCtl(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// Validate checks the config. Syntax only: it does not resolve or contact the Sablier server.
func (c *Config) Validate() error {
	if c == nil || (!c.Enabled && c.URL == "") {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Hostname() == "" {
		return errors.New("Sablier URL must be http(s)://host[:port] without credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("Sablier URL must not contain a query or fragment")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && blockedIP(ip) && !c.AllowMetadataAddress {
		return errors.New("Sablier URL points at a link-local / metadata address (tick the allow option if that is really intended)")
	}
	switch c.Strategy {
	case "", StrategyDynamic, StrategyBlocking:
	default:
		return errors.New("strategy must be dynamic or blocking")
	}
	if (len(c.Names) == 0) == (c.Group == "") {
		return errors.New("set either one or more names or a group (not both)")
	}
	if len(c.Names) > 32 {
		return errors.New("too many names (max 32)")
	}
	for _, n := range c.Names {
		if !nameRe.MatchString(n) {
			return fmt.Errorf("invalid name %q", n)
		}
	}
	if c.Group != "" && !nameRe.MatchString(c.Group) {
		return errors.New("invalid group")
	}
	if c.SessionDuration != "" {
		if _, err := parseDur("session duration", c.SessionDuration, 5*time.Second, 30*24*time.Hour); err != nil {
			return err
		}
	}
	if c.RefreshFrequency != "" {
		if _, err := parseDur("refresh frequency", c.RefreshFrequency, time.Second, time.Hour); err != nil {
			return err
		}
	}
	if c.BlockingTimeout != "" {
		if _, err := parseDur("blocking timeout", c.BlockingTimeout, time.Second, MaxBlockingTimeout); err != nil {
			return err
		}
	}
	if len(c.DisplayName) > 100 || hasCtl(c.DisplayName) {
		return errors.New("display name must be at most 100 printable characters")
	}
	if c.Theme != "" && !themeRe.MatchString(c.Theme) {
		return errors.New("invalid theme name")
	}
	if c.ReadyCacheSeconds < -1 || c.ReadyCacheSeconds > int(MaxReadyCache/time.Second) {
		return errors.New("ready cache must be -1 (off) or 0-60 seconds")
	}
	if c.RequestTimeoutSeconds < 0 || c.RequestTimeoutSeconds > 600 {
		return errors.New("request timeout must be 0-600 seconds")
	}
	if len(c.BypassPaths) > 50 {
		return errors.New("too many bypass paths")
	}
	for _, p := range c.BypassPaths {
		if !strings.HasPrefix(p, "/") || hasCtl(p) || len(p) > 256 {
			return fmt.Errorf("bypass path %q must start with /", p)
		}
	}
	return nil
}

// Outcome of asking Sablier
type Outcome struct {
	Ready  bool
	Status int    //Sablier's status when not ready
	Type   string //Content-Type when not ready
	Body   []byte //Waiting page when not ready
	Cached bool
}

// Gate asks Sablier on behalf of one rule. Safe for concurrent use.
type Gate struct {
	cfg    Config
	client *http.Client
	now    func() time.Time

	mu         sync.Mutex
	readyUntil time.Time
	inflight   *call
}

type call struct {
	done chan struct{}
	out  *Outcome
	err  error
}

// New builds the gate of a validated config
func New(cfg Config) (*Gate, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	g := &Gate{cfg: cfg, now: time.Now}
	g.client = newClient(cfg)
	return g, nil
}

func newClient(cfg Config) *http.Client {
	d := &net.Dialer{
		Timeout: 3 * time.Second,
		//Every connection address is checked here, after DNS resolution, so a name that resolves to a metadata address is refused too
		Control: func(network, address string, _ syscall.RawConn) error {
			if cfg.AllowMetadataAddress {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || blockedIP(ip) {
				return errors.New("sablier: connection to a link-local / metadata address refused")
			}
			return nil
		},
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, //never through an environment proxy: the address checks above must see the real peer
			DialContext:         d.DialContext,
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// RequestURL builds the Sablier API URL for this config
func (c *Config) RequestURL() string {
	strategy := c.Strategy
	if strategy == "" {
		strategy = StrategyDynamic
	}
	q := url.Values{}
	sd := c.SessionDuration
	if sd == "" {
		sd = DefaultSessionDuration.String()
	}
	q.Set("session_duration", sd)
	for _, n := range c.Names {
		q.Add("names", n)
	}
	if c.Group != "" {
		q.Set("group", c.Group)
	}
	if strategy == StrategyDynamic {
		if c.DisplayName != "" {
			q.Set("display_name", c.DisplayName)
		}
		if c.Theme != "" {
			q.Set("theme", c.Theme)
		}
		if c.RefreshFrequency != "" {
			q.Set("refresh_frequency", c.RefreshFrequency)
		}
		if c.ShowDetails {
			q.Set("show_details", "true")
		}
	} else {
		bt := c.BlockingTimeout
		if bt == "" {
			bt = DefaultBlockingTimeout.String()
		}
		q.Set("timeout", bt)
	}
	return strings.TrimSuffix(c.URL, "/") + "/api/strategies/" + strategy + "?" + q.Encode()
}

func (g *Gate) readyTTL() time.Duration {
	switch n := g.cfg.ReadyCacheSeconds; {
	case n < 0:
		return 0
	case n == 0:
		return DefaultReadyCache
	default:
		return time.Duration(n) * time.Second
	}
}

func (g *Gate) timeout() time.Duration {
	if n := g.cfg.RequestTimeoutSeconds; n > 0 {
		return time.Duration(n) * time.Second
	}
	if g.cfg.Strategy == StrategyBlocking {
		bt := DefaultBlockingTimeout
		if g.cfg.BlockingTimeout != "" {
			if d, err := time.ParseDuration(g.cfg.BlockingTimeout); err == nil {
				bt = d
			}
		}
		return bt + DefaultRequestTimeout
	}
	return DefaultRequestTimeout
}

// Check returns the outcome for one incoming request. Concurrent callers share one call to Sablier.
func (g *Gate) Check(ctx context.Context) (*Outcome, error) {
	g.mu.Lock()
	if g.now().Before(g.readyUntil) {
		g.mu.Unlock()
		return &Outcome{Ready: true, Cached: true}, nil
	}
	if c := g.inflight; c != nil {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.out, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	g.inflight = c
	g.mu.Unlock()

	//The shared call must not die with one impatient client: it has its own deadline
	cctx, cancel := context.WithTimeout(context.Background(), g.timeout())
	go func() {
		defer cancel()
		out, err := g.fetch(cctx)
		g.mu.Lock()
		if err == nil && out.Ready {
			if ttl := g.readyTTL(); ttl > 0 {
				g.readyUntil = g.now().Add(ttl)
			}
		}
		g.inflight = nil
		g.mu.Unlock()
		c.out, c.err = out, err
		close(c.done)
	}()
	select {
	case <-c.done:
		return c.out, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Invalidate forgets a cached ready answer (used by tests / after an edit)
func (g *Gate) Invalidate() {
	g.mu.Lock()
	g.readyUntil = time.Time{}
	g.mu.Unlock()
}

func (g *Gate) fetch(ctx context.Context) (*Outcome, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.RequestURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Zoraxy-Sablier")
	req.Header.Set("Accept", "text/html, application/json;q=0.9, */*;q=0.8")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sablier request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("sablier response read failed: %w", err)
	}
	if len(body) > maxBodyBytes {
		return nil, errors.New("sablier response too large")
	}
	status := resp.Header.Get(StatusHeader)
	if strings.EqualFold(status, StatusReady) && resp.StatusCode < 300 {
		return &Outcome{Ready: true}, nil
	}
	if status == "" {
		//Without the session status header this is not a session answer (wrong URL, auth proxy in between, Sablier error)
		return nil, fmt.Errorf("sablier answered %d without %s", resp.StatusCode, StatusHeader)
	}
	st := resp.StatusCode
	if st < 200 || st > 599 || st == 101 {
		st = http.StatusServiceUnavailable
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = http.DetectContentType(body)
	}
	return &Outcome{Status: st, Type: ct, Body: bytes.Clone(body)}, nil
}

// Bypass reports whether the path skips the gate
func (c *Config) Bypass(path string) bool {
	for _, p := range c.BypassPaths {
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}
