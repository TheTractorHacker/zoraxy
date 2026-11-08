// Package dnsresponder is an opt-in, deliberately small authoritative DNS
// responder for the hostnames Zoraxy proxies (a split-horizon helper: LAN clients
// resolve the proxied names straight to the proxy). It is NOT a general DNS server.
//
// Safety properties: off by default; binds only to an explicitly configured
// address (wildcard binds need an explicit confirmation field); refuses every name
// it does not host unless forwarding is enabled AND the client is inside the
// configured CIDRs (so it can never become an open resolver); per client rate
// limiting; UDP responses are size limited; TCP has timeouts and a connection cap.
package dnsresponder

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultPort is used when the listen address has no port
const DefaultPort = 5353

// Config is the persisted responder configuration
type Config struct {
	Enabled            bool   `json:"enabled"`
	ListenAddr         string `json:"listenAddr"`         //ip:port (no hostnames). Port defaults to 5353
	AllowAllInterfaces bool   `json:"allowAllInterfaces"` //Must be true to bind an empty / 0.0.0.0 / :: address

	IPv4 string `json:"ipv4"` //Address returned for A queries (default: the listen address if IPv4)
	IPv6 string `json:"ipv6"` //Address returned for AAAA queries (default: the listen address if IPv6)
	TTL  uint32 `json:"ttl"`  //Seconds, default 60

	ForwardEnabled bool     `json:"forwardEnabled"` //Forward non-hosted names to Upstreams
	Upstreams      []string `json:"upstreams"`      //ip or ip:port resolvers
	AllowedCIDRs   []string `json:"allowedCidrs"`   //Only clients inside these may use forwarding

	RateLimitQPS  float64 `json:"rateLimitQps"`  //Queries per second per client IP (IPv6: per /64), default 20
	RateBurst     int     `json:"rateBurst"`     //Token bucket size, default 40
	MaxUDPSize    int     `json:"maxUdpSize"`    //Maximum UDP response size, 512-4096, default 1232
	TCPTimeoutSec int     `json:"tcpTimeoutSec"` //TCP read / write / idle timeout, default 5
	MaxTCPConns   int     `json:"maxTcpConns"`   //Concurrent TCP connections, default 64
}

// DefaultConfig returns the disabled default configuration
func DefaultConfig() Config {
	c := Config{}
	c.Normalize()
	return c
}

// Normalize fills defaults and canonicalises text fields. It never fails.
func (c *Config) Normalize() {
	c.ListenAddr = strings.TrimSpace(c.ListenAddr)
	if c.ListenAddr != "" {
		if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
			if a, perr := netip.ParseAddr(strings.Trim(c.ListenAddr, "[]")); perr == nil {
				c.ListenAddr = net.JoinHostPort(a.String(), strconv.Itoa(DefaultPort))
			}
		}
	}
	c.IPv4 = strings.TrimSpace(c.IPv4)
	c.IPv6 = strings.TrimSpace(c.IPv6)
	if c.TTL == 0 {
		c.TTL = 60
	}
	if c.RateLimitQPS == 0 {
		c.RateLimitQPS = 20
	}
	if c.RateBurst == 0 {
		c.RateBurst = 40
	}
	if c.MaxUDPSize == 0 {
		c.MaxUDPSize = 1232
	}
	if c.TCPTimeoutSec == 0 {
		c.TCPTimeoutSec = 5
	}
	if c.MaxTCPConns == 0 {
		c.MaxTCPConns = 64
	}
	if c.Upstreams == nil {
		c.Upstreams = []string{}
	}
	if c.AllowedCIDRs == nil {
		c.AllowedCIDRs = []string{}
	}
	ups := make([]string, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if n, err := normalizeUpstream(u); err == nil {
			u = n
		}
		ups = append(ups, u)
	}
	c.Upstreams = ups
	cidrs := make([]string, 0, len(c.AllowedCIDRs))
	for _, s := range c.AllowedCIDRs {
		s = strings.TrimSpace(s)
		if s != "" {
			cidrs = append(cidrs, s)
		}
	}
	c.AllowedCIDRs = cidrs
}

func normalizeUpstream(u string) (string, error) {
	if h, p, err := net.SplitHostPort(u); err == nil {
		a, perr := netip.ParseAddr(h)
		port, nerr := strconv.Atoi(p)
		if perr != nil || nerr != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid upstream %q (use ip or ip:port)", u)
		}
		return net.JoinHostPort(a.Unmap().String(), strconv.Itoa(port)), nil
	}
	a, err := netip.ParseAddr(strings.Trim(u, "[]"))
	if err != nil {
		return "", fmt.Errorf("invalid upstream %q (use ip or ip:port)", u)
	}
	return net.JoinHostPort(a.Unmap().String(), "53"), nil
}

// ParseListenAddr splits the listen address. wildcard is true for an empty / unspecified host.
func ParseListenAddr(addr string) (host string, port int, wildcard bool, err error) {
	h, p, serr := net.SplitHostPort(addr)
	if serr != nil {
		return "", 0, false, errors.New("listen address must be ip:port")
	}
	port, perr := strconv.Atoi(p)
	if perr != nil || port < 0 || port > 65535 {
		return "", 0, false, errors.New("port must be between 1 and 65535")
	}
	if h == "" {
		return "", port, true, nil
	}
	a, aerr := netip.ParseAddr(h)
	if aerr != nil || a.Zone() != "" {
		return "", 0, false, errors.New("listen host must be an IP address")
	}
	return a.String(), port, a.IsUnspecified(), nil
}

// Validate checks a normalised config. Disabled configs only get syntax checks on
// fields that are set. Port 0 is refused (tests use an internal path).
func (c Config) Validate() error { return c.validate(false) }

func (c Config) validate(allowEphemeral bool) error {
	if c.ListenAddr == "" {
		if c.Enabled {
			return errors.New("a listen address is required (for example 192.168.1.2:5353)")
		}
	} else {
		_, port, wildcard, err := ParseListenAddr(c.ListenAddr)
		if err != nil {
			return err
		}
		if port == 0 && !allowEphemeral {
			return errors.New("port must be between 1 and 65535")
		}
		if wildcard && c.Enabled && !c.AllowAllInterfaces {
			return errors.New("listening on all interfaces needs the explicit confirmation option; prefer binding a specific address")
		}
	}
	for _, s := range []string{c.IPv4, c.IPv6} {
		if s == "" {
			continue
		}
		if _, err := netip.ParseAddr(s); err != nil {
			return fmt.Errorf("invalid answer address %q", s)
		}
	}
	if c.IPv4 != "" {
		if a, _ := netip.ParseAddr(c.IPv4); !a.Unmap().Is4() {
			return errors.New("IPv4 answer address must be an IPv4 address")
		}
	}
	if c.IPv6 != "" {
		if a, _ := netip.ParseAddr(c.IPv6); a.Is4() || a.Is4In6() {
			return errors.New("IPv6 answer address must be an IPv6 address")
		}
	}
	if c.TTL > 86400 {
		return errors.New("ttl must be at most 86400")
	}
	if c.RateLimitQPS <= 0 || c.RateLimitQPS > 10000 || c.RateBurst < 1 || c.RateBurst > 10000 {
		return errors.New("rate limit must be 0-10000 qps with a burst of 1-10000")
	}
	if c.MaxUDPSize < 512 || c.MaxUDPSize > 4096 {
		return errors.New("max UDP size must be between 512 and 4096")
	}
	if c.TCPTimeoutSec < 1 || c.TCPTimeoutSec > 60 {
		return errors.New("TCP timeout must be between 1 and 60 seconds")
	}
	if c.MaxTCPConns < 1 || c.MaxTCPConns > 1024 {
		return errors.New("max TCP connections must be between 1 and 1024")
	}
	if len(c.Upstreams) > 8 || len(c.AllowedCIDRs) > 64 {
		return errors.New("too many upstreams or allowed CIDRs")
	}
	for _, u := range c.Upstreams {
		if _, err := normalizeUpstream(u); err != nil {
			return err
		}
	}
	for _, s := range c.AllowedCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q", s)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("CIDR %q would allow every client; forwarding is never open to the whole internet", s)
		}
	}
	if c.ForwardEnabled {
		if len(c.Upstreams) == 0 {
			return errors.New("forwarding needs at least one upstream resolver")
		}
		if len(c.AllowedCIDRs) == 0 {
			return errors.New("forwarding needs at least one allowed client CIDR")
		}
		if c.ListenAddr != "" {
			_, lport, _, _ := ParseListenAddr(c.ListenAddr)
			for _, u := range c.Upstreams {
				n, _ := normalizeUpstream(u)
				if n == c.ListenAddr && lport != 0 {
					return errors.New("an upstream may not be this responder itself")
				}
			}
		}
	}
	return nil
}
