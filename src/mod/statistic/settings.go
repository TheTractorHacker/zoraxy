package statistic

import (
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
)

/*
	Statistic collection filters (all opt-in, the zero value records everything
	exactly like before):

	  - ExcludeNetworks: requests whose client IP is inside one of these CIDRs /
	    addresses are not recorded at all (e.g. the admin's own IP)
	  - ExcludeBlocked: requests that were rejected by Zoraxy itself (access
	    list, rate limit, WAF, CAPTCHA, ...) are not recorded
	  - QueryMode: how the URL query string is stored in "Top requested paths"
*/

// Query string handling modes for the recorded request URL
const (
	QueryModeStrip = "strip" // default: path only, no query string
	QueryModeMask  = "mask"  // keep parameter names, replace values with "*"
	QueryModeFull  = "full"  // keep the whole query string
)

// MaxExcludeEntries bounds the exclusion list
const MaxExcludeEntries = 256

// Settings is the user visible configuration of the collector filters
type Settings struct {
	ExcludeNetworks []string // CIDRs or single IPs
	ExcludeBlocked  bool
	QueryMode       string
}

type compiledSettings struct {
	Settings
	prefixes []netip.Prefix
}

// DefaultSettings returns the upstream compatible behaviour
func DefaultSettings() Settings {
	return Settings{QueryMode: QueryModeStrip}
}

// NormalizeNetwork validates one exclusion entry and returns it in canonical
// CIDR form (a bare IP becomes /32 or /128).
func NormalizeNetwork(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty entry")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", errors.New("invalid CIDR: " + s)
		}
		return p.Masked().String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", errors.New("invalid IP address: " + s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()).String(), nil
}

func compileSettings(s Settings) (*compiledSettings, error) {
	if len(s.ExcludeNetworks) > MaxExcludeEntries {
		return nil, errors.New("too many exclusion entries")
	}
	switch s.QueryMode {
	case "":
		s.QueryMode = QueryModeStrip
	case QueryModeStrip, QueryModeMask, QueryModeFull:
	default:
		return nil, errors.New("invalid query mode")
	}
	cs := &compiledSettings{}
	seen := map[string]bool{}
	for _, n := range s.ExcludeNetworks {
		norm, err := NormalizeNetwork(n)
		if err != nil {
			return nil, err
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		cs.Settings.ExcludeNetworks = append(cs.Settings.ExcludeNetworks, norm)
		cs.prefixes = append(cs.prefixes, netip.MustParsePrefix(norm))
	}
	cs.ExcludeBlocked = s.ExcludeBlocked
	cs.QueryMode = s.QueryMode
	return cs, nil
}

// settingsHolder is embedded in Collector
type settingsHolder struct {
	v atomic.Pointer[compiledSettings]
}

// SetSettings validates and applies new filter settings
func (c *Collector) SetSettings(s Settings) error {
	cs, err := compileSettings(s)
	if err != nil {
		return err
	}
	c.settings.v.Store(cs)
	return nil
}

// GetSettings returns the active filter settings
func (c *Collector) GetSettings() Settings {
	cs := c.settings.v.Load()
	if cs == nil {
		return DefaultSettings()
	}
	out := cs.Settings
	out.ExcludeNetworks = append([]string{}, cs.ExcludeNetworks...)
	return out
}

// QueryMode returns the active query handling mode
func (c *Collector) QueryMode() string {
	if cs := c.settings.v.Load(); cs != nil && cs.QueryMode != "" {
		return cs.QueryMode
	}
	return QueryModeStrip
}

// ExcludesBlocked reports whether requests rejected by Zoraxy itself are left out of the statistics
func (c *Collector) ExcludesBlocked() bool {
	cs := c.settings.v.Load()
	return cs != nil && cs.ExcludeBlocked
}

// ExcludesIP reports whether ip (possibly a "a,b" forwarded list, an
// IPv4-mapped IPv6 address or "[v6]") is inside the exclusion list
func (c *Collector) ExcludesIP(ip string) bool {
	cs := c.settings.v.Load()
	if cs == nil || len(cs.prefixes) == 0 {
		return false
	}
	return prefixesContain(cs.prefixes, ip)
}

func prefixesContain(prefixes []netip.Prefix, ip string) bool {
	if i := strings.Index(ip, ","); i >= 0 {
		ip = ip[:i]
	}
	ip = strings.Trim(strings.TrimSpace(ip), "[]")
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// shouldRecord applies the exclusion filters to a request
func (c *Collector) shouldRecord(ri *RequestInfo) bool {
	cs := c.settings.v.Load()
	if cs == nil {
		return true
	}
	if cs.ExcludeBlocked && ri.Blocked {
		return false
	}
	if len(cs.prefixes) > 0 && prefixesContain(cs.prefixes, ri.IpAddr) {
		return false
	}
	return true
}

// IsBlockedForwardType reports whether a request class (the "forwardType"
// given to the router log) means Zoraxy itself rejected the request:
// access list, rate limit, WAF, CAPTCHA, exploit detection, path rules,
// plugin or peer / client certificate denial.
func IsBlockedForwardType(ft string) bool {
	switch ft {
	case "blacklist", "whitelist", "ratelimit", "waf-blocked", "captcha-required",
		"exploit-blocked", "plugin-blocked", "peer-not-allowed",
		"path-rule-deny", "path-rule-noauth", "path-rule-ratelimit":
		return true
	}
	return strings.HasPrefix(ft, "client-cert-")
}

// BuildStatURL assembles the string recorded as "request URL": host + escaped
// path, plus the query string depending on mode.
func BuildStatURL(host, escapedPath, rawQuery, mode string) string {
	base := host + escapedPath
	if rawQuery == "" || mode == "" || mode == QueryModeStrip {
		return base
	}
	if mode == QueryModeFull {
		return base + "?" + rawQuery
	}
	// mask: keep the parameter names only
	parts := strings.Split(rawQuery, "&")
	for i, p := range parts {
		if eq := strings.Index(p, "="); eq >= 0 {
			parts[i] = p[:eq+1] + "*"
		}
	}
	return base + "?" + strings.Join(parts, "&")
}
