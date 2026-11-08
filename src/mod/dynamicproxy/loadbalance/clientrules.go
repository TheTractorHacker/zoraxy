package loadbalance

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
)

/*
	Client attribute routing (upstream #677)

	Config.ClientRules is an ordered list. The first rule whose CIDR list or country list
	matches the client selects a group of upstreams (by their address). The configured
	algorithm then runs on that group only, so every algorithm, health check, draining flag
	and sticky session keeps working inside the group. If no upstream of the group is
	available the rule's Fallback decides: "any" (default) uses all remaining candidates,
	"deny" fails the request (the proxy answers 521/503 like any other upstream failure).
	Clients matching no rule use all candidates, exactly as without rules.
*/

const (
	ClientRuleFallbackAny  = "any"
	ClientRuleFallbackDeny = "deny"
)

// ClientRule pins matching clients to a group of upstreams
type ClientRule struct {
	Name      string
	CIDRs     []string //Client IPs or CIDR blocks
	Countries []string //ISO 3166-1 alpha-2 codes, resolved with the GeoIP database
	Upstreams []string //OriginIpOrDomain of the upstreams in the group
	Fallback  string   //"any" (default) or "deny"
}

type compiledClientRule struct {
	rule      *ClientRule
	prefixes  []netip.Prefix
	countries map[string]bool
	group     map[string]bool
}

type clientRuleState struct {
	once  sync.Once
	rules []compiledClientRule
}

func parseClientCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (c *Config) validateClientRules() error {
	if len(c.ClientRules) > 100 {
		return errors.New("too many client rules (max 100)")
	}
	for i, r := range c.ClientRules {
		if r == nil {
			return fmt.Errorf("client rule %d is empty", i+1)
		}
		if len(r.CIDRs) == 0 && len(r.Countries) == 0 {
			return fmt.Errorf("client rule %d needs at least one CIDR or country", i+1)
		}
		if len(r.Upstreams) == 0 {
			return fmt.Errorf("client rule %d needs at least one upstream", i+1)
		}
		if r.Fallback != "" && r.Fallback != ClientRuleFallbackAny && r.Fallback != ClientRuleFallbackDeny {
			return fmt.Errorf("client rule %d: fallback must be any or deny", i+1)
		}
		for _, cidr := range r.CIDRs {
			if _, err := parseClientCIDR(cidr); err != nil {
				return fmt.Errorf("client rule %d: invalid CIDR %q", i+1, cidr)
			}
		}
		for _, cc := range r.Countries {
			if len(cc) != 2 || !isAlpha(cc) {
				return fmt.Errorf("client rule %d: %q is not a two letter country code", i+1, cc)
			}
		}
	}
	return nil
}

func isAlpha(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// ValidateClientRuleGroups checks that every group member is an upstream of the endpoint
func (c *Config) ValidateClientRuleGroups(origins []string) error {
	if c == nil {
		return nil
	}
	known := map[string]bool{}
	for _, o := range origins {
		known[o] = true
	}
	for i, r := range c.ClientRules {
		for _, u := range r.Upstreams {
			if !known[u] {
				return fmt.Errorf("client rule %d: upstream %q does not exist in this proxy rule", i+1, u)
			}
		}
	}
	return nil
}

func (c *Config) compiledClientRules() []compiledClientRule {
	if c == nil || len(c.ClientRules) == 0 {
		return nil
	}
	c.crState.once.Do(func() {
		for _, r := range c.ClientRules {
			cr := compiledClientRule{rule: r, countries: map[string]bool{}, group: map[string]bool{}}
			for _, s := range r.CIDRs {
				if p, err := parseClientCIDR(s); err == nil {
					cr.prefixes = append(cr.prefixes, p.Masked())
				}
			}
			for _, cc := range r.Countries {
				cr.countries[strings.ToUpper(cc)] = true
			}
			for _, u := range r.Upstreams {
				cr.group[u] = true
			}
			c.crState.rules = append(c.crState.rules, cr)
		}
	})
	return c.crState.rules
}

// matchClientRule returns the first rule matching the client, nil if none
func (c *Config) matchClientRule(opt *SelectOptions) *compiledClientRule {
	rules := c.compiledClientRules()
	if len(rules) == 0 || opt.ClientIP == nil {
		return nil
	}
	ipStr := opt.ClientIP()
	var addr netip.Addr
	if h, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = h
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	country, countryDone := "", false
	for i := range rules {
		r := &rules[i]
		for _, p := range r.prefixes {
			if p.Contains(addr) {
				return r
			}
		}
		if len(r.countries) > 0 && opt.ClientCountry != nil {
			if !countryDone {
				country, countryDone = strings.ToUpper(opt.ClientCountry()), true
			}
			if country != "" && r.countries[country] {
				return r
			}
		}
	}
	return nil
}

// restrictToClientGroup applies the matching client rule to the candidates
func (c *Config) restrictToClientGroup(cands []*Upstream, rule *compiledClientRule) ([]*Upstream, error) {
	sub := make([]*Upstream, 0, len(cands))
	for _, u := range cands {
		if rule.group[u.OriginIpOrDomain] {
			sub = append(sub, u)
		}
	}
	if len(sub) > 0 {
		return sub, nil
	}
	if rule.rule.Fallback == ClientRuleFallbackDeny {
		return nil, ErrNoUpstreamForClient
	}
	return cands, nil
}

// ErrNoUpstreamForClient is returned when a "deny" client rule has no available upstream
var ErrNoUpstreamForClient = errors.New("no upstream of the client's group is available")
