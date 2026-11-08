package ech

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSCheckResult is the outcome of looking up the HTTPS record of a host
type DNSCheckResult struct {
	Host        string
	Resolver    string
	HasHTTPS    bool     // At least one HTTPS record exists
	HasECH      bool     // At least one record carries an ech= parameter
	Published   []string // Base64 ECHConfigLists found in the records
	Expected    string   // Base64 ECHConfigList Zoraxy advertises (empty if no active key)
	Match       bool     // One published list is byte-identical to the expected one
	Stale       bool     // ECH is published but it is not the current list (rotation not yet in DNS, or a retired key)
	Advice      string
	AliasTarget string `json:",omitempty"` //Target of an AliasMode (priority 0) record, which this check does not follow
}

// Lookup resolves the HTTPS (type 65) records of host through the resolver ("host:port"; empty = system resolver or a public fallback)
func lookupHTTPS(ctx context.Context, host, resolver string) ([]*dns.HTTPS, string, error) {
	if resolver == "" {
		if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cc.Servers) > 0 {
			resolver = net.JoinHostPort(cc.Servers[0], cc.Port)
		} else {
			resolver = "1.1.1.1:53"
		}
	} else if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)
	msg.RecursionDesired = true
	c := &dns.Client{Timeout: 4 * time.Second}
	in, _, err := c.ExchangeContext(ctx, msg, resolver)
	if err != nil {
		return nil, resolver, err
	}
	if in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, msg, resolver)
		if err != nil {
			return nil, resolver, err
		}
	}
	var out []*dns.HTTPS
	for _, rr := range in.Answer {
		if h, ok := rr.(*dns.HTTPS); ok {
			out = append(out, h)
		}
	}
	return out, resolver, nil
}

// CheckDNS looks up the HTTPS record of host and compares its ech= parameter to the expected ECHConfigList (base64)
func CheckDNS(ctx context.Context, host, resolver, expected string) (*DNSCheckResult, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /:@*") {
		return nil, errors.New("invalid host name")
	}
	if resolver != "" {
		h := resolver
		if hh, _, err := net.SplitHostPort(resolver); err == nil {
			h = hh
		}
		if net.ParseIP(h) == nil {
			return nil, errors.New("resolver must be an IP address (optionally ip:port)")
		}
	}
	rrs, used, err := lookupHTTPS(ctx, host, resolver)
	if err != nil {
		return nil, err
	}
	return analyse(host, used, rrs, expected), nil
}

func analyse(host, resolver string, rrs []*dns.HTTPS, expected string) *DNSCheckResult {
	res := &DNSCheckResult{Host: host, Resolver: resolver, Expected: expected}
	for _, rr := range rrs {
		res.HasHTTPS = true
		if rr.Priority == 0 {
			res.AliasTarget = rr.Target
			continue
		}
		for _, kv := range rr.Value {
			if e, ok := kv.(*dns.SVCBECHConfig); ok {
				res.HasECH = true
				b64 := base64.StdEncoding.EncodeToString(e.ECH)
				res.Published = append(res.Published, b64)
				if expected != "" && b64 == expected {
					res.Match = true
				}
			}
		}
	}
	switch {
	case !res.HasHTTPS:
		res.Advice = "No HTTPS record found. Browsers only try ECH when an HTTPS record with an ech= parameter exists."
	case res.AliasTarget != "" && !res.HasECH:
		res.Advice = "The HTTPS record is an alias (priority 0) to " + res.AliasTarget + "; check that name instead."
	case !res.HasECH:
		res.Advice = "An HTTPS record exists but has no ech= parameter. Add the ECHConfigList shown above."
	case expected == "":
		res.Advice = "DNS publishes ECH but Zoraxy has no active key. Generate a key first."
	case res.Match:
		res.Advice = "DNS matches the current ECHConfigList."
	default:
		res.Stale = true
		res.Advice = "DNS publishes a different ECHConfigList than the active key. After a rotation this is expected until you update the record (the retired key keeps decrypting meanwhile)."
	}
	return res
}
