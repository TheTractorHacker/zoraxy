package utils

import (
	"strings"

	"golang.org/x/net/idna"
)

/*
	Internationalised domain names (IDN, upstream #458)

	Browsers and TLS clients always put the ASCII (punycode, "xn--") form of a host name on the wire (Host header,
	SNI, ACME identifiers, DNS record names), while users type the Unicode form into the UI. Every place that
	compares or stores a host name has to normalise both sides to the same representation, otherwise the rule
	"bücher.example" never matches a request for "xn--bcher-kva.example". The canonical form is lower case ASCII
	without trailing dot.
*/

// NormalizeHostname returns the canonical ASCII (punycode) form of a host name or domain pattern.
// Wildcard labels ("*", "?" patterns) are preserved. Input that cannot be converted is returned lower-cased
// and unchanged, so a bad value never turns into a different valid host name.
func NormalizeHostname(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" || isPlainASCII(host) && !strings.Contains(host, "xn--") {
		return host
	}
	labels := strings.Split(host, ".")
	for i, l := range labels {
		if l == "" || strings.ContainsAny(l, "*?[") {
			continue
		}
		if isPlainASCII(l) && !strings.HasPrefix(l, "xn--") {
			continue
		}
		a, err := idna.Lookup.ToASCII(l)
		if err != nil {
			return host
		}
		labels[i] = a
	}
	return strings.Join(labels, ".")
}

// DisplayHostname returns the Unicode form of a host name (xn-- labels decoded). It returns the input
// unchanged when it is not valid punycode.
func DisplayHostname(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if !strings.Contains(host, "xn--") {
		return host
	}
	u, err := idna.Lookup.ToUnicode(host)
	if err != nil {
		return host
	}
	return u
}

// NormalizeHostnames normalises every entry of a list, dropping duplicates and empty entries (order kept).
func NormalizeHostnames(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	seen := map[string]bool{}
	for _, h := range hosts {
		n := NormalizeHostname(h)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func isPlainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
