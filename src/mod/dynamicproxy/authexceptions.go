package dynamicproxy

import (
	"errors"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/pathmatch"
)

/*
	authexceptions.go

	Exception rules of the Forward Auth and OAuth2 providers (upstream #652).

	A request that matches any rule skips the SSO check. Because a wrong match is an
	authentication bypass, matching is deliberately strict and fails closed:

	  - The client IP comes from Router.GetClientIPForEndpoint, i.e. the trusted-proxy
	    aware resolver. Forwarding headers are never read here.
	  - Paths are only compared when the request target is already in canonical form.
	    Anything that would be interpreted differently by a server that normalises the
	    path itself (dot segments, "//", encoded slashes that decode into them, a
	    backslash, a ';' path parameter such as "/public/..;/admin", percent signs left
	    after one round of decoding i.e. double encoding, control characters) is NOT
	    exempted, the SSO check simply runs.
	  - Prefix rules match on segment boundaries ("/public" does not match "/publicfoo").
	  - Regex rules must match the whole normalised path (they are wrapped in ^(?:...)$),
	    Go's RE2 engine guarantees linear time.
	  - Matching is case sensitive unless the rule opts out.
*/

const (
	AuthExceptionMatchPrefix = "prefix"
	AuthExceptionMatchExact  = "exact"
	AuthExceptionMatchRegex  = "regex"

	maxExceptionPatternLen = 512
)

var (
	exceptionRegexCache sync.Map // key: caseInsensitive+pattern -> *regexp.Regexp (nil = invalid)
)

// canonicalExceptionPath: see pathmatch.CanonicalPath
func canonicalExceptionPath(target string) (string, bool) { return pathmatch.CanonicalPath(target) }

func exceptionRegex(pattern string, fold bool) *regexp.Regexp {
	key := "s:" + pattern
	if fold {
		key = "i:" + pattern
	}
	if v, ok := exceptionRegexCache.Load(key); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	expr := "^(?:" + pattern + ")$"
	if fold {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		re = nil
	}
	exceptionRegexCache.Store(key, re)
	return re
}

func parseExceptionIP(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

func exceptionCIDRContains(rule string, ip netip.Addr) bool {
	rule = strings.TrimSpace(rule)
	if strings.Contains(rule, "/") {
		p, err := netip.ParsePrefix(rule)
		if err != nil {
			return false
		}
		a := p.Addr().Unmap()
		bits := p.Bits()
		if p.Addr().Is4In6() {
			bits -= 96
			if bits < 0 {
				return false
			}
		}
		pp, err := a.Prefix(bits)
		return err == nil && pp.Contains(ip)
	}
	a, ok := parseExceptionIP(rule)
	return ok && a == ip
}

// AuthExceptionMatched reports whether the request is exempt from SSO by one of the
// rules. clientIP must come from the trusted-proxy aware resolver.
func AuthExceptionMatched(rules []*AuthExceptionRule, r *http.Request, clientIP string) bool {
	if len(rules) == 0 || r == nil {
		return false
	}
	reqPath, pathOK := canonicalExceptionPath(pathmatch.RequestTarget(r))
	ip, ipOK := parseExceptionIP(clientIP)
	lowerPath := strings.ToLower(reqPath)

	for _, rule := range rules {
		if rule == nil {
			continue
		}
		switch rule.RuleType {
		case AuthExceptionType_Paths:
			if !pathOK {
				continue
			}
			pat := strings.TrimSpace(rule.PathPattern)
			if pat == "" {
				continue
			}
			candidate := reqPath
			if rule.CaseInsensitive {
				candidate = lowerPath
			}
			switch rule.MatchMode {
			case AuthExceptionMatchRegex:
				if re := exceptionRegex(pat, rule.CaseInsensitive); re != nil && re.MatchString(reqPath) {
					return true
				}
			case AuthExceptionMatchExact:
				want := path.Clean("/" + pat)
				if rule.CaseInsensitive {
					want = strings.ToLower(want)
				}
				if candidate == want {
					return true
				}
			default: //prefix
				want := path.Clean("/" + pat)
				if want == "/" {
					continue //never exempt the whole site by path, validation refuses it too
				}
				if rule.CaseInsensitive {
					want = strings.ToLower(want)
				}
				if candidate == want || strings.HasPrefix(candidate, want+"/") {
					return true
				}
			}
		case AuthExceptionType_CIDR:
			if ipOK && exceptionCIDRContains(rule.CIDR, ip) {
				return true
			}
		}
	}
	return false
}

// ValidateAuthExceptionRule checks and normalises a rule before it is stored
func ValidateAuthExceptionRule(rule *AuthExceptionRule) error {
	if rule == nil {
		return errors.New("empty rule")
	}
	switch rule.RuleType {
	case AuthExceptionType_CIDR:
		c := strings.TrimSpace(rule.CIDR)
		if c == "" {
			return errors.New("IP / CIDR is empty")
		}
		if strings.Contains(c, "/") {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return errors.New("invalid CIDR")
			}
			if p.Bits() == 0 {
				return errors.New("refusing a /0 CIDR: it would exempt every client")
			}
			rule.CIDR = p.Masked().String()
		} else {
			a, ok := parseExceptionIP(c)
			if !ok {
				return errors.New("invalid IP address (wildcards are not supported, use a CIDR)")
			}
			rule.CIDR = a.String()
		}
		rule.MatchMode, rule.PathPattern, rule.CaseInsensitive = "", "", false
		return nil
	case AuthExceptionType_Paths:
		pat := strings.TrimSpace(rule.PathPattern)
		if pat == "" || len(pat) > maxExceptionPatternLen {
			return errors.New("path pattern is empty or too long")
		}
		switch rule.MatchMode {
		case "", AuthExceptionMatchPrefix, AuthExceptionMatchExact:
			if rule.MatchMode == "" {
				rule.MatchMode = AuthExceptionMatchPrefix
			}
			if !strings.HasPrefix(pat, "/") {
				return errors.New("path must start with /")
			}
			for _, bad := range []string{"..", "//", "\\", ";", "%", "?", "#", "*"} {
				if strings.Contains(pat, bad) {
					return errors.New("path must be a plain absolute path (no '" + bad + "'); use the regex mode for patterns")
				}
			}
			for i := 0; i < len(pat); i++ {
				if pat[i] < 0x20 || pat[i] == 0x7f {
					return errors.New("path contains control characters")
				}
			}
			if rule.MatchMode == AuthExceptionMatchPrefix && path.Clean(pat) == "/" {
				return errors.New("refusing the prefix / : it would exempt the whole site")
			}
			if len(pat) > 1 {
				pat = strings.TrimSuffix(pat, "/")
			}
		case AuthExceptionMatchRegex:
			if _, err := regexp.Compile("^(?:" + pat + ")$"); err != nil {
				return errors.New("invalid regular expression: " + err.Error())
			}
		default:
			return errors.New("unknown match mode")
		}
		rule.PathPattern = pat
		rule.CIDR = ""
		return nil
	}
	return errors.New("unknown rule type")
}

// externalAuthExempt reports whether the request bypasses Forward Auth / OAuth2 for this endpoint
func (router *Router) externalAuthExempt(sep *ProxyEndpoint, r *http.Request) bool {
	if sep == nil || sep.AuthenticationProvider == nil || len(sep.AuthenticationProvider.ExternalAuthExceptionRules) == 0 || pathForcesAuth(r) {
		return false
	}
	return AuthExceptionMatched(sep.AuthenticationProvider.ExternalAuthExceptionRules, r, router.GetClientIPForEndpoint(r, sep))
}
