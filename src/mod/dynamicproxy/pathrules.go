package dynamicproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/metrics"
	"imuslab.com/zoraxy/mod/pathmatch"
)

/*
	pathrules.go

	Path scoped access control and rate limiting per proxy endpoint (upstream #238 / #726).

	ProxyEndpoint.PathRules is an ordered list. The first rule whose path, method and scope
	all match decides:

	  allow         stop evaluating path rules, the request continues down the chain
	                (it does NOT bypass other protections such as WAF, auth or rate limits)
	  deny          403
	  rate_limit    token bucket per (endpoint, rule, client IP or key): RateLimit req/s (or req/min with RateUnit), RateBurst burst, 429 when empty
	  require_auth  the endpoint's authentication provider is enforced for this path even when an SSO
	                exception rule would skip it. If the endpoint has no provider the request is refused (fail closed)

	Matching is done on a normalised path. A request target can be read differently by the proxy and the
	upstream (//, /./, %2e, %2f, double encoding, ;params, backslashes, NUL), so:

	  - deny / rate_limit / require_auth match if ANY plausible reading of the path matches the rule
	    (decoded 1..4 times, ';' parameters stripped, '\' read as '/', truncated at NUL, dot segments resolved).
	  - allow only matches when the request target is already canonical, so an allow rule can never be
	    abused with a crafted path.

	Scope (optional): CIDRs / Countries limit who the rule applies to. ScopeInvert applies it to everybody
	except them (e.g. deny /admin for everyone outside 10.0.0.0/8). The client IP is the trusted-proxy aware
	address from GetClientIPForEndpoint, forwarded headers are never trusted here.

	The method override headers (X-HTTP-Method-Override) are not interpreted; the real HTTP method is matched.
*/

const (
	PathRuleAllow       = "allow"
	PathRuleDeny        = "deny"
	PathRuleRequireAuth = "require_auth"
	PathRuleRateLimit   = "rate_limit"

	PathRuleMatchPrefix = "prefix"
	PathRuleMatchExact  = "exact"
	PathRuleMatchRegex  = "regex"

	maxPathRules          = 200
	maxPathRulePatternLen = 512
	maxPathDecodeRounds   = 4
)

// PathRule is one entry of ProxyEndpoint.PathRules
type PathRule struct {
	Name            string   //Free text label
	MatchMode       string   //"prefix" (default, segment boundary), "exact" or "regex" (full match of the normalised path)
	Pattern         string   //Path (starts with /) or regular expression
	CaseInsensitive bool     //Compare without regard to letter case
	Methods         []string //Empty = every method
	Action          string   //allow, deny, require_auth, rate_limit
	RateLimit       int64    //rate_limit: requests per second per client IP
	RateBurst       int64    //rate_limit: burst size, 0 = same as RateLimit
	RateUnit        string   `json:",omitempty"` //rate_limit: what RateLimit is per, "" = second (default), "minute"
	KeyBy           string   `json:",omitempty"` //rate_limit: "" = client address (default), "authorization" or "header" (hashed, falls back to the address)
	KeyHeader       string   `json:",omitempty"` //rate_limit: header name when KeyBy is "header"
	CIDRs           []string //Optional scope: IP addresses or CIDR blocks
	Countries       []string //Optional scope: ISO 3166 alpha-2 country codes
	ScopeInvert     bool     //Apply the rule to everybody NOT in the scope
}

type compiledPathRule struct {
	PathRule
	re        *regexp.Regexp
	pattern   string //cleaned (and lower cased if case insensitive) prefix / exact path
	methods   map[string]bool
	prefixes  []netip.Prefix
	countries map[string]bool
	hasScope  bool
	ratePerS  float64 //rate_limit: tokens per second (RateLimit in RateUnit)
	rateBurst float64 //rate_limit: bucket size in requests
}

type pathForceAuthKey struct{}

// pathForcesAuth reports whether a path rule demanded authentication for this request
func pathForcesAuth(r *http.Request) bool {
	v, _ := r.Context().Value(pathForceAuthKey{}).(bool)
	return v
}

func parseScopePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		bits := p.Bits()
		if p.Addr().Is4In6() {
			bits -= 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
			}
		}
		pp, err := p.Addr().Unmap().Prefix(bits)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		return pp, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address %q", s)
	}
	a = a.WithZone("").Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

var httpMethodToken = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,15}$`)

func compilePathRule(rule *PathRule) (*compiledPathRule, error) {
	if rule == nil {
		return nil, errors.New("empty rule")
	}
	c := &compiledPathRule{PathRule: *rule}
	c.Pattern = strings.TrimSpace(c.Pattern)
	if c.Pattern == "" {
		return nil, errors.New("path pattern is empty")
	}
	if len(c.Pattern) > maxPathRulePatternLen {
		return nil, errors.New("path pattern is too long")
	}
	switch c.MatchMode {
	case "", PathRuleMatchPrefix, PathRuleMatchExact:
		if !strings.HasPrefix(c.Pattern, "/") {
			return nil, errors.New("path must start with /")
		}
		cp := path.Clean(c.Pattern)
		if c.CaseInsensitive {
			cp = strings.ToLower(cp)
		}
		c.pattern = cp
		if c.MatchMode == "" {
			c.MatchMode = PathRuleMatchPrefix
		}
	case PathRuleMatchRegex:
		expr := "^(?:" + c.Pattern + ")$"
		if c.CaseInsensitive {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid regular expression: %w", err)
		}
		c.re = re
	default:
		return nil, fmt.Errorf("unknown match mode %q", c.MatchMode)
	}

	switch c.Action {
	case PathRuleAllow, PathRuleDeny, PathRuleRequireAuth:
	case PathRuleRateLimit:
		if c.RateLimit <= 0 {
			return nil, errors.New("rate_limit needs a rate greater than 0")
		}
		if c.RateBurst < 0 {
			return nil, errors.New("burst cannot be negative")
		}
		if c.RateLimit > maxProxyRateLimitPerUnit {
			return nil, errors.New("rate is too large")
		}
		unit, err := NormalizeRateUnit(c.RateUnit)
		if err != nil {
			return nil, err
		}
		c.RateUnit = unit
		if err := ValidateKeying(c.KeyBy, c.KeyHeader); err != nil {
			return nil, err
		}
		c.KeyBy, _ = normalizeKeyBy(c.KeyBy)
		if c.KeyBy == RateKeyHeader {
			c.KeyHeader = http.CanonicalHeaderKey(c.KeyHeader)
		}
		c.ratePerS = RatePerSecond(c.RateLimit, c.RateUnit)
		c.rateBurst = rateBurstTokens(c.RateLimit, c.RateBurst)
	default:
		return nil, fmt.Errorf("unknown action %q", c.Action)
	}

	if len(c.Methods) > 0 {
		c.methods = map[string]bool{}
		for _, m := range c.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m == "" {
				continue
			}
			if !httpMethodToken.MatchString(m) {
				return nil, fmt.Errorf("invalid HTTP method %q", m)
			}
			c.methods[m] = true
		}
	}
	for _, s := range c.CIDRs {
		if strings.TrimSpace(s) == "" {
			continue
		}
		p, err := parseScopePrefix(s)
		if err != nil {
			return nil, err
		}
		c.prefixes = append(c.prefixes, p)
	}
	if len(c.Countries) > 0 {
		c.countries = map[string]bool{}
		for _, cc := range c.Countries {
			cc = strings.ToUpper(strings.TrimSpace(cc))
			if cc == "" {
				continue
			}
			if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
				return nil, fmt.Errorf("invalid country code %q", cc)
			}
			c.countries[cc] = true
		}
	}
	c.hasScope = len(c.prefixes) > 0 || len(c.countries) > 0
	if c.ScopeInvert && !c.hasScope {
		return nil, errors.New("'everyone except' needs at least one CIDR or country")
	}
	return c, nil
}

// ValidatePathRules checks a rule list before it is stored
func ValidatePathRules(rules []*PathRule) error {
	if len(rules) > maxPathRules {
		return fmt.Errorf("too many rules (max %d)", maxPathRules)
	}
	for i, r := range rules {
		if _, err := compilePathRule(r); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

func (pe *ProxyEndpoint) initPathRules() {
	pe.pathRules = nil
	pe.pathRulesErr = nil
	if len(pe.PathRules) == 0 {
		return
	}
	if len(pe.PathRules) > maxPathRules {
		pe.pathRulesErr = errors.New("too many path rules")
		return
	}
	out := make([]*compiledPathRule, 0, len(pe.PathRules))
	for i, r := range pe.PathRules {
		c, err := compilePathRule(r)
		if err != nil {
			pe.pathRulesErr = fmt.Errorf("path rule %d: %w", i+1, err)
			return
		}
		out = append(out, c)
	}
	pe.pathRules = out
}

/* Path normalisation */

func stripPathParams(p string) string {
	if !strings.Contains(p, ";") {
		return p
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if j := strings.IndexByte(s, ';'); j >= 0 {
			segs[i] = s[:j]
		}
	}
	return strings.Join(segs, "/")
}

func cleanReading(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.IndexByte(p, 0); i >= 0 {
		p = p[:i]
	}
	p = stripPathParams(p)
	return path.Clean("/" + p)
}

// pathReadings returns every plausible reading of the request path (lower cased when fold is
// set) and whether the target is already canonical.
func pathReadings(target string, fold bool) (readings []string, canonical bool) {
	_, canonical = canonicalExceptionPath(target)

	raw := target
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	//Absolute-form targets (GET http://host/path)
	if u, err := url.ParseRequestURI(target); err == nil && u.Host != "" {
		raw = u.EscapedPath()
	}
	seen := map[string]bool{}
	add := func(p string) {
		p = cleanReading(p)
		if fold {
			p = strings.ToLower(p)
		}
		if !seen[p] {
			seen[p] = true
			readings = append(readings, p)
		}
	}
	//The literal text (a backend that does not decode) and the shared one-round reading
	add(raw)
	add(pathmatch.CleanRequestPath(target))
	cur := raw
	for i := 0; i < maxPathDecodeRounds; i++ {
		next, err := url.PathUnescape(cur)
		if err != nil {
			//Undecodable percent sequence: decode what can be decoded
			next = lenientUnescape(cur)
		}
		if next == cur {
			break
		}
		cur = next
		add(cur)
	}
	return readings, canonical
}

// lenientUnescape decodes valid %XX sequences and leaves invalid ones alone
func lenientUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (c *compiledPathRule) matchPath(p string) bool {
	switch c.MatchMode {
	case PathRuleMatchRegex:
		return c.re.MatchString(p)
	case PathRuleMatchExact:
		return p == c.pattern
	default:
		if c.pattern == "/" {
			return true
		}
		return p == c.pattern || strings.HasPrefix(p, c.pattern+"/")
	}
}

func (c *compiledPathRule) matchesRequest(target string, method string) bool {
	if c.methods != nil && !c.methods[strings.ToUpper(method)] {
		return false
	}
	readings, canonical := pathReadings(target, c.CaseInsensitive)
	if c.Action == PathRuleAllow {
		//Only a canonical request target may trigger an allow
		return canonical && len(readings) > 0 && c.matchPath(readings[0])
	}
	for _, p := range readings {
		if c.matchPath(p) {
			return true
		}
	}
	return false
}

func (c *compiledPathRule) inScope(router *Router, ip string) bool {
	if !c.hasScope {
		return true
	}
	in := false
	if a, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
		a = a.WithZone("").Unmap()
		for _, p := range c.prefixes {
			if p.Contains(a) {
				in = true
				break
			}
		}
	}
	if !in && len(c.countries) > 0 && router != nil && router.Option != nil && router.Option.GeodbStore != nil && ip != "" {
		if info, err := router.Option.GeodbStore.ResolveCountryCodeFromIP(ip); err == nil && info != nil && c.countries[strings.ToUpper(info.CountryIsoCode)] {
			in = true
		}
	}
	return in != c.ScopeInvert
}

// handlePathRules evaluates the endpoint's path rules. Returns true when the request was answered.
func (h *ProxyHandler) handlePathRules(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if sep.pathRulesErr != nil {
		h.Parent.Option.Logger.PrintAndLog("proxy-pathrule", "Path rules of "+sep.RootOrMatchingDomain+" are invalid, refusing requests", sep.pathRulesErr)
		http.Error(w, "503 - Path rules misconfigured", http.StatusServiceUnavailable)
		return true
	}
	if len(sep.pathRules) == 0 {
		return false
	}
	target := pathmatch.RequestTarget(r)
	ip := ""
	for i, rule := range sep.pathRules {
		if !rule.matchesRequest(target, r.Method) {
			continue
		}
		if rule.hasScope && ip == "" {
			ip = h.Parent.GetClientIPForEndpoint(r, sep)
		}
		if !rule.inScope(h.Parent, ip) {
			continue
		}
		switch rule.Action {
		case PathRuleAllow:
			return false
		case PathRuleDeny:
			h.Parent.logRequest(r, false, 403, "path-rule-deny", r.Host, "", sep)
			serveProxyRequestError(w, r, http.StatusForbidden, h.Parent, ErrorTemplateForbidden)
			return true
		case PathRuleRequireAuth:
			if sep.AuthenticationProvider == nil || sep.AuthenticationProvider.AuthMethod == AuthMethodNone {
				h.Parent.logRequest(r, false, 403, "path-rule-noauth", r.Host, "", sep)
				serveProxyRequestError(w, r, http.StatusForbidden, h.Parent, ErrorTemplateForbidden)
				return true
			}
			*r = *r.WithContext(context.WithValue(r.Context(), pathForceAuthKey{}, true))
			return false
		case PathRuleRateLimit:
			if ip == "" {
				ip = h.Parent.GetClientIPForEndpoint(r, sep)
			}
			if ip == "" {
				return false
			}
			if sep.rateOpts != nil && sep.rateExempt(r, ip) {
				return false //trusted monitoring, see ratelimit_policy.go
			}
			key := "path|" + sep.RootOrMatchingDomain + "|" + strconv.Itoa(i)
			if sep.rateSkipsWebSocket(r) {
				//WebSocket handshake: not counted in the rule's bucket, but a much larger guard bucket still applies
				if !h.Parent.rateLimitCounter.wsExemptAllow(key, ip, rule.ratePerS, rule.rateBurst) {
					h.Parent.Option.Metrics.Event(metrics.EventRateLimited, sep.RootOrMatchingDomain, "path")
					h.Parent.logRequest(r, false, 429, "path-rule-ratelimit", r.Host, "", sep)
					w.Header().Set("Retry-After", "5")
					w.WriteHeader(http.StatusTooManyRequests)
					return true
				}
				return false
			}
			if !h.Parent.rateLimitCounter.rateAllow(r, key, ip, rule.KeyBy, rule.KeyHeader, rule.ratePerS, rule.rateBurst) {
				h.Parent.Option.Metrics.Event(metrics.EventRateLimited, sep.RootOrMatchingDomain, "path")
				h.Parent.logRequest(r, false, 429, "path-rule-ratelimit", r.Host, "", sep)
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(rule.ratePerS)))
				w.WriteHeader(http.StatusTooManyRequests)
				return true
			}
			return false
		}
	}
	return false
}
