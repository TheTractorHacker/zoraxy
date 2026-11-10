package dynamicproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/metrics"
)

/*
	ratelimit_policy.go

	Per minute limits, keying, trusted monitoring exemption and WebSocket accounting for the rate limit of a
	proxy rule. Everything here is additive and OFF unless set:

	  - Unit. ProxyEndpoint.RateLimit / PathRule.RateLimit stay "a number of requests". The new RateUnit says
	    what the number is per: "" (the historic default) = per second, "minute" = per minute. A per minute
	    limit of N refills the same token bucket at N/60 tokens per second; the number is stored as typed, so
	    nothing is rounded and a saved config means exactly what it says. The default burst (RateLimitBurst 0)
	    is the number itself, i.e. 120 req/min allows 120 requests at once and then 2 per second.
	  - Key. By default the bucket is per client IP. KeyBy "authorization" or "header" (+ KeyHeader) keys it by
	    the SHA-256 of that request header instead (API key, bearer token), falling back to the IP when the
	    header is absent. The header value is only ever hashed in memory, never logged or stored. Because a
	    client can invent header values, a keyed limit also keeps a looser per IP guard (rateKeyedGuardFactor
	    times the limit) so rotating keys can not give unlimited throughput.
	  - Exempt. Requests from ExemptCIDRs (the trusted client address, never a forwarded header from an
	    untrusted peer), or that carry ExemptHeader with the secret ExemptHeaderValue, skip the limit.
	  - WebSocket. A WebSocket handshake is one HTTP request. Historically it was counted against the request
	    limit like any other. With WSExempt it is not counted; WSMaxConnsPerIP caps the concurrent WebSocket
	    connections per client address instead (0 = no cap). Frames inside an open WebSocket are not HTTP
	    requests and are never counted.

	The rules engine (mod/ruleset) rate_limit action is unchanged: it is per second and ignores these options.
*/

const (
	RateUnitSecond = ""       //historic default (stored as empty so old configs are unchanged)
	RateUnitMinute = "minute" //requests per minute

	RateKeyIP            = ""              //per client address (default); "ip" is accepted too
	RateKeyAuthorization = "authorization" //hash of the Authorization header
	RateKeyHeader        = "header"        //hash of the header named in KeyHeader

	//a keyed limit also enforces this multiple of the limit per client address
	rateKeyedGuardFactor = 10
	maxRateKeyValueLen   = 8192
	maxRateExemptCIDRs   = 100
	maxWSConnsPerIP      = 100000
)

// RateLimitOptions are the optional extras of a proxy rule's rate limit (ProxyEndpoint.RateOptions)
type RateLimitOptions struct {
	KeyBy             string   `json:",omitempty"` //"" / "ip", "authorization" or "header"
	KeyHeader         string   `json:",omitempty"` //header name when KeyBy is "header"
	ExemptCIDRs       []string `json:",omitempty"` //trusted monitoring: client addresses / CIDRs that skip the limit
	ExemptHeader      string   `json:",omitempty"` //optional: a request carrying this header with ExemptHeaderValue skips the limit
	ExemptHeaderValue string   `json:",omitempty"` //the shared secret value for ExemptHeader (never logged)
	WSExempt          bool     `json:",omitempty"` //WebSocket handshakes are not counted against the request limit
	WSMaxConnsPerIP   int64    `json:",omitempty"` //max concurrent WebSocket connections per client address, 0 = no cap
}

// IsZero reports whether no option is set
func (o *RateLimitOptions) IsZero() bool {
	return o == nil || (o.KeyBy == "" && o.KeyHeader == "" && len(o.ExemptCIDRs) == 0 && o.ExemptHeader == "" &&
		o.ExemptHeaderValue == "" && !o.WSExempt && o.WSMaxConnsPerIP == 0)
}

// NormalizeRateUnit maps the accepted spellings to RateUnitSecond or RateUnitMinute
func NormalizeRateUnit(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "s", "sec", "second", "seconds", "per_second":
		return RateUnitSecond, nil
	case "m", "min", "minute", "minutes", "per_minute":
		return RateUnitMinute, nil
	}
	return "", errors.New("rate unit must be second or minute")
}

// RatePerSecond converts a limit in the given unit to tokens per second
func RatePerSecond(limit int64, unit string) float64 {
	if unit == RateUnitMinute {
		return float64(limit) / 60
	}
	return float64(limit)
}

// FormatRate renders "120 req/min" / "5 req/s"
func FormatRate(limit int64, unit string) string {
	if unit == RateUnitMinute {
		return fmt.Sprintf("%d req/min", limit)
	}
	return fmt.Sprintf("%d req/s", limit)
}

// rateBurstTokens is the bucket size: the burst, or the limit number itself when the burst is 0
func rateBurstTokens(limit, burst int64) float64 {
	if burst <= 0 {
		return float64(limit)
	}
	return float64(burst)
}

func normalizeKeyBy(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "ip":
		return RateKeyIP, nil
	case RateKeyAuthorization:
		return RateKeyAuthorization, nil
	case RateKeyHeader:
		return RateKeyHeader, nil
	}
	return "", errors.New("key must be ip, authorization or header")
}

func validateKeyHeader(name string) error {
	if !headerNameRe.MatchString(name) {
		return fmt.Errorf("invalid header name %q", name)
	}
	switch strings.ToLower(name) {
	case "host", "connection", "upgrade", "content-length", "transfer-encoding", "cookie":
		return fmt.Errorf("header %q can not be used", name)
	}
	return nil
}

// ValidateKeying checks a KeyBy / KeyHeader pair
func ValidateKeying(keyBy, keyHeader string) error {
	k, err := normalizeKeyBy(keyBy)
	if err != nil {
		return err
	}
	if k == RateKeyHeader {
		if keyHeader == "" {
			return errors.New("a header name is required to key the limit by a header")
		}
		return validateKeyHeader(keyHeader)
	}
	if keyHeader != "" && k != RateKeyHeader {
		return errors.New("a key header is only used when the key is a header")
	}
	return nil
}

// Validate checks the options. It does not modify them; see Normalised.
func (o *RateLimitOptions) Validate() error {
	if o == nil {
		return nil
	}
	if err := ValidateKeying(o.KeyBy, o.KeyHeader); err != nil {
		return err
	}
	if len(o.ExemptCIDRs) > maxRateExemptCIDRs {
		return fmt.Errorf("too many exempt addresses (max %d)", maxRateExemptCIDRs)
	}
	for _, c := range o.ExemptCIDRs {
		if strings.TrimSpace(c) == "" {
			continue
		}
		if _, err := parseScopePrefix(c); err != nil {
			return err
		}
	}
	if (o.ExemptHeader == "") != (o.ExemptHeaderValue == "") {
		return errors.New("the exempt header needs both a name and a secret value")
	}
	if o.ExemptHeader != "" {
		if err := validateKeyHeader(o.ExemptHeader); err != nil {
			return err
		}
		if len(o.ExemptHeaderValue) < 8 || len(o.ExemptHeaderValue) > 256 || hasControl(o.ExemptHeaderValue) {
			return errors.New("the exempt header value must be 8-256 printable characters (it is a shared secret)")
		}
	}
	if o.WSMaxConnsPerIP < 0 || o.WSMaxConnsPerIP > maxWSConnsPerIP {
		return fmt.Errorf("WebSocket connection cap must be between 0 and %d", maxWSConnsPerIP)
	}
	if o.WSExempt && o.WSMaxConnsPerIP <= 0 {
		return errors.New("WebSocket handshakes can only skip the request limit together with a connection cap")
	}
	return nil
}

// Normalised returns a cleaned copy (nil when nothing is set): key spellings canonical, lists trimmed
func (o *RateLimitOptions) Normalised() *RateLimitOptions {
	if o == nil {
		return nil
	}
	n := *o
	n.KeyBy, _ = normalizeKeyBy(n.KeyBy)
	n.ExemptCIDRs = nil
	for _, c := range o.ExemptCIDRs {
		if c = strings.TrimSpace(c); c != "" {
			n.ExemptCIDRs = append(n.ExemptCIDRs, c)
		}
	}
	if n.IsZero() {
		return nil
	}
	return &n
}

// ValidateRateLimitSetting checks a site wide limit (number in unit, burst in requests)
func ValidateRateLimitSetting(enabled bool, limit int64, unit string, burst int64) error {
	if _, err := NormalizeRateUnit(unit); err != nil {
		return err
	}
	if enabled && limit <= 0 {
		return errors.New("rate limit number must be greater than 0")
	}
	if limit < 0 || limit > maxProxyRateLimitPerUnit {
		return fmt.Errorf("rate limit number is too large (%d at most)", maxProxyRateLimitPerUnit)
	}
	if burst < 0 {
		return errors.New("invalid rate limit burst, must be a number >= 0")
	}
	return nil
}

const maxProxyRateLimitPerUnit = 1000000

/* ---- compiled runtime form ---- */

type compiledRateOptions struct {
	RateLimitOptions
	exemptPrefixes []netip.Prefix
	keyHeaderName  string //canonical
	exemptName     string //canonical
}

func (pe *ProxyEndpoint) initRateOptions() {
	pe.rateOpts = nil
	o := pe.RateOptions.Normalised()
	if o == nil {
		return
	}
	c := &compiledRateOptions{RateLimitOptions: *o}
	for _, cidr := range o.ExemptCIDRs {
		if p, err := parseScopePrefix(cidr); err == nil { //a broken entry exempts nobody (fail closed)
			c.exemptPrefixes = append(c.exemptPrefixes, p)
		}
	}
	if o.KeyBy == RateKeyHeader && validateKeyHeader(o.KeyHeader) == nil {
		c.keyHeaderName = http.CanonicalHeaderKey(o.KeyHeader)
	}
	if o.ExemptHeader != "" && validateKeyHeader(o.ExemptHeader) == nil {
		c.exemptName = http.CanonicalHeaderKey(o.ExemptHeader)
	}
	pe.rateOpts = c
}

// rateExempt reports whether the request is trusted monitoring and skips every rate limit of the rule.
// ip is the trusted client address (GetClientIPForEndpoint).
func (pe *ProxyEndpoint) rateExempt(r *http.Request, ip string) bool {
	c := pe.rateOpts
	if c == nil {
		return false
	}
	if len(c.exemptPrefixes) > 0 && ip != "" {
		if a, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
			a = a.WithZone("").Unmap()
			for _, p := range c.exemptPrefixes {
				if p.Contains(a) {
					return true
				}
			}
		}
	}
	if c.exemptName != "" && c.ExemptHeaderValue != "" {
		for _, v := range r.Header.Values(c.exemptName) {
			if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(v)), []byte(c.ExemptHeaderValue)) == 1 {
				return true
			}
		}
	}
	return false
}

// rateSkipsWebSocket reports whether this request is a WebSocket handshake the rule does not count.
// A rule that blocks WebSockets answers the handshake itself, so nothing is exempted there.
func (pe *ProxyEndpoint) rateSkipsWebSocket(r *http.Request) bool {
	return pe.rateOpts != nil && pe.rateOpts.WSExempt && !pe.DisableWebSocket && isWebSocketHandshake(r)
}

// wsExemptGuardFactor: exempt handshakes are not free. They draw from a separate bucket this many times
// larger than the rule's own, so reconnect storms pass but a flood of (possibly forged) handshakes cannot
// reach the upstream without limit.
const wsExemptGuardFactor = 20

// wsExemptAllow counts an exempt handshake against the guard bucket of the rule
func (t *RequestCountPerIpTable) wsExemptAllow(id, ip string, ratePerSec, burst float64) bool {
	return t.AllowRate(id+"|wsguard", ip, ratePerSec*wsExemptGuardFactor, burst*wsExemptGuardFactor)
}

// rateKeyFor returns the bucket key of the request. keyed is false when the client address is used
// (the default, or the header is missing / oversized: the safe fallback).
func rateKeyFor(r *http.Request, keyBy, headerName, ip string) (key string, keyed bool) {
	var v string
	switch keyBy {
	case RateKeyAuthorization:
		v = r.Header.Get("Authorization")
	case RateKeyHeader:
		if headerName != "" {
			v = r.Header.Get(headerName)
		}
	default:
		return ip, false
	}
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxRateKeyValueLen {
		return ip, false
	}
	sum := sha256.Sum256([]byte(v))
	return "h:" + hex.EncodeToString(sum[:16]), true
}

// rateAllow takes one token for the request from bucket id, keyed per the options. A keyed bucket
// is accompanied by the per client address guard so that inventing keys does not escape the limit.
func (t *RequestCountPerIpTable) rateAllow(r *http.Request, id, ip, keyBy, keyHeader string, ratePerSec, burst float64) bool {
	key, keyed := rateKeyFor(r, keyBy, keyHeader, ip)
	if !keyed {
		return t.AllowRate(id, ip, ratePerSec, burst)
	}
	if !t.AllowRate(id+"|ipguard", ip, ratePerSec*rateKeyedGuardFactor, burst*rateKeyedGuardFactor) {
		return false
	}
	return t.AllowRate(id, key, ratePerSec, burst)
}

// retryAfterSeconds is the time until one token is back, at least 1 second
func retryAfterSeconds(ratePerSec float64) int {
	if ratePerSec <= 0 {
		return 60
	}
	s := int(math.Ceil(1 / ratePerSec))
	if s < 1 {
		s = 1
	}
	if s > 3600 {
		s = 3600
	}
	return s
}

/* ---- WebSocket connection accounting ---- */

// wsConnTable counts the open WebSocket connections per (endpoint, client address). Zero value ready.
type wsConnTable struct {
	mu sync.Mutex
	n  map[string]int64
}

// acquire reserves a slot; false when the client already has max connections open
func (t *wsConnTable) acquire(key string, max int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.n == nil {
		t.n = map[string]int64{}
	}
	if t.n[key] >= max {
		return false
	}
	t.n[key]++
	return true
}

func (t *wsConnTable) release(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.n[key] <= 1 {
		delete(t.n, key)
		return
	}
	t.n[key]--
}

func (t *wsConnTable) count(key string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n[key]
}

// Len is the number of (endpoint, client) pairs with an open connection
func (t *wsConnTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.n)
}

// wsAcquire enforces WSMaxConnsPerIP for a WebSocket handshake that is about to be proxied. The returned
// release must be called when the connection ends. ok is false when the request was refused (429 written).
func (h *ProxyHandler) wsAcquire(w http.ResponseWriter, r *http.Request, pe *ProxyEndpoint) (release func(), ok bool) {
	noop := func() {}
	c := pe.rateOpts
	if c == nil || c.WSMaxConnsPerIP <= 0 {
		return noop, true
	}
	ip := h.Parent.GetClientIPForEndpoint(r, pe)
	if ip == "" || pe.rateExempt(r, ip) {
		return noop, true
	}
	key := pe.RootOrMatchingDomain + "|" + ip
	if !h.Parent.wsConns.acquire(key, c.WSMaxConnsPerIP) {
		h.Parent.Option.Metrics.Event(metrics.EventRateLimited, pe.RootOrMatchingDomain, "wsconn")
		h.Parent.logRequestDetail(r, false, 429, "ws-connlimit", r.Host, "", pe, "limit "+strconv.FormatInt(c.WSMaxConnsPerIP, 10)+" concurrent WebSocket connections per client")
		w.Header().Set("Retry-After", "5")
		http.Error(w, "429 - Too many WebSocket connections", http.StatusTooManyRequests)
		return noop, false
	}
	var once sync.Once
	return func() { once.Do(func() { h.Parent.wsConns.release(key) }) }, true
}
