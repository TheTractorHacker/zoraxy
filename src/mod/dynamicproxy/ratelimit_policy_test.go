package dynamicproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

/* ---- unit conversion and limiter math ---- */

func TestRateUnitConversion(t *testing.T) {
	if RatePerSecond(120, RateUnitMinute) != 2 {
		t.Errorf("120 req/min must be 2 req/s")
	}
	if RatePerSecond(120, RateUnitSecond) != 120 {
		t.Errorf("per second must stay as is")
	}
	if got := RatePerSecond(5, RateUnitMinute); got < 0.0833 || got > 0.0834 {
		t.Errorf("5 req/min = %v", got)
	}
	for in, want := range map[string]string{"": "", "second": "", "S": "", "minute": "minute", "min": "minute", " Minute ": "minute"} {
		got, err := NormalizeRateUnit(in)
		if err != nil || got != want {
			t.Errorf("NormalizeRateUnit(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := NormalizeRateUnit("hour"); err == nil {
		t.Errorf("hour must be rejected")
	}
	if FormatRate(120, RateUnitMinute) != "120 req/min" || FormatRate(5, "") != "5 req/s" {
		t.Errorf("FormatRate: %q %q", FormatRate(120, RateUnitMinute), FormatRate(5, ""))
	}
	// the number is stored as typed: nothing is rounded, a huge or odd value survives a JSON round trip
	ep := &ProxyEndpoint{RequireRateLimit: true, RateLimit: 7, RateUnit: RateUnitMinute, RateLimitBurst: 3}
	js, _ := json.Marshal(ep)
	var back ProxyEndpoint
	if err := json.Unmarshal(js, &back); err != nil || back.RateLimit != 7 || back.RateUnit != "minute" || back.RateLimitBurst != 3 {
		t.Errorf("round trip lost data: %+v %v", &back, err)
	}
}

func TestTokenBucket_PerMinuteMath(t *testing.T) {
	l, now := newTestLimiter()
	rate, burst := RatePerSecond(5, RateUnitMinute), rateBurstTokens(5, 0)
	if burst != 5 {
		t.Fatalf("default burst is the number itself, got %v", burst)
	}
	for i := 0; i < 5; i++ {
		if !l.AllowRate("e", "1.1.1.1", rate, burst) {
			t.Fatalf("request %d within the burst must pass", i)
		}
	}
	if l.AllowRate("e", "1.1.1.1", rate, burst) {
		t.Fatal("6th immediate request must be limited")
	}
	*now = now.Add(11 * time.Second)
	if l.AllowRate("e", "1.1.1.1", rate, burst) {
		t.Fatal("5 req/min refills one token per 12 s, not 11")
	}
	*now = now.Add(2 * time.Second)
	if !l.AllowRate("e", "1.1.1.1", rate, burst) {
		t.Fatal("one token must be back after 13 s")
	}
	if l.AllowRate("e", "1.1.1.1", rate, burst) {
		t.Fatal("only one token was due")
	}
	*now = now.Add(time.Hour) //refill is capped at the burst
	passed := 0
	for i := 0; i < 20; i++ {
		if l.AllowRate("e", "1.1.1.1", rate, burst) {
			passed++
		}
	}
	if passed != 5 {
		t.Fatalf("refill must cap at the burst of 5, got %d", passed)
	}
}

// 60 req/min and 1 req/s are the same bucket math
func TestPerMinuteEqualsPerSecondEquivalent(t *testing.T) {
	a, nowA := newTestLimiter()
	b, nowB := newTestLimiter()
	for step := 0; step < 40; step++ {
		for i := 0; i < 3; i++ {
			ga := a.AllowRate("e", "ip", RatePerSecond(60, RateUnitMinute), 4)
			gb := b.Allow("e", "ip", 1, 4)
			if ga != gb {
				t.Fatalf("step %d: per minute %v, per second %v", step, ga, gb)
			}
		}
		*nowA = nowA.Add(900 * time.Millisecond)
		*nowB = nowB.Add(900 * time.Millisecond)
	}
}

func TestAllowKeepsOldSemantics(t *testing.T) {
	l, _ := newTestLimiter()
	if l.Allow("e", "ip", 0, 5) || l.Allow("e", "ip", -1, 0) {
		t.Error("a limit of 0 or less keeps blocking everything")
	}
	if l.AllowRate("e", "ip", 0, 5) || l.AllowRate("e", "ip", 1, 0) {
		t.Error("AllowRate needs a positive rate and burst")
	}
}

func TestHandleRateLimit_PerMinute(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RootOrMatchingDomain: "a.example.com", RequireRateLimit: true, RateLimit: 6, RateUnit: RateUnitMinute}
	pe.initRateOptions()
	passed := 0
	var last *httptest.ResponseRecorder
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		if router.handleRateLimit(w, newTestRequest("198.51.100.7:1234", nil), pe) == nil {
			passed++
		} else {
			last = w
		}
	}
	if passed != 6 {
		t.Fatalf("6 req/min allows a burst of 6, got %d", passed)
	}
	if last.Code != 429 || last.Header().Get("Retry-After") != "10" {
		t.Errorf("429 with Retry-After 10 expected, got %d %q", last.Code, last.Header().Get("Retry-After"))
	}
	// another client has its own budget
	if err := router.handleRateLimit(httptest.NewRecorder(), newTestRequest("198.51.100.8:1234", nil), pe); err != nil {
		t.Error("another client must not be limited")
	}
}

// Configs written before units, keying and options existed load and behave exactly as before.
func TestOldConfigsKeepMeaning(t *testing.T) {
	old := `{"RootOrMatchingDomain":"old.example.com","RequireRateLimit":true,"RateLimit":5,"RateLimitBurst":0,
	 "PathRules":[{"Pattern":"/login","Action":"rate_limit","RateLimit":2,"RateBurst":3}]}`
	ep := &ProxyEndpoint{}
	if err := json.Unmarshal([]byte(old), ep); err != nil {
		t.Fatal(err)
	}
	if ep.RateUnit != RateUnitSecond || ep.RateOptions != nil {
		t.Fatalf("old config must load with per second and no options: %+v", ep)
	}
	ep.initNetworkOptions()
	if ep.pathRulesErr != nil || ep.rateOpts != nil || len(ep.pathRules) != 1 {
		t.Fatalf("old config must compile: %v", ep.pathRulesErr)
	}
	if ep.pathRules[0].ratePerS != 2 || ep.pathRules[0].rateBurst != 3 || ep.pathRules[0].KeyBy != "" {
		t.Errorf("old path rule meaning changed: %+v", ep.pathRules[0])
	}
	if RatePerSecond(ep.RateLimit, ep.RateUnit) != 5 {
		t.Errorf("old site limit is per second")
	}
	// and nothing new is written for a config that does not use the new fields
	js, _ := json.Marshal(ep)
	for _, k := range []string{"RateUnit", "RateOptions", "KeyBy", "KeyHeader"} {
		if strings.Contains(string(js), k) {
			t.Errorf("%s must be omitted from an old style config: %s", k, js)
		}
	}
	// the old behaviour: 5 req/s, burst 5
	router := newTestRateLimitRouter(t, false)
	ep.RootOrMatchingDomain = "old.example.com"
	passed := 0
	for i := 0; i < 20; i++ {
		if router.handleRateLimit(httptest.NewRecorder(), newTestRequest("198.51.100.7:1", nil), ep) == nil {
			passed++
		}
	}
	if passed != 5 {
		t.Errorf("old limit of 5/s must pass 5 at once, got %d", passed)
	}
	// a per second 429 carries no new header
	w := httptest.NewRecorder()
	router.handleRateLimit(w, newTestRequest("198.51.100.7:1", nil), ep)
	if w.Code != 429 || w.Header().Get("Retry-After") != "" {
		t.Errorf("per second 429 unchanged expected, got %d %q", w.Code, w.Header().Get("Retry-After"))
	}
}

/* ---- keying ---- */

func authReq(remote, auth string) *http.Request {
	h := map[string]string{}
	if auth != "" {
		h["Authorization"] = auth
	}
	return newTestRequest(remote, h)
}

func TestKeyByAuthorization(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RootOrMatchingDomain: "api.example.com", RequireRateLimit: true, RateLimit: 3, RateOptions: &RateLimitOptions{KeyBy: RateKeyAuthorization}}
	pe.initRateOptions()
	count := func(auth string) int {
		n := 0
		for i := 0; i < 10; i++ {
			if router.handleRateLimit(httptest.NewRecorder(), authReq("198.51.100.7:1", auth), pe) == nil {
				n++
			}
		}
		return n
	}
	if got := count("Bearer key-one"); got != 3 {
		t.Fatalf("key one has its own budget of 3, got %d", got)
	}
	if got := count("Bearer key-two"); got != 3 {
		t.Fatalf("key two shares the IP but not the budget, got %d", got)
	}
	// the same key from another address is the same client
	n := 0
	for i := 0; i < 5; i++ {
		if router.handleRateLimit(httptest.NewRecorder(), authReq("203.0.113.9:1", "Bearer key-one"), pe) == nil {
			n++
		}
	}
	if n != 0 {
		t.Errorf("a key that is out of budget stays limited from another address, got %d", n)
	}
	// no header: safe fallback to the IP bucket
	if got := count(""); got != 3 {
		t.Fatalf("a request without the header falls back to the IP budget of 3, got %d", got)
	}
}

func TestKeyByNamedHeaderAndSecretNeverStored(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RootOrMatchingDomain: "api.example.com", RequireRateLimit: true, RateLimit: 2,
		RateOptions: &RateLimitOptions{KeyBy: RateKeyHeader, KeyHeader: "x-api-key"}}
	pe.initRateOptions()
	secret := "SUPER-SECRET-API-KEY-12345"
	for i := 0; i < 5; i++ {
		r := newTestRequest("198.51.100.7:1", map[string]string{"X-Api-Key": secret})
		router.handleRateLimit(httptest.NewRecorder(), r, pe)
	}
	router.rateLimitCounter.table.Range(func(k, v interface{}) bool {
		if strings.Contains(k.(string), secret) || strings.Contains(k.(string), "SECRET") {
			t.Errorf("the key value must only be kept hashed, found %q", k)
		}
		return true
	})
	// a different header does not count as the key
	n := 0
	for i := 0; i < 10; i++ {
		r := newTestRequest("198.51.100.7:1", map[string]string{"Authorization": "x" + strconv.Itoa(i)})
		if router.handleRateLimit(httptest.NewRecorder(), r, pe) == nil {
			n++
		}
	}
	if n > 2 {
		t.Errorf("without the named header the IP budget applies, %d passed", n)
	}
}

// A client can invent a new key per request. The per IP guard bounds that.
func TestKeyRotationIsBoundedByIPGuard(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RootOrMatchingDomain: "api.example.com", RequireRateLimit: true, RateLimit: 5, RateOptions: &RateLimitOptions{KeyBy: RateKeyAuthorization}}
	pe.initRateOptions()
	passed := 0
	for i := 0; i < 500; i++ {
		if router.handleRateLimit(httptest.NewRecorder(), authReq("198.51.100.7:1", "Bearer rotating-"+strconv.Itoa(i)), pe) == nil {
			passed++
		}
	}
	if passed > 5*rateKeyedGuardFactor {
		t.Errorf("rotating keys must not give unlimited throughput: %d of 500 passed", passed)
	}
	if passed < 5 {
		t.Errorf("legitimate keys must still pass, got %d", passed)
	}
}

func TestRateKeyFor(t *testing.T) {
	r := authReq("1.1.1.1:1", "Bearer abc")
	k1, keyed := rateKeyFor(r, RateKeyAuthorization, "", "1.1.1.1")
	k2, _ := rateKeyFor(authReq("2.2.2.2:1", "Bearer abc"), RateKeyAuthorization, "", "2.2.2.2")
	k3, _ := rateKeyFor(authReq("1.1.1.1:1", "Bearer abd"), RateKeyAuthorization, "", "1.1.1.1")
	if !keyed || k1 != k2 || k1 == k3 || strings.Contains(k1, "abc") {
		t.Errorf("keys: %q %q %q keyed=%v", k1, k2, k3, keyed)
	}
	if k, keyed := rateKeyFor(r, RateKeyIP, "", "1.1.1.1"); keyed || k != "1.1.1.1" {
		t.Errorf("default key is the IP, got %q %v", k, keyed)
	}
	if k, keyed := rateKeyFor(authReq("1.1.1.1:1", "  "), RateKeyAuthorization, "", "1.1.1.1"); keyed || k != "1.1.1.1" {
		t.Errorf("empty header falls back to the IP, got %q %v", k, keyed)
	}
	huge := strings.Repeat("a", maxRateKeyValueLen+1)
	if k, keyed := rateKeyFor(authReq("1.1.1.1:1", huge), RateKeyAuthorization, "", "1.1.1.1"); keyed || k != "1.1.1.1" {
		t.Errorf("an oversized value falls back to the IP, got %q %v", k, keyed)
	}
}

/* ---- trusted monitoring exemption ---- */

func TestExemptCIDRAndHeader(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RootOrMatchingDomain: "app.example.com", RequireRateLimit: true, RateLimit: 1,
		RateOptions: &RateLimitOptions{ExemptCIDRs: []string{"192.0.2.0/24", "2001:db8::1"}, ExemptHeader: "X-Monitor-Token", ExemptHeaderValue: "s3cret-token-value"}}
	if err := pe.RateOptions.Validate(); err != nil {
		t.Fatal(err)
	}
	pe.initRateOptions()
	limited := func(r *http.Request) bool {
		for i := 0; i < 30; i++ {
			if router.handleRateLimit(httptest.NewRecorder(), r.Clone(r.Context()), pe) != nil {
				return true
			}
		}
		return false
	}
	if limited(newTestRequest("192.0.2.55:1", nil)) {
		t.Error("an address in the exempt CIDR is never limited")
	}
	if limited(newTestRequest("[2001:db8::1]:1", nil)) {
		t.Error("an exempt IPv6 address is never limited")
	}
	if !limited(newTestRequest("198.51.100.7:1", nil)) {
		t.Error("other addresses are limited")
	}
	if limited(newTestRequest("198.51.100.8:1", map[string]string{"X-Monitor-Token": "s3cret-token-value"})) {
		t.Error("the secret header exempts the request")
	}
	if !limited(newTestRequest("198.51.100.9:1", map[string]string{"X-Monitor-Token": "wrong-token-value!"})) {
		t.Error("a wrong header value must not exempt")
	}
	if !limited(newTestRequest("198.51.100.10:1", map[string]string{"X-Monitor-Token": "s3cret-token-valu"})) {
		t.Error("a prefix of the secret must not exempt")
	}
	// an exempt request does not consume the bucket of the address
	pe2 := &ProxyEndpoint{RootOrMatchingDomain: "b.example.com", RequireRateLimit: true, RateLimit: 2, RateOptions: &RateLimitOptions{ExemptCIDRs: []string{"192.0.2.0/24"}}}
	pe2.initRateOptions()
	for i := 0; i < 50; i++ {
		router.handleRateLimit(httptest.NewRecorder(), newTestRequest("192.0.2.1:1", nil), pe2)
	}
	if router.rateLimitCounter.Has("b.example.com", "192.0.2.1") {
		t.Error("exempt requests are not counted")
	}
}

// A forwarded header from a peer that is not a trusted proxy must not grant the exemption.
func TestExemptCannotBeSpoofedWithForwardedHeader(t *testing.T) {
	router := newTestRateLimitRouter(t, true, "104.16.0.0/13")
	pe := &ProxyEndpoint{RootOrMatchingDomain: "app.example.com", RequireRateLimit: true, RateLimit: 1, RateOptions: &RateLimitOptions{ExemptCIDRs: []string{"192.0.2.0/24"}}}
	pe.initRateOptions()
	limited := false
	for i := 0; i < 20; i++ {
		r := newTestRequest("198.51.100.7:1", map[string]string{"X-Forwarded-For": "192.0.2.1", "CF-Connecting-IP": "192.0.2.1"})
		if router.handleRateLimit(httptest.NewRecorder(), r, pe) != nil {
			limited = true
		}
	}
	if !limited {
		t.Error("a spoofed forwarded address from an untrusted peer must not be exempt")
	}
	// from a trusted proxy the forwarded address is the client
	for i := 0; i < 20; i++ {
		r := newTestRequest("104.16.5.1:443", map[string]string{"CF-Connecting-IP": "192.0.2.1"})
		if err := router.handleRateLimit(httptest.NewRecorder(), r, pe); err != nil {
			t.Fatal("the real client behind a trusted proxy is exempt")
		}
	}
}

func TestRateOptionsValidation(t *testing.T) {
	bad := []RateLimitOptions{
		{KeyBy: "cookie"},
		{KeyBy: RateKeyHeader},
		{KeyBy: RateKeyHeader, KeyHeader: "bad name"},
		{KeyBy: RateKeyHeader, KeyHeader: "Host"},
		{KeyBy: RateKeyAuthorization, KeyHeader: "X-Key"},
		{ExemptCIDRs: []string{"300.1.1.1"}},
		{ExemptHeader: "X-Mon"},
		{ExemptHeaderValue: "longenoughsecret"},
		{ExemptHeader: "X-Mon", ExemptHeaderValue: "short"},
		{ExemptHeader: "X-Mon", ExemptHeaderValue: "has\ncontrol-char"},
		{WSMaxConnsPerIP: -1},
		{WSExempt: true},
		{WSMaxConnsPerIP: maxWSConnsPerIP + 1},
	}
	for i, o := range bad {
		o := o
		if err := o.Validate(); err == nil {
			t.Errorf("case %d (%+v) accepted", i, o)
		}
	}
	good := RateLimitOptions{KeyBy: "header", KeyHeader: "X-API-Key", ExemptCIDRs: []string{"10.0.0.0/8", " ", "192.0.2.7"}, ExemptHeader: "X-Mon", ExemptHeaderValue: "longenoughsecret", WSExempt: true, WSMaxConnsPerIP: 10}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	n := good.Normalised()
	if len(n.ExemptCIDRs) != 2 {
		t.Errorf("blank entries must be dropped: %v", n.ExemptCIDRs)
	}
	if (&RateLimitOptions{KeyBy: "ip"}).Normalised() != nil {
		t.Error("an options value that sets nothing normalises to nil, so nothing is stored")
	}
	if err := ValidateRateLimitSetting(true, 0, "", 0); err == nil {
		t.Error("an enabled limit of 0 is rejected")
	}
	if err := ValidateRateLimitSetting(true, 5, "hour", 0); err == nil {
		t.Error("an unknown unit is rejected")
	}
	if err := ValidateRateLimitSetting(true, 120, "minute", 0); err != nil {
		t.Error(err)
	}
}

/* ---- WebSocket accounting ---- */

func wsRequest(remote string) *http.Request {
	r := newTestRequest(remote, map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"})
	return r
}

// Today (default): a WebSocket handshake is an HTTP request and is counted like any other.
func TestWebSocketHandshakeCountedByDefault(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RootOrMatchingDomain: "ws.example.com", RequireRateLimit: true, RateLimit: 3}
	pe.initRateOptions()
	blocked := 0
	for i := 0; i < 10; i++ {
		if router.handleRateLimit(httptest.NewRecorder(), wsRequest("198.51.100.7:1"), pe) != nil {
			blocked++
		}
	}
	if blocked != 7 {
		t.Errorf("by default handshakes are counted (3 pass, 7 limited), blocked %d", blocked)
	}
}

func TestWebSocketHandshakeExempt(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RootOrMatchingDomain: "ws.example.com", RequireRateLimit: true, RateLimit: 3,
		RateOptions: &RateLimitOptions{WSExempt: true, WSMaxConnsPerIP: 5}}
	pe.initRateOptions()
	for i := 0; i < 50; i++ {
		if router.handleRateLimit(httptest.NewRecorder(), wsRequest("198.51.100.7:1"), pe) != nil {
			t.Fatal("exempt handshakes are never limited")
		}
	}
	if router.rateLimitCounter.Has("ws.example.com", "198.51.100.7") {
		t.Error("exempt handshakes must not consume the bucket")
	}
	// plain HTTP requests are still limited and a request that only claims websocket in another header is not exempt
	blocked := 0
	for i := 0; i < 10; i++ {
		if router.handleRateLimit(httptest.NewRecorder(), newTestRequest("198.51.100.7:1", nil), pe) != nil {
			blocked++
		}
	}
	if blocked != 7 {
		t.Errorf("normal requests keep their limit, blocked %d", blocked)
	}
	// when WebSockets are disabled on the rule the handshake is answered with 403 by the proxy and is not exempt
	pe.DisableWebSocket = true
	if !pe.rateSkipsWebSocket(wsRequest("198.51.100.7:1")) == false {
		t.Error("a rule that blocks WebSockets exempts nothing")
	}
}

func TestWebSocketConnectionCap(t *testing.T) {
	router, _, _ := newNonTLSTestRouter(t)
	h := &ProxyHandler{Parent: router}
	pe := &ProxyEndpoint{RootOrMatchingDomain: "ws.example.com", RateOptions: &RateLimitOptions{WSMaxConnsPerIP: 2, ExemptCIDRs: []string{"192.0.2.0/24"}}}
	pe.initRateOptions()

	var rel []func()
	for i := 0; i < 2; i++ {
		release, ok := h.wsAcquire(httptest.NewRecorder(), wsRequest("198.51.100.7:1"), pe)
		if !ok {
			t.Fatalf("connection %d is within the cap", i+1)
		}
		rel = append(rel, release)
	}
	w := httptest.NewRecorder()
	if _, ok := h.wsAcquire(w, wsRequest("198.51.100.7:2"), pe); ok || w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("the third connection is refused with 429, got ok=%v %d", ok, w.Code)
	}
	// another client and an exempt monitor are not affected
	if r, ok := h.wsAcquire(httptest.NewRecorder(), wsRequest("198.51.100.8:1"), pe); !ok {
		t.Error("another client has its own cap")
	} else {
		r()
	}
	for i := 0; i < 10; i++ {
		if r, ok := h.wsAcquire(httptest.NewRecorder(), wsRequest("192.0.2.4:1"), pe); !ok {
			t.Fatal("trusted monitoring is not capped")
		} else {
			r()
		}
	}
	// closing a connection frees its slot; releasing twice frees only one
	rel[0]()
	rel[0]()
	if router.wsConns.count("ws.example.com|198.51.100.7") != 1 {
		t.Errorf("double release must not free two slots, open=%d", router.wsConns.count("ws.example.com|198.51.100.7"))
	}
	r3, ok := h.wsAcquire(httptest.NewRecorder(), wsRequest("198.51.100.7:3"), pe)
	if !ok {
		t.Fatal("a freed slot can be used again")
	}
	r3()
	rel[1]()
	if router.wsConns.Len() != 0 {
		t.Errorf("the table must be empty when every connection closed, has %d", router.wsConns.Len())
	}
	// no cap configured: nothing is counted
	pe0 := &ProxyEndpoint{RootOrMatchingDomain: "none.example.com"}
	pe0.initRateOptions()
	for i := 0; i < 100; i++ {
		if _, ok := h.wsAcquire(httptest.NewRecorder(), wsRequest("198.51.100.7:1"), pe0); !ok {
			t.Fatal("without a cap every connection passes")
		}
	}
	if router.wsConns.Len() != 0 {
		t.Error("without a cap nothing is tracked")
	}
}

/* ---- through the shared chain: path limits ---- */

func TestPathRuleRateLimitPerMinute(t *testing.T) {
	router, sep := pathRuleRouter(t, &PathRule{Pattern: "/login", Action: PathRuleRateLimit, RateLimit: 4, RateUnit: "minute", RateBurst: 2})
	sep.RequireRateLimit = false
	codes := []int{}
	var last *httptest.ResponseRecorder
	for i := 0; i < 5; i++ {
		last = serveRaw(router, sep, "POST", "/login", "198.51.100.7:1", nil)
		codes = append(codes, last.Code)
	}
	if codes[0] == 429 || codes[1] == 429 || codes[2] != 429 {
		t.Errorf("burst of 2 expected: %v", codes)
	}
	if last.Header().Get("Retry-After") != "15" {
		t.Errorf("4 req/min = one token per 15 s, Retry-After %q", last.Header().Get("Retry-After"))
	}
	if c := serveRaw(router, sep, "GET", "/other", "198.51.100.7:1", nil).Code; c == 429 {
		t.Errorf("other paths are not limited by the path rule")
	}
}

func TestPathRuleKeyedAndExempt(t *testing.T) {
	router, sep := pathRuleRouter(t, &PathRule{Pattern: "/api", Action: PathRuleRateLimit, RateLimit: 2, RateUnit: "minute", KeyBy: "authorization"})
	sep.RateOptions = &RateLimitOptions{ExemptCIDRs: []string{"192.0.2.0/24"}}
	sep.initNetworkOptions()
	count := func(remote, auth string) int {
		n := 0
		for i := 0; i < 6; i++ {
			hdr := map[string]string{}
			if auth != "" {
				hdr["Authorization"] = auth
			}
			if serveRaw(router, sep, "GET", "/api/x", remote, hdr).Code != 429 {
				n++
			}
		}
		return n
	}
	if n := count("198.51.100.7:1", "Bearer a"); n != 2 {
		t.Errorf("key a: 2 pass, got %d", n)
	}
	if n := count("198.51.100.7:1", "Bearer b"); n != 2 {
		t.Errorf("key b has its own budget, got %d", n)
	}
	if n := count("192.0.2.9:1", ""); n != 6 {
		t.Errorf("exempt monitor passes everything, got %d", n)
	}
}

func TestPathRuleWebSocketExempt(t *testing.T) {
	router, sep := pathRuleRouter(t, &PathRule{Pattern: "/ws", Action: PathRuleRateLimit, RateLimit: 1, RateUnit: "minute"})
	hdr := map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}
	blocked := 0
	for i := 0; i < 5; i++ {
		if serveRaw(router, sep, "GET", "/ws", "198.51.100.7:1", hdr).Code == 429 {
			blocked++
		}
	}
	if blocked != 4 {
		t.Fatalf("default: handshakes counted, got %d limited", blocked)
	}
	sep.RateOptions = &RateLimitOptions{WSExempt: true, WSMaxConnsPerIP: 5}
	sep.initNetworkOptions()
	for i := 0; i < 5; i++ {
		if serveRaw(router, sep, "GET", "/ws", "198.51.100.17:1", hdr).Code == 429 {
			t.Fatal("exempt handshakes are not counted by path limits either")
		}
	}
}

func TestPathRuleNewFieldsValidated(t *testing.T) {
	for i, r := range []PathRule{
		{Pattern: "/a", Action: PathRuleRateLimit, RateLimit: 1, RateUnit: "hour"},
		{Pattern: "/a", Action: PathRuleRateLimit, RateLimit: 1, KeyBy: "header"},
		{Pattern: "/a", Action: PathRuleRateLimit, RateLimit: 1, KeyBy: "header", KeyHeader: "Host"},
		{Pattern: "/a", Action: PathRuleRateLimit, RateLimit: maxProxyRateLimitPerUnit + 1},
	} {
		r := r
		if _, err := compilePathRule(&r); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	c, err := compilePathRule(&PathRule{Pattern: "/a", Action: PathRuleRateLimit, RateLimit: 30, RateUnit: "Minute", KeyBy: "HEADER", KeyHeader: "x-api-key"})
	if err != nil || c.RateUnit != "minute" || c.KeyBy != "header" || c.KeyHeader != "X-Api-Key" || c.ratePerS != 0.5 || c.rateBurst != 30 {
		t.Errorf("compiled: %+v %v", c, err)
	}
}

/* ---- templates and presets ---- */

func presetByName(t *testing.T, name string) *RuleTemplate {
	t.Helper()
	for _, p := range AppPresets() {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("preset %q missing", name)
	return nil
}

func TestRateLimitPresetsCatalogue(t *testing.T) {
	want := []string{"Public website", "Login page", "Admin dashboard", "Odoo ERP", "REST API per key", "Webhook receiver", "File upload", "WebSocket app limits", "Monitoring-friendly"}
	for _, n := range want {
		p := presetByName(t, n)
		if !p.NoDowngrade || !strings.HasPrefix(p.Note, "A starting point, review it") {
			t.Errorf("%s: NoDowngrade and the review note are required", n)
		}
		if !strings.Contains(p.Note, "availability") {
			t.Errorf("%s: the note must say what rate limiting does and does not protect", n)
		}
	}
	// the table's starting numbers and recommendations
	checks := []struct {
		name  string
		limit int64
		unit  string
		note  string
	}{
		{"Public website", 120, "minute", ""},
		{"Admin dashboard", 60, "minute", "VPN or an IP restriction"},
		{"Odoo ERP", 300, "minute", "Tune it by endpoint"},
		{"REST API per key", 120, "minute", "Authorization"},
		{"Webhook receiver", 120, "minute", "Authenticate webhooks"},
		{"Monitoring-friendly", 300, "minute", "monitoring system"},
	}
	for _, c := range checks {
		p := presetByName(t, c.name)
		if p.RateLimit == nil || *p.RateLimit != c.limit || p.rateUnit() != c.unit {
			t.Errorf("%s: want %d/%s", c.name, c.limit, c.unit)
		}
		if !strings.Contains(p.Note, c.note) {
			t.Errorf("%s: note must contain %q", c.name, c.note)
		}
	}
	login := presetByName(t, "Login page")
	if login.RateLimit != nil || len(login.PathRateLimits) == 0 || !strings.Contains(login.Note, "Account-level protection") {
		t.Errorf("login preset limits login paths only and warns about account protection: %+v", login)
	}
	for _, p := range login.PathRateLimits {
		if p.RateUnit != "minute" || p.RateLimit < 5 || p.RateLimit > 10 {
			t.Errorf("login: 5-10 attempts per minute, got %d/%s", p.RateLimit, p.RateUnit)
		}
	}
	up := presetByName(t, "File upload")
	for _, p := range up.PathRateLimits {
		if p.RateLimit < 10 || p.RateLimit > 20 || p.RateUnit != "minute" {
			t.Errorf("upload: 10-20 per minute, got %d/%s", p.RateLimit, p.RateUnit)
		}
	}
	ws := presetByName(t, "WebSocket app limits")
	if ws.RateLimit != nil || ws.WSMaxConnsPerIP == nil || ws.WSExemptFromRateLimit == nil || !*ws.WSExemptFromRateLimit {
		t.Errorf("the WebSocket preset limits connections, not requests: %+v", ws)
	}
	if k := presetByName(t, "REST API per key"); k.RateKeyBy == nil || *k.RateKeyBy != "authorization" {
		t.Error("the API preset keys by Authorization")
	}
	if !presetByName(t, "Admin dashboard").RequiresAuth {
		t.Error("the admin preset asks for authentication")
	}
}

func TestRateLimitPresetsApplyNoDowngrade(t *testing.T) {
	// fresh rule
	ep := presetTestRule()
	ch, err := ApplyRuleTemplate(ep, presetByName(t, "Public website"))
	if err != nil || len(ch) == 0 {
		t.Fatal(ch, err)
	}
	if !ep.RequireRateLimit || ep.RateLimit != 120 || ep.RateUnit != "minute" {
		t.Errorf("120 req/min expected: %+v", ep)
	}
	foundRate := false
	for _, c := range ch {
		if c.Field == "Rate limit" && c.Old == "off" && c.New == "120 req/min" {
			foundRate = true
		}
	}
	if !foundRate {
		t.Errorf("the preview must show the change in the unit: %+v", ch)
	}
	// idempotent
	if ch2, _ := ApplyRuleTemplate(ep, presetByName(t, "Public website")); len(ch2) != 0 {
		t.Errorf("second apply changes nothing: %v", ch2)
	}

	// 1 req/s (= 60/min) is stricter than 120/min: kept, and the unit does not flip
	strict := presetTestRule()
	strict.RequireRateLimit, strict.RateLimit = true, 1
	ApplyRuleTemplate(strict, presetByName(t, "Public website"))
	if strict.RateLimit != 1 || strict.RateUnit != "" {
		t.Errorf("a stricter per second limit is kept: %+v", strict)
	}
	// a stricter per minute limit is kept against a per second preset value of the same speed
	strict2 := presetTestRule()
	strict2.RequireRateLimit, strict2.RateLimit, strict2.RateUnit = true, 30, "minute"
	ApplyRuleTemplate(strict2, presetByName(t, "Admin dashboard"))
	if strict2.RateLimit != 30 || strict2.RateUnit != "minute" {
		t.Errorf("30/min is stricter than 60/min: %+v", strict2)
	}
	// a looser limit is tightened
	loose := presetTestRule()
	loose.RequireRateLimit, loose.RateLimit = true, 100
	ApplyRuleTemplate(loose, presetByName(t, "Admin dashboard"))
	if loose.RateLimit != 60 || loose.RateUnit != "minute" {
		t.Errorf("100 req/s is looser than 60 req/min and is tightened: %+v", loose)
	}
	// equal speed in another unit is kept as it is (60/min == 1/s)
	same := presetTestRule()
	same.RequireRateLimit, same.RateLimit = true, 1
	if ch, _ := ApplyRuleTemplate(same, presetByName(t, "Admin dashboard")); len(findField(ch, "Rate limit")) != 0 {
		t.Errorf("an equal limit is not rewritten: %v", ch)
	}

	// key: only with the limit it belongs to, never over an operator's choice
	api := presetTestRule()
	ApplyRuleTemplate(api, presetByName(t, "REST API per key"))
	if api.RateOptions == nil || api.RateOptions.KeyBy != "authorization" {
		t.Errorf("fresh rule gets the key: %+v", api.RateOptions)
	}
	chosen := presetTestRule()
	chosen.RateOptions = &RateLimitOptions{KeyBy: "header", KeyHeader: "X-Key"}
	chosen.RequireRateLimit, chosen.RateLimit = true, 10000
	ApplyRuleTemplate(chosen, presetByName(t, "REST API per key"))
	if chosen.RateOptions.KeyBy != "header" || chosen.RateOptions.KeyHeader != "X-Key" {
		t.Errorf("the operator's key stays: %+v", chosen.RateOptions)
	}
	keptStrict := presetTestRule()
	keptStrict.RequireRateLimit, keptStrict.RateLimit = true, 1
	ApplyRuleTemplate(keptStrict, presetByName(t, "REST API per key"))
	if keptStrict.RateOptions != nil {
		t.Errorf("the key changes with the limit only; a kept strict per IP limit stays per IP: %+v", keptStrict.RateOptions)
	}

	// exemptions are never touched and a lower cap is kept
	wsEp := presetTestRule()
	wsEp.RateOptions = &RateLimitOptions{ExemptCIDRs: []string{"192.0.2.0/24"}, WSMaxConnsPerIP: 5}
	ApplyRuleTemplate(wsEp, presetByName(t, "WebSocket app limits"))
	if len(wsEp.RateOptions.ExemptCIDRs) != 1 || wsEp.RateOptions.WSMaxConnsPerIP != 5 || !wsEp.RateOptions.WSExempt {
		t.Errorf("exemptions and a lower cap are kept: %+v", wsEp.RateOptions)
	}
	hi := presetTestRule()
	hi.RateOptions = &RateLimitOptions{WSMaxConnsPerIP: 500}
	ApplyRuleTemplate(hi, presetByName(t, "WebSocket app limits"))
	if hi.RateOptions.WSMaxConnsPerIP != 20 {
		t.Errorf("a higher cap is lowered to 20: %+v", hi.RateOptions)
	}
}

func findField(ch []RuleChange, prefix string) []RuleChange {
	var out []RuleChange
	for _, c := range ch {
		if strings.HasPrefix(c.Field, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func TestPathLimitPresetsAppendAndNeverShadow(t *testing.T) {
	ep := presetTestRule()
	deny := &PathRule{Pattern: "/login", Action: PathRuleDeny, CIDRs: []string{"10.0.0.0/8"}, ScopeInvert: true}
	other := &PathRule{Pattern: "/status", Action: PathRuleAllow}
	ep.PathRules = []*PathRule{deny, other}
	orig := ep.PathRules
	preset := presetByName(t, "Login page")
	ch, err := ApplyRuleTemplate(ep, preset)
	if err != nil {
		t.Fatal(err)
	}
	if len(ep.PathRules) != 2+len(preset.PathRateLimits) {
		t.Fatalf("limits are added: %d rules", len(ep.PathRules))
	}
	if ep.PathRules[0] != deny || ep.PathRules[1] != other {
		t.Error("existing rules keep their place; new limits go to the end so they never shadow a deny")
	}
	if len(orig) != 2 {
		t.Error("the original slice is not modified in place")
	}
	if len(findField(ch, "Path limit /login")) != 1 {
		t.Errorf("preview lists each path: %v", ch)
	}
	for _, r := range ep.PathRules[2:] {
		if r.Action != PathRuleRateLimit || r.RateUnit != "minute" || r.RateLimit != 5 {
			t.Errorf("new rule: %+v", r)
		}
	}
	ep.initNetworkOptions()
	if ep.pathRulesErr != nil {
		t.Fatalf("rules compile: %v", ep.pathRulesErr)
	}
	if ch2, _ := ApplyRuleTemplate(ep, preset); len(ch2) != 0 {
		t.Errorf("second apply changes nothing: %v", ch2)
	}

	// an existing limit for the same path: the stricter wins, the live rule object is not mutated
	ep2 := presetTestRule()
	liveLoose := &PathRule{Pattern: "/login", Action: PathRuleRateLimit, RateLimit: 50, CIDRs: []string{"203.0.113.0/24"}}
	liveStrict := &PathRule{Pattern: "/signin", Action: PathRuleRateLimit, RateLimit: 1, RateUnit: "minute"}
	ep2.PathRules = []*PathRule{liveLoose, liveStrict}
	ApplyRuleTemplate(ep2, preset)
	if liveLoose.RateLimit != 50 || liveLoose.RateUnit != "" {
		t.Error("the shared rule pointer must not be mutated (preview works on a copy but may share pointers)")
	}
	if got := ep2.PathRules[0]; got.RateLimit != 5 || got.RateUnit != "minute" || len(got.CIDRs) != 1 {
		t.Errorf("a looser limit is tightened and keeps its scope: %+v", got)
	}
	if got := ep2.PathRules[1]; got.RateLimit != 1 || got.RateUnit != "minute" {
		t.Errorf("a stricter limit is kept: %+v", got)
	}
}

func TestPresetPreviewDoesNotTouchLiveEndpoint(t *testing.T) {
	live := presetTestRule()
	live.PathRules = []*PathRule{{Pattern: "/login", Action: PathRuleRateLimit, RateLimit: 50}}
	live.RateOptions = &RateLimitOptions{WSMaxConnsPerIP: 500}
	cp := CopyEndpoint(live)
	for _, n := range []string{"Login page", "Odoo ERP", "WebSocket app limits", "File upload", "REST API per key"} {
		if _, err := ApplyRuleTemplate(cp, presetByName(t, n)); err != nil {
			t.Fatal(err)
		}
	}
	if len(live.PathRules) != 1 || live.PathRules[0].RateLimit != 50 || live.RateOptions.WSMaxConnsPerIP != 500 || live.RequireRateLimit {
		t.Errorf("preview on a copy must leave the live rule alone: %+v %+v", live.PathRules[0], live.RateOptions)
	}
}

func TestTemplateValidationOfRateParts(t *testing.T) {
	base := func() *RuleTemplate { return &RuleTemplate{Name: "T"} }
	cases := map[string]func(t *RuleTemplate){
		"unit without limit":       func(t *RuleTemplate) { t.RateUnit = sptr("minute") },
		"bad unit":                 func(t *RuleTemplate) { t.RateLimit, t.RateUnit = i64(5), sptr("day") },
		"key without limit":        func(t *RuleTemplate) { t.RateKeyBy = sptr("authorization") },
		"bad key":                  func(t *RuleTemplate) { t.RateLimit, t.RateKeyBy = i64(5), sptr("cookie") },
		"ws exempt without cap":    func(t *RuleTemplate) { t.WSExemptFromRateLimit = bptr(true) },
		"negative cap":             func(t *RuleTemplate) { t.WSMaxConnsPerIP = i64(-1) },
		"path limit without slash": func(t *RuleTemplate) { t.PathRateLimits = []PathRateLimit{{Pattern: "login", RateLimit: 5}} },
		"path limit zero":          func(t *RuleTemplate) { t.PathRateLimits = []PathRateLimit{{Pattern: "/login"}} },
	}
	for name, mut := range cases {
		tt := base()
		mut(tt)
		if err := tt.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := base()
	ok.RateLimit, ok.RateUnit, ok.RateKeyBy = i64(60), sptr("minute"), sptr("authorization")
	if err := ok.Validate(); err != nil {
		t.Error(err)
	}
}

func TestBulkRateLimitUnit(t *testing.T) {
	router := bulkRouter(t, "a.example.com")
	run := func(p BulkParams) []BulkResult {
		res, _ := router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkSetRateLimit, Params: p}, BulkHooks{})
		return res
	}
	if res := run(BulkParams{RateLimitEnabled: true, RateLimit: 120, RateUnit: "minute"}); !res[0].OK {
		t.Fatalf("%+v", res)
	}
	if ep, _ := router.LoadProxy("a.example.com"); ep.RateLimit != 120 || ep.RateUnit != "minute" {
		t.Fatalf("%+v", ep)
	}
	// without a unit a bulk limit means per second again, as before units existed
	run(BulkParams{RateLimitEnabled: true, RateLimit: 10})
	if ep, _ := router.LoadProxy("a.example.com"); ep.RateLimit != 10 || ep.RateUnit != "" {
		t.Fatalf("%+v", ep)
	}
	if res := run(BulkParams{RateLimitEnabled: true, RateLimit: 10, RateUnit: "week"}); res != nil && res[0].OK {
		t.Error("an unknown unit is rejected")
	}
}
