package dynamicproxy

import (
	"net/http/httptest"
	"testing"
)

// Upstream #1107: "Require Rate Limit" is a per proxy rule setting. A limited rule must not throttle
// another rule, and a rule without the option must never be limited.
func TestHandleRateLimit_IsPerProxyRule(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	limited := &ProxyEndpoint{RootOrMatchingDomain: "a.example.com", RequireRateLimit: true, RateLimit: 2}
	other := &ProxyEndpoint{RootOrMatchingDomain: "b.example.com", RequireRateLimit: true, RateLimit: 1000}

	hit := func(pe *ProxyEndpoint) error {
		return router.handleRateLimit(httptest.NewRecorder(), newTestRequest("198.51.100.5:1234", nil), pe)
	}
	blocked := false
	for i := 0; i < 5; i++ {
		if hit(limited) != nil {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("rule with a low limit never limited the client")
	}
	for i := 0; i < 50; i++ {
		if err := hit(other); err != nil {
			t.Fatalf("the other rule was throttled by the first rule's counter at request %d", i)
		}
	}
}
