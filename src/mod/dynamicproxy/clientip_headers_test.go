package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Upstream #1359: with the trusted proxy list enabled, client IP headers sent by a
// peer that is not a trusted proxy must not reach the upstream.
func TestUntrustedClientIPHeadersAreStripped(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	rule.TrustProxyHeadersOnly = true
	router.Option.AccessController.AddTrustedProxy("203.0.113.0/24", "cdn")

	var seen http.Header
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
		seen = r.Header.Clone()
		w.WriteHeader(299)
		return true
	}

	send := func(remote string) http.Header {
		seen = nil
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "10.0.0.5")
		r.Header.Set("X-Real-Ip", "10.0.0.5")
		r.Header.Set("CF-Connecting-IP", "10.0.0.5")
		r.Header.Set("Forwarded", "for=10.0.0.5")
		router.handleNonTLSRequest(w, r, sep)
		if w.Code != 299 {
			t.Fatalf("request from %s got %d", remote, w.Code)
		}
		return seen
	}

	// Direct, untrusted client: spoofed headers are dropped
	h := send("198.51.100.7:4444")
	for _, k := range []string{"X-Forwarded-For", "X-Real-Ip", "CF-Connecting-IP", "Forwarded"} {
		if v := h.Get(k); v != "" {
			t.Errorf("untrusted client could set %s=%q", k, v)
		}
	}

	// Trusted proxy (CDN): its headers are kept
	h = send("203.0.113.9:4444")
	if h.Get("X-Forwarded-For") != "10.0.0.5" || h.Get("X-Real-Ip") != "10.0.0.5" {
		t.Errorf("headers from a trusted proxy must be preserved: %v", h)
	}

	// Setups that never enabled the trusted proxy option keep the old pass-through behaviour
	rule.TrustProxyHeadersOnly = false
	h = send("198.51.100.7:4444")
	if h.Get("X-Forwarded-For") != "10.0.0.5" {
		t.Errorf("legacy pass-through must be unchanged when the option is off: %v", h)
	}
}
