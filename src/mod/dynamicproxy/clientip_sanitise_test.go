package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Upstream #1359 residual: with "trust proxy headers" off (default) the client IP headers were
// forwarded unchanged. The opt-in sanitise switch (per endpoint or global) drops them for
// every peer that is not in the trusted proxy list. Default off keeps the old behaviour.
func TestSanitiseClientIPHeaders(t *testing.T) {
	spoofed := []string{"X-Forwarded-For", "X-Real-Ip", "CF-Connecting-IP", "Forwarded", "True-Client-IP", "Fastly-Client-IP"}

	cases := []struct {
		name         string
		endpointOn   bool
		globalOn     bool
		remote       string
		wantStripped bool
	}{
		{"default off passes through", false, false, "198.51.100.7:4444", false},
		{"endpoint on strips", true, false, "198.51.100.7:4444", true},
		{"global on strips", false, true, "198.51.100.7:4444", true},
		{"trusted proxy keeps headers", true, false, "203.0.113.9:4444", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, sep, rule := newNonTLSTestRouter(t)
			rule.TrustProxyHeadersOnly = false // the default; the switch must work without it
			router.Option.AccessController.AddTrustedProxy("203.0.113.0/24", "cdn")
			sep.SanitiseClientIPHeaders = tc.endpointOn
			router.Option.SanitiseClientIPHeaders = tc.globalOn

			var seen http.Header
			router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
				seen = r.Header.Clone()
				w.WriteHeader(299)
				return true
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
			r.RemoteAddr = tc.remote
			for _, h := range spoofed {
				r.Header.Set(h, "10.0.0.5")
			}
			router.handleNonTLSRequest(w, r, sep)
			if w.Code != 299 {
				t.Fatalf("got %d", w.Code)
			}
			for _, h := range spoofed {
				if got := seen.Get(h) != ""; got == tc.wantStripped {
					t.Errorf("%s present=%v, want present=%v", h, got, !tc.wantStripped)
				}
			}
		})
	}
}
