package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/metrics"
)

func scrapeText(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	var b strings.Builder
	if err := reg.Write(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestMetricsHooksOnRequestChain(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	reg := metrics.New()
	router.Option.Metrics = reg
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.9", "test")

	// disabled: nothing recorded, requests still served
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.1:1000"); w.Code != 299 {
		t.Fatalf("got %d", w.Code)
	}
	if reg.EndpointCount() != 0 {
		t.Fatal("recorded while disabled")
	}

	reg.SetEnabled(true)
	serveNonTLS(router, sep, "http://app.example.com/a?secret=1", "198.51.100.1:1000")
	serveNonTLS(router, sep, "http://app.example.com/b", "198.51.100.9:1000") //blocked 403
	out := scrapeText(t, reg)
	for _, want := range []string{
		`zoraxy_http_requests_total{endpoint="app.example.com",status_class="2xx",method="GET"} 1`,
		`zoraxy_http_requests_total{endpoint="app.example.com",status_class="4xx",method="GET"} 1`,
		`zoraxy_access_blocked_total{endpoint="app.example.com",reason="blacklist"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// raw paths, queries and client IPs never become labels
	for _, bad := range []string{"/a", "secret", "198.51.100"} {
		if strings.Contains(out, bad) {
			t.Fatalf("label leak %q in:\n%s", bad, out)
		}
	}
}

func TestMetricsRateLimitAndDefaultSiteLabel(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	reg := metrics.New()
	reg.SetEnabled(true)
	router.Option.Metrics = reg
	sep.RequireRateLimit = true
	sep.RateLimit = 1
	sep.RateLimitBurst = 1
	limited := 0
	for i := 0; i < 5; i++ {
		w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.1:1000")
		if w.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("rate limit never triggered")
	}
	out := scrapeText(t, reg)
	if !strings.Contains(out, `zoraxy_ratelimit_rejected_total{endpoint="app.example.com",reason="limit"}`) {
		t.Fatalf("rate limit event missing:\n%s", out)
	}

	// unmatched host through the TLS handler mux is attributed to _default
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://unknown.invalid/x", nil)
	router.Root = &ProxyEndpoint{DefaultSiteOption: DefaultSite_TeaPot}
	router.mux.ServeHTTP(w, r)
	if !strings.Contains(scrapeText(t, reg), `endpoint="`+DefaultSiteMetricsLabel+`"`) {
		t.Fatal("default site label missing")
	}
}
