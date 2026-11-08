package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Upstream #386 / #490 / #537: with a proxy rule for the host, "force HTTPS
// redirect" off and no plain-HTTP bypass, the port 80 listener answered every
// request (including the Let's Encrypt HTTP-01 challenge) with 400.
func TestPort80ServesACMEChallengeForExistingProxyRule(t *testing.T) {
	for _, forceRedirect := range []bool{false, true} {
		router, sep, _ := newNonTLSTestRouter(t)
		router.Option.ForceHttpsRedirect = forceRedirect
		router.ProxyEndpoints.Store("app.example.com", sep)
		router.AddRoutingRules(&RoutingRule{
			ID:      "acme-test",
			Enabled: true,
			MatchRule: func(r *http.Request) bool {
				return r.URL.Path == "/.well-known/acme-challenge/tok"
			},
			RoutingHandler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(218) },
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com/.well-known/acme-challenge/tok", nil)
		router.handlePort80Request(w, r)
		if w.Code != 218 {
			t.Fatalf("forceRedirect=%v: ACME challenge not served on port 80, got %d", forceRedirect, w.Code)
		}

		// Other paths keep the old behaviour
		w = httptest.NewRecorder()
		r = httptest.NewRequest(http.MethodGet, "http://app.example.com/other", nil)
		router.handlePort80Request(w, r)
		if forceRedirect && w.Code != http.StatusTemporaryRedirect {
			t.Fatalf("expected redirect to https, got %d", w.Code)
		}
		if !forceRedirect && w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for non-TLS-enabled host, got %d", w.Code)
		}
	}
}
