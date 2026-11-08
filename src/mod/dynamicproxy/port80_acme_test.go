package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Upstream #537: the CA's HTTP-01 request must reach the ACME handler on port 80 whatever the redirect
// setting is and whether or not the host has a proxy rule; otherwise Let's Encrypt reports
// "Error getting validation data".
func TestPort80AnswersACMEChallengeBeforeRedirectOrRejection(t *testing.T) {
	for _, force := range []bool{true, false} {
		router, sep, _ := newNonTLSTestRouter(t)
		router.Option.ForceHttpsRedirect = force
		router.Option.Port = 443
		router.AddRoutingRules(&RoutingRule{
			ID: "acme-autorenew", Enabled: true,
			MatchRule: func(r *http.Request) bool {
				return len(r.URL.Path) > 28 && r.URL.Path[:28] == "/.well-known/acme-challenge/"
			},
			RoutingHandler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(218) },
		})
		router.ProxyEndpoints.Store(sep.RootOrMatchingDomain, sep) // host with a rule that does not allow plain HTTP

		for _, host := range []string{sep.RootOrMatchingDomain, "unknown.example.org"} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "http://"+host+"/.well-known/acme-challenge/tok123", nil)
			r.RemoteAddr = "198.51.100.1:1000"
			router.handlePort80Request(w, r)
			if w.Code != 218 {
				t.Errorf("forceRedirect=%v host=%s: challenge got %d (%s), want the ACME handler", force, host, w.Code, w.Header().Get("Location"))
			}
		}
	}
}
