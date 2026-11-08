package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/dynamicproxy/redirection"
	"imuslab.com/zoraxy/mod/eventsystem"
	"imuslab.com/zoraxy/mod/info/logger"
)

// newNonTLSTestRouter builds a Router with a real access controller, redirect
// table and ProxyHandler mux. Requests that survive the protection chain are
// answered by pluginRouteHook with 299 so no upstream is needed.
func newNonTLSTestRouter(t *testing.T) (*Router, *ProxyEndpoint, *access.AccessRule) {
	t.Helper()
	router := newTestRateLimitRouter(t, false)
	lg, _ := logger.NewFmtLogger()
	router.Option.Logger = lg
	eventsystem.InitEventSystem(lg)
	router.Option.WebDirectory = t.TempDir()
	rt, err := redirection.NewRuleTable(filepath.Join(t.TempDir(), "redirect"), false, false, lg)
	if err != nil {
		t.Fatal(err)
	}
	router.Option.RedirectRuleTable = rt
	router.ProxyEndpoints = &sync.Map{}
	router.mux = &ProxyHandler{Parent: router}
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
		w.WriteHeader(299)
		return true
	}
	sep := &ProxyEndpoint{RootOrMatchingDomain: "app.example.com", parent: router, AuthenticationProvider: &AuthenticationProvider{}}
	rule, err := router.Option.AccessController.GetAccessRuleByID("default")
	if err != nil {
		t.Fatal(err)
	}
	return router, sep, rule
}

func serveNonTLS(router *Router, sep *ProxyEndpoint, target string, remote string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remote
	router.handleNonTLSRequest(w, r, sep)
	return w
}

func TestNonTLS_PluginRoutingConsulted(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.1:1000")
	if w.Code != 299 {
		t.Fatalf("plugin routing was not consulted on the non-TLS path, got %d", w.Code)
	}
}

func TestNonTLS_BlacklistedIPBlocked(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.9", "test")
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.9:1000"); w.Code != 403 {
		t.Fatalf("blacklisted IP got %d, want 403", w.Code)
	}
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.10:1000"); w.Code != 299 {
		t.Fatalf("clean IP got %d, want 299", w.Code)
	}
}

func TestNonTLS_ExploitDetectorApplies(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.BlockCommonExploits = true
	sep.MitigationAction = 1
	sep.InitializeExploitDetector()
	w := serveNonTLS(router, sep, "http://app.example.com/?q=union+all+select+1", "198.51.100.1:1000")
	if w.Code != 403 {
		t.Fatalf("exploit request got %d, want 403", w.Code)
	}
}

func TestNonTLS_RedirectRuleApplies(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	if err := router.Option.RedirectRuleTable.AddRedirectRule("app.example.com/old", "https://new.example.org/", false, 301, false, "all"); err != nil {
		t.Fatal(err)
	}
	w := serveNonTLS(router, sep, "http://app.example.com/old", "198.51.100.1:1000")
	if w.Code != 301 || w.Header().Get("Location") != "https://new.example.org/" {
		t.Fatalf("redirect not applied: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestNonTLS_SpecialRoutingRuleApplies(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.AddRoutingRules(&RoutingRule{
		ID:      "acme-test",
		Enabled: true,
		MatchRule: func(r *http.Request) bool {
			return r.URL.Path == "/.well-known/acme-challenge/tok"
		},
		RoutingHandler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(218) },
	})
	w := serveNonTLS(router, sep, "http://app.example.com/.well-known/acme-challenge/tok", "198.51.100.1:1000")
	if w.Code != 218 {
		t.Fatalf("special routing rule (ACME) not honoured on non-TLS path, got %d", w.Code)
	}
}
