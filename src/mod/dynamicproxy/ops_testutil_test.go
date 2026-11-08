package dynamicproxy

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

// newOpsTestRouter returns a router whose ProxyHandler serves host app.example.com through the
// full TLS-path chain (ProxyHandler.ServeHTTP) to the given upstream.
func newOpsTestRouter(t *testing.T, upstream string) (*Router, *ProxyEndpoint) {
	t.Helper()
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = nil
	router.loadBalancer = &loadbalance.RouteManager{}
	sep.ProxyType = ProxyTypeHost
	sep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: upstream, Weight: 1}}
	if _, err := router.PrepareProxyRoute(sep); err != nil {
		t.Fatal(err)
	}
	router.ProxyEndpoints.Store("app.example.com", sep)
	return router, sep
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func serveOps(router *Router, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, target, nil)
	r.Host = "app.example.com"
	r.RemoteAddr = "198.51.100.1:1000"
	r.RequestURI = target
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	router.mux.ServeHTTP(w, r)
	return w
}
