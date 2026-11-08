package dynamicproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

// Upstream #403 (Uptime Kuma): external monitors probe with HEAD, with keep-alive connections and against names
// that have no rule. HEAD must be proxied like GET (status and headers, no body), keep-alive must work for
// repeated probes, and an unknown host must answer with a clean HTTP status instead of closing or hanging.
func TestMonitorStyleProbes(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = nil
	router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: router.Option.Logger})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "yes")
		w.Write([]byte("hello body"))
	}))
	defer backend.Close()
	sep.ProxyType = ProxyTypeHost
	sep.BypassGlobalTLS = true
	sep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(backend.URL, "http://"), Weight: 1}}
	prepared, err := router.PrepareProxyRoute(sep)
	if err != nil {
		t.Fatal(err)
	}
	prepared.parent = router
	if err := router.AddProxyRouteToRuntime(prepared); err != nil {
		t.Fatal(err)
	}
	router.Root = &ProxyEndpoint{}
	proxy := httptest.NewServer(http.HandlerFunc(router.handlePort80Request))
	defer proxy.Close()

	client := &http.Client{} // keep-alive enabled
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("HEAD", proxy.URL+"/", nil)
		req.Host = "app.example.com"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HEAD %d: %v", i, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("X-Backend") != "yes" || len(b) != 0 {
			t.Fatalf("HEAD %d: status=%d backend-header=%q body=%q", i, resp.StatusCode, resp.Header.Get("X-Backend"), b)
		}
	}
	req, _ := http.NewRequest("GET", proxy.URL+"/", nil)
	req.Host = "app.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "hello body" {
		t.Fatalf("GET: %d %q", resp.StatusCode, b)
	}

	// Unknown host: some definite HTTP answer (not a connection error, not 2xx)
	req, _ = http.NewRequest("GET", proxy.URL+"/", nil)
	req.Host = "nobody.example.org"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("unknown host: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Fatalf("unknown host answered %d", resp.StatusCode)
	}
}
