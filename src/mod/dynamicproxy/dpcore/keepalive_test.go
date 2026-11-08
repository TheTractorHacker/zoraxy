package dpcore

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// countConnections proxies n sequential requests and returns how many TCP connections
// the upstream accepted.
func countConnections(t *testing.T, opts *DpcoreOptions, n int, forceHTTP11 bool) int32 {
	t.Helper()
	var conns int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	upstream.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&conns, 1)
		}
	}
	upstream.Start()
	t.Cleanup(upstream.Close)

	target, _ := url.Parse(upstream.URL)
	core := NewDynamicProxyCore(target, "", opts)
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://front.example.com/", nil)
		rw := httptest.NewRecorder()
		status, err := core.ProxyHTTP(rw, req, &ResponseRewriteRuleSet{
			ProxyDomain:  target.Host,
			OriginalHost: "front.example.com",
			ForceHTTP11:  forceHTTP11,
		})
		if err != nil || status != http.StatusOK {
			t.Fatalf("request %d: status=%d err=%v", i, status, err)
		}
	}
	return atomic.LoadInt32(&conns)
}

// Upstream #1343: upstreams that close the connection after every response (or race with
// the idle pool) need connection reuse switched off per upstream.
func TestDisableKeepAliveOpensOneConnectionPerRequest(t *testing.T) {
	if got := countConnections(t, &DpcoreOptions{}, 3, false); got != 1 {
		t.Fatalf("default: %d connections for 3 requests, want 1 (reuse)", got)
	}
	if got := countConnections(t, &DpcoreOptions{DisableKeepAlive: true}, 3, false); got != 3 {
		t.Fatalf("DisableKeepAlive: %d connections for 3 requests, want 3", got)
	}
	// still honoured on the per request clone made for ForceHTTP11
	if got := countConnections(t, &DpcoreOptions{DisableKeepAlive: true}, 3, true); got != 3 {
		t.Fatalf("DisableKeepAlive+ForceHTTP11: %d connections, want 3", got)
	}
}
