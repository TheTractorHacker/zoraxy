package dynamicproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/dynamicproxy/redirection"
	"imuslab.com/zoraxy/mod/info/logger"
)

// Through the real request handler: if the upstream drops the connection after it
// started a chunked response, the client must see a failed transfer, not a body that
// looks complete.
func TestBrokenUpstreamResponseAbortsClientConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nchunk\r\n")
		buf.Flush()
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}))
	defer upstream.Close()

	router := newTestRateLimitRouter(t, false)
	lg, _ := logger.NewFmtLogger()
	router.Option.Logger = lg
	router.Option.WebDirectory = t.TempDir()
	rt, err := redirection.NewRuleTable(t.TempDir(), false, false, lg)
	if err != nil {
		t.Fatal(err)
	}
	router.Option.RedirectRuleTable = rt
	router.ProxyEndpoints = &sync.Map{}
	router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: lg})

	ep := &ProxyEndpoint{
		RootOrMatchingDomain:   "abort.test",
		ProxyType:              ProxyTypeHost,
		ActiveOrigins:          []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(upstream.URL, "http://")}},
		DisableLogging:         true,
		AuthenticationProvider: &AuthenticationProvider{AuthMethod: AuthMethodNone},
	}
	prepared, err := router.PrepareProxyRoute(ep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := router.AddProxyRouteToRuntime(prepared); err != nil {
		t.Fatalf("add: %v", err)
	}

	front := httptest.NewServer(&ProxyHandler{Parent: router})
	defer front.Close()

	req, _ := http.NewRequest("GET", front.URL+"/big.bin", nil)
	req.Host = "abort.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed before the body: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("truncated upstream response (%q) was delivered as a complete response", body)
	}
}
