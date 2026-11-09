package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/dynamicproxy/redirection"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/info/logger"
)

const respLeak = "<html><body>java.lang.RuntimeException: boom\n\tat com.acme.Foo.bar(Foo.java:42)\n\tat com.acme.Baz.run(Baz.java:7)\n\tat java.lang.Thread.run(Thread.java:748)\n</body></html>"

// newLeakProxy is newCentralWAFTestProxy with an upstream that returns a leaking page and a Server banner
func newLeakProxy(t testing.TB, st *waf.State, customise func(*ProxyEndpoint)) *ProxyHandler {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("Content-Length", strconv.Itoa(len(respLeak)))
		w.WriteHeader(500)
		w.Write([]byte(respLeak))
	}))
	t.Cleanup(upstream.Close)

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
	router.SetWAFState(st)
	ep := &ProxyEndpoint{
		RootOrMatchingDomain:   "leak.test",
		ProxyType:              ProxyTypeHost,
		ActiveOrigins:          []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(upstream.URL, "http://")}},
		DisableLogging:         true,
		AuthenticationProvider: &AuthenticationProvider{AuthMethod: AuthMethodNone},
	}
	if customise != nil {
		customise(ep)
	}
	prepared, err := router.PrepareProxyRoute(ep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := router.AddProxyRouteToRuntime(prepared); err != nil {
		t.Fatalf("add: %v", err)
	}
	return &ProxyHandler{Parent: router}
}

func serveLeak(h *ProxyHandler) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := wafReq("GET", "/page", nil, nil)
	r.Host = "leak.test"
	r.URL.Host = "leak.test"
	h.ServeHTTP(w, r)
	return w
}

// Through the real router: policy default, profile override, endpoint override, BlockObserver without abuse feed
func TestResponseProtectionThroughRouter(t *testing.T) {
	var blocks int
	old := BlockObserver
	BlockObserver = func(site, kind string) { blocks++ }
	defer func() { BlockObserver = old }()

	pol := waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock,
		Response: &waf.ResponseConfig{Groups: map[string]string{waf.GroupStackTrace: waf.RespActionLog, waf.GroupHeaders: waf.RespActionStrip}}}

	// policy: log -> original bytes, banner stripped
	h := newLeakProxy(t, mustState(t, pol), nil)
	w := serveLeak(h)
	if w.Code != 500 || w.Body.String() != respLeak {
		t.Fatalf("log must forward the original response, got %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("Server") != "" {
		t.Fatal("Server banner not stripped")
	}

	// endpoint override to block
	h = newLeakProxy(t, mustState(t, pol), func(ep *ProxyEndpoint) {
		ep.WAFExtra = &waf.Overrides{Response: &waf.ResponseConfig{Groups: map[string]string{waf.GroupStackTrace: waf.RespActionBlock}}}
	})
	w = serveLeak(h)
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "RuntimeException") {
		t.Fatalf("block: %d %q", w.Code, w.Body.String())
	}
	if blocks != 1 {
		t.Fatalf("BlockObserver calls: %d", blocks)
	}

	// profile with block, endpoint turns the group off again
	prof := waf.Profile{Name: "Leaky", Mode: waf.ModeBlock, Response: &waf.ResponseConfig{Groups: map[string]string{waf.GroupStackTrace: waf.RespActionBlock}}}
	h = newLeakProxy(t, mustState(t, pol, prof), func(ep *ProxyEndpoint) { ep.WAFSource = waf.SourceProfile; ep.WAFProfile = "Leaky" })
	if w = serveLeak(h); w.Code != http.StatusBadGateway {
		t.Fatalf("profile block: %d", w.Code)
	}
	h = newLeakProxy(t, mustState(t, pol, prof), func(ep *ProxyEndpoint) {
		ep.WAFSource = waf.SourceProfile
		ep.WAFProfile = "Leaky"
		ep.WAFExtra = &waf.Overrides{Response: &waf.ResponseConfig{Groups: map[string]string{waf.GroupStackTrace: waf.RespActionOff}}}
	})
	if w = serveLeak(h); w.Code != 500 || w.Body.String() != respLeak {
		t.Fatalf("endpoint off: %d", w.Code)
	}

	// WAF off for the endpoint: nothing happens, banner stays
	h = newLeakProxy(t, mustState(t, pol), func(ep *ProxyEndpoint) { ep.WAFSource = waf.SourceOff })
	if w = serveLeak(h); w.Header().Get("Server") == "" || w.Body.String() != respLeak {
		t.Fatal("WAF off must not inspect responses")
	}
	// no response settings at all: no guard, no cost
	h = newLeakProxy(t, mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock}), nil)
	ep, _ := h.Parent.LoadProxy("leak.test")
	if ep.wafRT.Load().resp != nil || h.Parent.responseGuard(nil, ep) != nil {
		t.Fatal("a guard exists without response settings")
	}
}
