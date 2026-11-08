package dynamicproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/dynamicproxy/redirection"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/info/logger"
)

// newWAFTestProxy wires a real Router + ProxyHandler in front of a recording
// upstream, with the given WAF config on the endpoint.
func newWAFTestProxy(t testing.TB, cfg *waf.Config) (*ProxyHandler, *int32, *[]byte) {
	h, hits, last := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) { ep.WAF = cfg })
	return h, hits, last
}

// newCentralWAFTestProxy is newWAFTestProxy with an optional central state
// (installed before the endpoint is prepared) and an endpoint customiser.
func newCentralWAFTestProxy(t testing.TB, st *waf.State, customise func(*ProxyEndpoint)) (*ProxyHandler, *int32, *[]byte) {
	t.Helper()
	var hits int32
	var lastBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		b, _ := io.ReadAll(r.Body)
		lastBody = b
		w.WriteHeader(200)
		w.Write([]byte("upstream-ok"))
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
	if st != nil {
		router.SetWAFState(st)
	}

	ep := &ProxyEndpoint{
		RootOrMatchingDomain:   "waf.test",
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
	return &ProxyHandler{Parent: router}, &hits, &lastBody
}

func wafReq(method, target string, body []byte, hdr map[string]string) *http.Request {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r := httptest.NewRequest(method, "http://waf.test"+target, rd)
	r.RemoteAddr = "198.51.100.9:50000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36")
	r.Header.Set("Accept", "*/*")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestWAFThroughProxyHandler(t *testing.T) {
	h, hits, last := newWAFTestProxy(t, &waf.Config{Mode: waf.ModeBlock})

	// attack: 403 with request id, upstream untouched, no rule leakage
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("GET", "/item?id=1%27%20OR%20%271%27%3D%271", nil, nil))
	if w.Code != 403 {
		t.Fatalf("attack should be 403, got %d", w.Code)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Error("blocked request must not reach upstream")
	}
	body := w.Body.String()
	if !strings.Contains(body, "Request ID: ") || w.Header().Get("X-Request-Id") == "" {
		t.Error("block page must carry the transaction id")
	}
	if strings.Contains(body, "942") || strings.Contains(strings.ToLower(body), "sql") && strings.Contains(body, "rule") {
		t.Error("block page leaks rule details")
	}
	if w.Header().Get("X-Zoraxy-WAF") != "" {
		t.Error("no WAF header may be exposed")
	}

	// clean JSON POST: body replayed byte for byte
	payload := []byte(`{"name":"Alice","note":"it's fine","n":[1,2,3]}`)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("POST", "/api/users", payload, map[string]string{"Content-Type": "application/json"}))
	if w.Code != 200 || !bytes.Equal(*last, payload) {
		t.Errorf("clean POST: code=%d upstream body=%q", w.Code, *last)
	}

	// big body (over the 128KiB default) passes through, intact
	big := bytes.Repeat([]byte("0123456789abcdef"), 20*1024) // 320 KiB
	w = httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("POST", "/upload", big, map[string]string{"Content-Type": "application/octet-stream"}))
	if w.Code != 200 || !bytes.Equal(*last, big) {
		t.Errorf("big body: code=%d upstream len=%d want %d", w.Code, len(*last), len(big))
	}

	// gRPC content type is never inspected
	grpc := []byte("\x00\x00\x00\x00\x05hello")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("POST", "/svc.Echo/Say?x=<script>", grpc, map[string]string{"Content-Type": "application/grpc"}))
	if w.Code != 200 || !bytes.Equal(*last, grpc) {
		t.Errorf("grpc: code=%d", w.Code)
	}
}

func TestWAFOffAndDetectionOnlyThroughProxyHandler(t *testing.T) {
	for _, cfg := range []*waf.Config{nil, {Mode: waf.ModeOff}, {Mode: waf.ModeDetectionOnly}} {
		h, hits, _ := newWAFTestProxy(t, cfg)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, wafReq("GET", "/item?id=1%27%20OR%20%271%27%3D%271", nil, nil))
		if w.Code != 200 || atomic.LoadInt32(hits) != 1 {
			t.Errorf("cfg=%+v: request must reach upstream, code=%d", cfg, w.Code)
		}
	}
}

func TestWAFInvalidCustomRulesRejectSave(t *testing.T) {
	router := &Router{Option: &RouterOption{}}
	ep := &ProxyEndpoint{RootOrMatchingDomain: "x.test", WAF: &waf.Config{Mode: waf.ModeBlock, CustomRules: `SecRule BROKEN`}}
	if _, err := router.PrepareProxyRoute(ep); err == nil {
		t.Error("invalid custom rules must reject the route preparation")
	}
}

/* Benchmarks: go test ./mod/dynamicproxy -run xxx -bench WAF -benchmem */

func benchWAF(b *testing.B, cfg *waf.Config, method, target string, payload []byte, hdr map[string]string) {
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	h := newBenchProxy(b, cfg, upstream.URL)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, wafReq(method, target, payload, hdr))
	}
}

func newBenchProxy(b *testing.B, cfg *waf.Config, upstreamURL string) *ProxyHandler {
	router := newTestRateLimitRouter(b, false)
	lg, _ := logger.NewFmtLogger()
	router.Option.Logger = lg
	router.Option.WebDirectory = b.TempDir()
	rt, err := redirection.NewRuleTable(b.TempDir(), false, false, lg)
	if err != nil {
		b.Fatal(err)
	}
	router.Option.RedirectRuleTable = rt
	router.ProxyEndpoints = &sync.Map{}
	router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: lg})
	ep := &ProxyEndpoint{
		RootOrMatchingDomain:   "waf.test",
		ProxyType:              ProxyTypeHost,
		ActiveOrigins:          []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(upstreamURL, "http://")}},
		DisableLogging:         true,
		AuthenticationProvider: &AuthenticationProvider{AuthMethod: AuthMethodNone},
		WAF:                    cfg,
	}
	prepared, err := router.PrepareProxyRoute(ep)
	if err != nil {
		b.Fatal(err)
	}
	router.AddProxyRouteToRuntime(prepared)
	return &ProxyHandler{Parent: router}
}

var jsonPayload = []byte(`{"user":{"name":"Alice Example","email":"alice@example.com"},"items":[{"id":1,"qty":2},{"id":2,"qty":1}],"note":"please deliver after 5pm"}`)
var jsonHdr = map[string]string{"Content-Type": "application/json"}

func BenchmarkProxyGET_WAFOff(b *testing.B) {
	benchWAF(b, nil, "GET", "/index.html?page=2&sort=asc", nil, nil)
}
func BenchmarkProxyGET_WAFPL1Block(b *testing.B) {
	benchWAF(b, &waf.Config{Mode: waf.ModeBlock}, "GET", "/index.html?page=2&sort=asc", nil, nil)
}
func BenchmarkProxyPOSTJSON_WAFOff(b *testing.B) {
	benchWAF(b, nil, "POST", "/api/orders", jsonPayload, jsonHdr)
}
func BenchmarkProxyPOSTJSON_WAFPL1Block(b *testing.B) {
	benchWAF(b, &waf.Config{Mode: waf.ModeBlock}, "POST", "/api/orders", jsonPayload, jsonHdr)
}
func BenchmarkProxyAttack_WAFPL1Block(b *testing.B) {
	benchWAF(b, &waf.Config{Mode: waf.ModeBlock}, "GET", "/item?id=1%27%20OR%20%271%27%3D%271", nil, nil)
}
