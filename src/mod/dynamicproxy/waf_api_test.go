package dynamicproxy

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

func TestAPIProtectionThroughProxyHandler(t *testing.T) {
	deep := strings.Repeat("[", 30) + strings.Repeat("]", 30)
	type tc struct {
		name   string
		st     *waf.State
		set    func(*ProxyEndpoint)
		body   string
		want   int
		upHits int32
	}
	apiBlock := &waf.APIConfig{Mode: waf.APIModeBlock}
	apiLog := &waf.APIConfig{Mode: waf.APIModeLog}
	cases := []tc{
		{"off by default", nil, nil, deep, 200, 1},
		{"endpoint block", nil, func(ep *ProxyEndpoint) { ep.WAFAPI = apiBlock }, deep, 400, 0},
		{"endpoint block, fine body", nil, func(ep *ProxyEndpoint) { ep.WAFAPI = apiBlock }, `{"a":1}`, 200, 1},
		{"endpoint log", nil, func(ep *ProxyEndpoint) { ep.WAFAPI = apiLog }, deep, 200, 1},
		{"policy default inherited", mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeOff, API: apiBlock}), nil, deep, 400, 0},
		{"policy disabled", mustState(t, waf.Policy{DefaultMode: waf.ModeBlock, API: apiBlock}), nil, deep, 200, 1},
		{"endpoint turns it off", mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeOff, API: apiBlock}),
			func(ep *ProxyEndpoint) { ep.WAFAPI = &waf.APIConfig{Mode: waf.APIModeOff} }, deep, 200, 1},
		{"WAF source off disables it", mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock, API: apiBlock}),
			func(ep *ProxyEndpoint) { ep.WAFSource = waf.SourceOff }, deep, 200, 1},
		{"profile", mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeOff}, waf.Profile{Name: "Api", Mode: waf.ModeDetectionOnly, API: apiBlock}),
			func(ep *ProxyEndpoint) { ep.WAFSource = waf.SourceProfile; ep.WAFProfile = "Api" }, deep, 400, 0},
		{"works together with the WAF (custom block)", nil, func(ep *ProxyEndpoint) {
			ep.WAF = &waf.Config{Mode: waf.ModeBlock}
			ep.WAFAPI = apiBlock
		}, deep, 400, 0},
		{"trusted path bypass", mustState(t, waf.Policy{Enabled: true, DefaultMode: waf.ModeBlock, API: apiBlock, TrustedPaths: []waf.TrustedPath{{Path: "/x"}}}), nil, deep, 200, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, hits, last := newCentralWAFTestProxy(t, c.st, c.set)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, wafReq("POST", "/x", []byte(c.body), map[string]string{"Content-Type": "application/json"}))
			if w.Code != c.want {
				t.Fatalf("status %d want %d (%s)", w.Code, c.want, w.Body.String())
			}
			if atomic.LoadInt32(hits) != c.upHits {
				t.Fatalf("upstream hits %d want %d", *hits, c.upHits)
			}
			if c.upHits == 1 && string(*last) != c.body {
				t.Fatalf("upstream received %q", *last)
			}
			if c.want == 400 && strings.Contains(w.Body.String(), "[[[[") {
				t.Fatal("block page echoes the body")
			}
		})
	}
}

func TestAPIProtectionBlockCountsAsWAFBlock(t *testing.T) {
	var mu sync.Mutex
	var observed []string
	old := BlockObserver
	BlockObserver = func(site, kind string) { mu.Lock(); observed = append(observed, site+"/"+kind); mu.Unlock() }
	defer func() { BlockObserver = old }()

	h, _, _ := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) { ep.WAFAPI = &waf.APIConfig{Mode: waf.APIModeBlock} })
	deep := strings.Repeat("[", 30) + strings.Repeat("]", 30)
	h.ServeHTTP(httptest.NewRecorder(), wafReq("POST", "/x", []byte(deep), map[string]string{"Content-Type": "application/json"}))
	mu.Lock()
	n := len(observed)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("block observer calls: %d", n)
	}

	// log mode: counted as an event but not as a block
	h, _, _ = newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) { ep.WAFAPI = &waf.APIConfig{Mode: waf.APIModeLog} })
	h.ServeHTTP(httptest.NewRecorder(), wafReq("POST", "/x", []byte(deep), map[string]string{"Content-Type": "application/json"}))
	mu.Lock()
	n = len(observed)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("log mode counted as a block: %d", n)
	}
}

func TestAPIProtectionBodyReplayThroughProxy(t *testing.T) {
	body := bytes.Repeat([]byte(`{"k":"v","n":[1,2,3]} `), 5000)
	body = append([]byte("["), append(bytes.TrimSuffix(bytes.ReplaceAll(body, []byte(" "), []byte(",")), []byte(",")), ']')...)
	h, _, last := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) {
		ep.WAFAPI = &waf.APIConfig{Mode: waf.APIModeBlock, Limits: &waf.APILimits{JSONMaxArrayLen: -1, MaxBodyBytes: 4 << 20}}
		ep.WAF = &waf.Config{Mode: waf.ModeDetectionOnly, MaxBodyBytes: 1 << 20}
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wafReq("POST", "/x", body, map[string]string{"Content-Type": "application/json"}))
	if w.Code != 200 || !bytes.Equal(*last, body) {
		t.Fatalf("status %d, upstream body identical=%v (%d vs %d bytes)", w.Code, bytes.Equal(*last, body), len(*last), len(body))
	}
}

func TestAPIProtectionCoverageReportsMode(t *testing.T) {
	h, _, _ := newCentralWAFTestProxy(t, nil, func(ep *ProxyEndpoint) {
		ep.WAFAPI = &waf.APIConfig{Mode: waf.APIModeLog, OpenAPI: &waf.OpenAPIConfig{Spec: "this is not a spec"}}
	})
	var found bool
	for _, c := range h.Parent.WAFCoverage() {
		if c.Endpoint == "waf.test" {
			found = true
			if c.APIMode != waf.APIModeLog || c.APIWarning == "" {
				t.Fatalf("coverage %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("endpoint missing from coverage")
	}
}
