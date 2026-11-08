package dynamicproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

// An endpoint config written by a version without load balancing options.
// It must load unchanged and behave exactly like before.
const oldFormatEndpointConfig = `{
	"ProxyType": 0,
	"RootOrMatchingDomain": "app.example.com",
	"MatchingDomainAlias": [],
	"ActiveOrigins": [
		{"OriginIpOrDomain": "192.168.1.10:8080", "RequireTLS": false, "SkipCertValidations": false, "SkipWebSocketOriginCheck": true, "Weight": 3, "MaxConn": 0, "RespTimeout": 0},
		{"OriginIpOrDomain": "192.168.1.11:8443", "RequireTLS": true, "SkipCertValidations": true, "SkipWebSocketOriginCheck": false, "Weight": 1, "MaxConn": 64, "RespTimeout": 5000},
		{"OriginIpOrDomain": "192.168.1.12:8080", "RequireTLS": false, "SkipCertValidations": false, "SkipWebSocketOriginCheck": false, "Weight": 0, "MaxConn": 0, "RespTimeout": 0}
	],
	"InactiveOrigins": [],
	"UseStickySession": false,
	"UseActiveLoadBalance": false,
	"Disabled": false,
	"VirtualDirectories": [],
	"DisableUptimeMonitor": false,
	"UptimeMonitorURI": "/health"
}`

func TestOldEndpointConfigKeepsHistoricalBehavior(t *testing.T) {
	var ep ProxyEndpoint
	if err := json.Unmarshal([]byte(oldFormatEndpointConfig), &ep); err != nil {
		t.Fatalf("old config no longer loads: %v", err)
	}
	if ep.LoadBalanceConfig != nil {
		t.Fatal("a config without load balancing options must leave LoadBalanceConfig nil")
	}
	if got := ep.LoadBalanceConfig.GetAlgorithm(); got != loadbalance.AlgoRandom {
		t.Fatalf("default algorithm %q", got)
	}
	if len(ep.ActiveOrigins) != 3 || ep.ActiveOrigins[1].MaxConn != 64 || ep.ActiveOrigins[1].RespTimeout != 5000 {
		t.Fatalf("existing upstream fields not preserved: %+v", ep.ActiveOrigins[1])
	}
	for _, u := range ep.ActiveOrigins {
		if u.Draining || u.MaxInFlight != 0 || u.HealthCheck != nil {
			t.Fatalf("new upstream fields must default to off: %+v", u)
		}
	}

	// Selection: weighted random, the fallback (weight 0) is never used while others are up
	lb := &loadbalance.RouteManager{}
	opt := &loadbalance.SelectOptions{Config: ep.LoadBalanceConfig}
	counts := map[string]int{}
	for i := 0; i < 8000; i++ {
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		u, err := lb.SelectUpstream(nil, r, ep.ActiveOrigins, opt)
		if err != nil {
			t.Fatal(err)
		}
		counts[u.OriginIpOrDomain]++
	}
	if counts["192.168.1.12:8080"] != 0 {
		t.Fatalf("fallback upstream used: %v", counts)
	}
	if share := float64(counts["192.168.1.10:8080"]) / 8000; share < 0.70 || share > 0.80 {
		t.Fatalf("weight 3:1 should give about 75%%, got %.2f (%v)", share, counts)
	}

	// Serve path with a nil config adds no behavior except counting
	res := lb.ServeWithRetry(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), ep.ActiveOrigins, ep.ActiveOrigins[0], opt,
		func(w http.ResponseWriter, r *http.Request, u *loadbalance.Upstream) (int, error) { return 204, nil })
	if res.Status != 204 || res.Attempts != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestNewEndpointFieldsRoundTrip(t *testing.T) {
	var ep ProxyEndpoint
	if err := json.Unmarshal([]byte(oldFormatEndpointConfig), &ep); err != nil {
		t.Fatal(err)
	}
	ep.LoadBalanceConfig = &loadbalance.Config{
		Algorithm:          loadbalance.AlgoHeaderHash,
		HashKey:            "X-Tenant",
		ActiveHealthCheck:  &loadbalance.ActiveHealthCheck{Enabled: true, Path: "/healthz", IntervalSeconds: 15},
		PassiveHealthCheck: &loadbalance.PassiveHealthCheck{Enabled: true, FailThreshold: 5},
		Retry:              &loadbalance.RetryConfig{Enabled: true, MaxRetries: 2, ExtraMethods: []string{"POST"}},
		SlowStartSeconds:   45,
	}
	ep.ActiveOrigins[0].Draining = true
	ep.ActiveOrigins[0].MaxInFlight = 10

	clone := ep.Clone()
	js, _ := json.Marshal(clone)
	for _, want := range []string{`"Algorithm":"header_hash"`, `"HashKey":"X-Tenant"`, `"IntervalSeconds":15`, `"SlowStartSeconds":45`, `"Draining":true`, `"MaxInFlight":10`} {
		if !strings.Contains(string(js), want) {
			t.Errorf("serialized config is missing %s", want)
		}
	}
	// Runtime state must never reach the config file
	if strings.Contains(string(js), "inflight") {
		t.Error("runtime state was serialized")
	}
	if clone.LoadBalanceConfig == ep.LoadBalanceConfig || clone.LoadBalanceConfig.Retry.MaxRetries != 2 {
		t.Error("clone must be a deep copy")
	}
}

func TestHealthChecksFollowRouterLifecycle(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	lb := &loadbalance.RouteManager{}
	defer lb.StopAllHealthChecks()
	router := &Router{loadBalancer: lb, ProxyEndpoints: &sync.Map{}}
	ep := &ProxyEndpoint{
		RootOrMatchingDomain: "hc.example.com",
		ActiveOrigins:        []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(backend.URL, "http://"), Weight: 1}},
		LoadBalanceConfig:    &loadbalance.Config{ActiveHealthCheck: &loadbalance.ActiveHealthCheck{Enabled: true, IntervalSeconds: 1}},
		parent:               router,
	}

	ep.UpdateToRuntime() //Router not running yet: no checks
	if lb.HealthCheckGroupCount() != 0 {
		t.Fatal("health checks started while the router is stopped")
	}

	router.Running = true
	router.syncAllHealthChecks() //What StartProxyService does
	if lb.HealthCheckGroupCount() != 1 {
		t.Fatal("health checks not started with the router")
	}
	ep.UpdateToRuntime() //Unchanged config: still one group
	if lb.HealthCheckGroupCount() != 1 {
		t.Fatal("unexpected group count after update")
	}

	router.stopAllHealthChecks() //What StopProxyService does
	if lb.HealthCheckGroupCount() != 0 {
		t.Fatal("health checks survived the router stop")
	}

	router.syncAllHealthChecks() //Restart
	if lb.HealthCheckGroupCount() != 1 {
		t.Fatal("health checks not restarted")
	}
	if err := ep.Remove(); err != nil || lb.HealthCheckGroupCount() != 0 {
		t.Fatal("health checks survived the endpoint removal")
	}

	ep.UpdateToRuntime()
	ep.Disabled = true
	ep.UpdateToRuntime() //Disabled endpoint: stopped
	if lb.HealthCheckGroupCount() != 0 {
		t.Fatal("disabled endpoint keeps checking")
	}
}
