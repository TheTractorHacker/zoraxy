package dynamicproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/cluster"
)

func newHealthTestRouter(health *cluster.HealthEndpoint) *Router {
	return &Router{
		Option:         &RouterOption{Health: health},
		ProxyEndpoints: &sync.Map{},
		Root:           &ProxyEndpoint{},
	}
}

func TestHealthEndpointServedBeforeHostRouting(t *testing.T) {
	router := newHealthTestRouter(cluster.NewHealthEndpoint("3.3.5"))
	router.ProxyEndpoints.Store("a.example.com", &ProxyEndpoint{RootOrMatchingDomain: "a.example.com"})
	router.ProxyEndpoints.Store("b.example.com", &ProxyEndpoint{RootOrMatchingDomain: "b.example.com", Disabled: true})
	router.Running = true

	downstream := 0
	h := router.withHealth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstream++
		w.WriteHeader(http.StatusTeapot)
	}))

	// any Host header, including one that matches nothing, gets an answer
	for _, host := range []string{"unknown.invalid", "a.example.com", "", "10.0.0.1:443"} {
		r := httptest.NewRequest("GET", "/.zoraxy/health", nil)
		r.Host = host
		r.RemoteAddr = "192.0.2.1:5000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("host %q: want 200 got %d", host, w.Code)
		}
		var body map[string]any
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["proxyRunning"] != true || body["activeEndpoints"] != float64(1) || body["version"] != "3.3.5" {
			t.Fatalf("body %v", body)
		}
	}
	if downstream != 0 {
		t.Fatal("health request reached host routing")
	}

	// 503 when the router is stopped
	router.Running = false
	r := httptest.NewRequest("GET", "/.zoraxy/health", nil)
	r.RemoteAddr = "192.0.2.1:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stopped router: want 503 got %d", w.Code)
	}
}

func TestHealthDoesNotShadowOtherRoutes(t *testing.T) {
	router := newHealthTestRouter(cluster.NewHealthEndpoint("1"))
	router.Running = true
	downstream := 0
	h := router.withHealth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstream++
	}))
	paths := []string{
		"/.zoraxy/captcha/verify",
		"/.well-known/acme-challenge/token123",
		"/.zoraxy/healthz",
		"/.zoraxy/health/",
		"/health",
		"/",
	}
	for _, p := range paths {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	if downstream != len(paths) {
		t.Fatalf("health handler shadowed %d of %d other routes", len(paths)-downstream, len(paths))
	}
}

func TestHealthDisabledOrAbsentFallsThrough(t *testing.T) {
	for name, health := range map[string]*cluster.HealthEndpoint{
		"nil":      nil,
		"disabled": func() *cluster.HealthEndpoint { h := cluster.NewHealthEndpoint("1"); h.Configure(nil, true); return h }(),
	} {
		router := newHealthTestRouter(health)
		router.Running = true
		called := false
		h := router.withHealth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/.zoraxy/health", nil))
		if !called {
			t.Errorf("%s: request must continue to normal routing", name)
		}
	}
}

func TestHealthAllowListUsesPeerAddressNotHeaders(t *testing.T) {
	health := cluster.NewHealthEndpoint("1")
	health.Configure([]string{"10.0.0.0/8"}, false)
	router := newHealthTestRouter(health)
	router.Running = true
	h := router.withHealth(http.NotFoundHandler())

	r := httptest.NewRequest("GET", "/.zoraxy/health", nil)
	r.RemoteAddr = "203.0.113.5:1"
	r.Header.Set("X-Forwarded-For", "10.1.1.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("spoofed X-Forwarded-For bypassed the allow list: %d", w.Code)
	}
	r.RemoteAddr = "10.2.2.2:1"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("allowed peer got %d", w.Code)
	}
}

func TestSessionSecretSelection(t *testing.T) {
	if sessionSecretFor(&RouterOption{HostUUID: "uuid"}) != "uuid" {
		t.Fatal("default must stay the host UUID")
	}
	if sessionSecretFor(&RouterOption{HostUUID: "uuid", SessionSecret: "derived"}) != "derived" {
		t.Fatal("session secret ignored")
	}
}

// The port-80 listener has its own handler; the health path must be answered
// there too, before any redirect or host routing.
func TestHealthServedOnPort80Handler(t *testing.T) {
	router := newHealthTestRouter(cluster.NewHealthEndpoint("test"))
	router.Running = true
	router.Root = &ProxyEndpoint{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/.zoraxy/health", nil)
	r.RemoteAddr = "198.51.100.7:5555"
	router.handlePort80Request(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("health on the port-80 handler got %d, want 200 (body %q)", w.Code, w.Body.String())
	}
}
