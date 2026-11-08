package loadbalance

import (
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPassiveEjectionAndSlowStart(t *testing.T) {
	m, clk := newTestManager()
	ups := mkUpstreams(1, 1)
	bad := ups[0]
	cfg := &Config{
		PassiveHealthCheck: &PassiveHealthCheck{Enabled: true, FailThreshold: 3, CooldownSeconds: 30},
		SlowStartSeconds:   20,
	}
	p, _ := cfg.passive()

	// Two failures then a success: counter resets, no ejection
	bad.reportPassive(p, true, clk.Now())
	bad.reportPassive(p, true, clk.Now())
	bad.reportPassive(p, false, clk.Now())
	if !bad.isHealthy(clk.Now()) {
		t.Fatal("ejected too early")
	}

	// Three in a row eject
	for i := 0; i < 2; i++ {
		if bad.reportPassive(p, true, clk.Now()) {
			t.Fatal("ejected before the threshold")
		}
	}
	if !bad.reportPassive(p, true, clk.Now()) {
		t.Fatal("expected ejection on the third consecutive failure")
	}
	if bad.isHealthy(clk.Now()) {
		t.Fatal("ejected upstream reported healthy")
	}
	if st := bad.GetState(clk.Now(), cfg).State; st != "ejected" {
		t.Fatalf("state %q", st)
	}
	counts := pickN(t, m, ups, cfg, 200, nil)
	if counts[bad.OriginIpOrDomain] != 0 {
		t.Fatalf("ejected upstream got traffic: %v", counts)
	}

	// Cooldown not over
	clk.Advance(29 * time.Second)
	if bad.isHealthy(clk.Now()) {
		t.Fatal("recovered before the cooldown ended")
	}

	// Cooldown over: back in rotation at the lowest weight, ramping up
	clk.Advance(1 * time.Second)
	if !bad.isHealthy(clk.Now()) {
		t.Fatal("still ejected after the cooldown")
	}
	if f := bad.slowStartFactor(clk.Now(), cfg.slowStart()); f > 0.11 {
		t.Fatalf("slow start should begin at the minimum, got %.2f", f)
	}
	if st := bad.GetState(clk.Now(), cfg).State; st != "slow_start" {
		t.Fatalf("state %q", st)
	}
	clk.Advance(10 * time.Second)
	if f := bad.slowStartFactor(clk.Now(), cfg.slowStart()); f < 0.5 || f > 0.6 {
		t.Fatalf("halfway factor %.2f", f)
	}
	clk.Advance(10 * time.Second)
	if f := bad.slowStartFactor(clk.Now(), cfg.slowStart()); f != 1 {
		t.Fatalf("slow start should be finished, got %.2f", f)
	}
	if st := bad.GetState(clk.Now(), cfg).State; st != "healthy" {
		t.Fatalf("state %q", st)
	}

	// A failure right after a probation re-ejects immediately (half-open): fail 3, wait, fail 1
	for i := 0; i < 3; i++ {
		bad.reportPassive(p, true, clk.Now())
	}
	clk.Advance(31 * time.Second)
	if !bad.reportPassive(p, true, clk.Now()) {
		t.Fatal("a failure while on probation must eject again")
	}
}

func TestActiveHealthStateMachine(t *testing.T) {
	m, clk := newTestManager()
	_ = m
	u := &Upstream{OriginIpOrDomain: "x:1", Weight: 1}
	hc := ActiveHealthCheck{Rise: 2, Fall: 3}.Normalized()

	steps := []struct {
		ok          bool
		wantChanged bool
		wantHealthy bool
	}{
		{true, false, true},
		{false, false, true}, // fall 1
		{false, false, true}, // fall 2
		{true, false, true},  // success resets the fall counter
		{false, false, true}, // fall 1
		{false, false, true}, // fall 2
		{false, true, false}, // fall 3 -> unhealthy
		{false, false, false},
		{true, false, false},  // rise 1
		{false, false, false}, // rise counter resets
		{true, false, false},  // rise 1
		{true, true, true},    // rise 2 -> healthy
		{true, false, true},
	}
	for i, s := range steps {
		clk.Advance(time.Second)
		changed := u.reportActive(hc, s.ok, "", clk.Now())
		if changed != s.wantChanged || u.isHealthy(clk.Now()) != s.wantHealthy {
			t.Fatalf("step %d: changed=%v healthy=%v, want %v/%v", i, changed, u.isHealthy(clk.Now()), s.wantChanged, s.wantHealthy)
		}
	}
	if f := u.slowStartFactor(clk.Now(), 10*time.Second); f > 0.2 {
		t.Fatalf("recovery by active check should start slow start, factor %.2f", f)
	}
}

func TestActiveHealthDefaults(t *testing.T) {
	hc := ActiveHealthCheck{Enabled: true}.Normalized()
	if hc.Mode != "http" || hc.Path != "/" || hc.Method != "GET" || hc.IntervalSeconds != 10 || hc.TimeoutSeconds != 5 ||
		hc.ExpectedStatusMin != 200 || hc.ExpectedStatusMax != 399 || hc.Rise != 2 || hc.Fall != 3 {
		t.Fatalf("unexpected defaults: %+v", hc)
	}
	p := PassiveHealthCheck{}.Normalized()
	if p.FailThreshold != 3 || p.CooldownSeconds != 30 || !containsInt(p.FailureStatuses, 503) {
		t.Fatalf("unexpected passive defaults: %+v", p)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"nil", nil, false},
		{"empty", &Config{}, false},
		{"every algorithm is valid", &Config{Algorithm: AlgoPowerOfTwoChoices}, false},
		{"unknown algorithm", &Config{Algorithm: "magic"}, true},
		{"header hash needs key", &Config{Algorithm: AlgoHeaderHash}, true},
		{"header hash with key", &Config{Algorithm: AlgoHeaderHash, HashKey: "X-A"}, false},
		{"bad path", &Config{ActiveHealthCheck: &ActiveHealthCheck{Path: "health"}}, true},
		{"bad range", &Config{ActiveHealthCheck: &ActiveHealthCheck{ExpectedStatusMin: 300, ExpectedStatusMax: 200}}, true},
		{"bad mode", &Config{ActiveHealthCheck: &ActiveHealthCheck{Mode: "udp"}}, true},
		{"negative interval", &Config{ActiveHealthCheck: &ActiveHealthCheck{IntervalSeconds: -1}}, true},
		{"bad failure status", &Config{PassiveHealthCheck: &PassiveHealthCheck{FailureStatuses: []int{42}}}, true},
		{"too many retries", &Config{Retry: &RetryConfig{MaxRetries: 99}}, true},
		{"lowercase method", &Config{Retry: &RetryConfig{ExtraMethods: []string{"post"}}}, true},
		{"connect never", &Config{Retry: &RetryConfig{ExtraMethods: []string{"CONNECT"}}}, true},
		{"good retry", &Config{Retry: &RetryConfig{Enabled: true, MaxRetries: 2, ExtraMethods: []string{"POST"}, RetryStatuses: []int{503}}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// useFastHealthInterval makes one "second" of health check interval last 20ms
func useFastHealthInterval(t *testing.T) {
	old := healthIntervalUnit
	healthIntervalUnit = 20 * time.Millisecond
	t.Cleanup(func() { healthIntervalUnit = old })
}

// flippingBackend is an httptest server whose health can be switched
type flippingBackend struct {
	*httptest.Server
	up   atomic.Bool
	hits atomic.Int64
}

func newFlippingBackend(body string) *flippingBackend {
	b := &flippingBackend{}
	b.up.Store(true)
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		if r.URL.Path != "/healthz" {
			w.WriteHeader(404)
			return
		}
		if !b.up.Load() {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(body))
	}))
	return b
}

func (b *flippingBackend) origin() string { return strings.TrimPrefix(b.URL, "http://") }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestActiveHealthCheckAgainstFlippingBackend(t *testing.T) {
	backend := newFlippingBackend("status: ok")
	defer backend.Close()

	m := &RouteManager{}
	u := &Upstream{OriginIpOrDomain: backend.origin(), Weight: 1}
	cfg := &Config{ActiveHealthCheck: &ActiveHealthCheck{
		Enabled: true, Path: "/healthz", IntervalSeconds: 1, TimeoutSeconds: 1, Rise: 2, Fall: 2, BodyContains: "ok",
	}}
	useFastHealthInterval(t)

	m.SyncHealthChecks("ep", cfg, []*Upstream{u})
	defer m.StopAllHealthChecks()

	waitFor(t, "first probe", func() bool { return backend.hits.Load() >= 1 })
	if !u.isHealthy(time.Now()) {
		t.Fatal("healthy backend reported unhealthy")
	}

	backend.up.Store(false)
	waitFor(t, "upstream marked unhealthy", func() bool { return !u.isHealthy(time.Now()) })
	if st := u.GetState(time.Now(), cfg); st.State != "unhealthy" || st.LastCheckError == "" {
		t.Fatalf("state %+v", st)
	}

	backend.up.Store(true)
	waitFor(t, "upstream recovered", func() bool { return u.isHealthy(time.Now()) })
}

func TestActiveHealthCheckExpectationsAndTCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/teapot" {
			w.WriteHeader(418)
		}
		if r.Method != "HEAD" {
			w.Write([]byte("hello world"))
		}
	}))
	defer srv.Close()
	origin := strings.TrimPrefix(srv.URL, "http://")

	tests := []struct {
		name    string
		hc      ActiveHealthCheck
		wantErr bool
	}{
		{"default ok", ActiveHealthCheck{}, false},
		{"status outside range", ActiveHealthCheck{Path: "/teapot"}, true},
		{"status inside custom range", ActiveHealthCheck{Path: "/teapot", ExpectedStatusMin: 418, ExpectedStatusMax: 418}, false},
		{"body match", ActiveHealthCheck{BodyContains: "world"}, false},
		{"body mismatch", ActiveHealthCheck{BodyContains: "nope"}, true},
		{"head method", ActiveHealthCheck{Method: "HEAD"}, false},
		{"tcp", ActiveHealthCheck{Mode: "tcp"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := &Upstream{OriginIpOrDomain: origin}
			p := newProber(u, tc.hc.Normalized())
			defer p.close()
			err := p.probe(t.Context())
			if (err != nil) != tc.wantErr {
				t.Fatalf("probe error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}

	// Closed port fails in both modes
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	for _, mode := range []string{"http", "tcp"} {
		p := newProber(&Upstream{OriginIpOrDomain: closed}, ActiveHealthCheck{Mode: mode}.Normalized())
		if err := p.probe(t.Context()); err == nil {
			t.Errorf("%s probe of a closed port succeeded", mode)
		}
		p.close()
	}
}

func TestActiveHealthCheckHonorsTLSSettings(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	origin := strings.TrimPrefix(srv.URL, "https://")

	strict := newProber(&Upstream{OriginIpOrDomain: origin, RequireTLS: true}, ActiveHealthCheck{}.Normalized())
	defer strict.close()
	if err := strict.probe(t.Context()); err == nil {
		t.Error("self signed certificate accepted without SkipCertValidations")
	}
	lax := newProber(&Upstream{OriginIpOrDomain: origin, RequireTLS: true, SkipCertValidations: true}, ActiveHealthCheck{}.Normalized())
	defer lax.close()
	if err := lax.probe(t.Context()); err != nil {
		t.Errorf("probe with SkipCertValidations failed: %v", err)
	}
}

// settleGoroutines waits for background goroutines of finished HTTP clients to disappear
func settleGoroutines(target int) int {
	n := runtime.NumGoroutine()
	for i := 0; i < 100 && n > target; i++ {
		time.Sleep(20 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	return n
}

func TestHealthCheckGoroutinesDoNotLeak(t *testing.T) {
	backend := newFlippingBackend("ok")
	defer backend.Close()
	http.DefaultClient.CloseIdleConnections()
	baseline := settleGoroutines(0)

	useFastHealthInterval(t)
	m := &RouteManager{}
	defer m.StopAllHealthChecks()
	mk := func() []*Upstream {
		return []*Upstream{
			{OriginIpOrDomain: backend.origin(), Weight: 1},
			{OriginIpOrDomain: backend.origin(), Weight: 1},
			{OriginIpOrDomain: backend.origin(), Weight: 1, HealthCheck: &ActiveHealthCheck{Enabled: true, Mode: "tcp"}},
		}
	}
	cfg := &Config{ActiveHealthCheck: &ActiveHealthCheck{Enabled: true, Path: "/healthz", IntervalSeconds: 1}}

	// Start, replace, remove one endpoint, restart everything
	for round := 0; round < 3; round++ {
		ups := mk()
		m.SyncHealthChecks("a", cfg, ups)
		m.SyncHealthChecks("b", cfg, mk())
		waitFor(t, "probes", func() bool { return backend.hits.Load() > int64(round) })
		if runtime.NumGoroutine() <= baseline {
			t.Fatal("expected health check goroutines to be running")
		}
		m.SyncHealthChecks("a", cfg, ups)  // unchanged: must be a no-op
		m.SyncHealthChecks("a", cfg, mk()) // changed upstream objects: replaced
		m.StopHealthChecks("a")
		if m.HealthCheckGroupCount() != 1 {
			t.Fatalf("groups = %d", m.HealthCheckGroupCount())
		}
		m.StopAllHealthChecks()
		if m.HealthCheckGroupCount() != 0 {
			t.Fatalf("groups = %d after stop all", m.HealthCheckGroupCount())
		}
	}
	// Disabling the check in the config stops the goroutines too
	plain := func() []*Upstream { return mkUpstreams(1, 1) }
	m.SyncHealthChecks("c", cfg, plain())
	m.SyncHealthChecks("c", &Config{}, plain())
	if m.HealthCheckGroupCount() != 0 {
		t.Fatal("disabled config should leave no group")
	}

	if n := settleGoroutines(baseline); n > baseline {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("goroutine leak: %d before, %d after\n%s", baseline, n, buf)
	}
}

func TestDisablingChecksClearsUnhealthyState(t *testing.T) {
	m := &RouteManager{}
	u := &Upstream{OriginIpOrDomain: "x:1", Weight: 1}
	u.rt.activeUnhealthy = true
	m.SyncHealthChecks("e", &Config{}, []*Upstream{u})
	if !u.isHealthy(time.Now()) {
		t.Fatal("stale unhealthy flag kept after checks were disabled")
	}
}
