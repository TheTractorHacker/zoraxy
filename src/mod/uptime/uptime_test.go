package uptime

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This test reproduces GitHub issue #1241: getWebsiteStatus used to leak one
// upstream TCP connection per call because it built a fresh keep-alive
// http.Transport every time and never closed/reused it. It verifies that
// every connection opened by a check is closed again shortly after.
func TestGetWebsiteStatusClosesConnections(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	var opened, closed int64
	var mu sync.Mutex
	seen := map[string]bool{}
	server.Config.ConnState = func(c net.Conn, state http.ConnState) {
		key := c.RemoteAddr().String()
		switch state {
		case http.StateNew:
			mu.Lock()
			if !seen[key] {
				seen[key] = true
				atomic.AddInt64(&opened, 1)
			}
			mu.Unlock()
		case http.StateClosed:
			atomic.AddInt64(&closed, 1)
		}
	}
	server.Start() //start only after ConnState is set (setting it on a running server races)

	m := &Monitor{Config: &Config{}}

	const n = 5
	for i := 0; i < n; i++ {
		code, err := m.getWebsiteStatus(server.URL, false, 2*time.Second)
		if err != nil {
			t.Fatalf("check %d failed: %v", i, err)
		}
		if code != http.StatusOK {
			t.Fatalf("check %d unexpected status: %d", i, code)
		}
	}

	// The transport closes connections asynchronously: poll with a generous
	// deadline instead of sleeping a fixed time (flaky under load).
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(&closed) < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	closedNow := atomic.LoadInt64(&closed)
	if closedNow < n {
		t.Fatalf("expected at least %d closed connections after %d checks, got %d closed (opened=%d) - connections are leaking", n, n, closedNow, atomic.LoadInt64(&opened))
	}
}

func TestStatusMeansReachable(t *testing.T) {
	up := []int{200, 204, 301, 302, 401, 403, 404, 405, 421, 429, 500, 525}
	down := []int{0, 502, 503, 504, 521, 522, 523, 524}
	for _, c := range up {
		if !statusMeansReachable(c) {
			t.Errorf("%d should count as reachable", c)
		}
	}
	for _, c := range down {
		if statusMeansReachable(c) {
			t.Errorf("%d should count as unreachable", c)
		}
	}
}

func TestStatusSpec(t *testing.T) {
	cases := []struct {
		spec string
		code int
		want bool
	}{
		{"", 401, true}, {"", 503, false}, {"any", 404, true},
		{"200-399", 401, false}, {"200-399", 302, true},
		{"2xx,401", 401, true}, {"2xx,401", 404, false},
		{"any,!", 200, true},
	}
	for _, c := range cases {
		s, err := ParseStatusSpec(c.spec)
		if c.spec == "any,!" {
			if err == nil {
				t.Fatal("garbage token must be rejected")
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", c.spec, err)
		}
		if got := s.Match(c.code); got != c.want {
			t.Errorf("spec %q code %d = %v, want %v", c.spec, c.code, got, c.want)
		}
	}
	for _, bad := range []string{"99", "600", "5-3", "abc", "2xxx", "6xx"} {
		if _, err := ParseStatusSpec(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
	if err := SetDefaultHealthyStatus("200-399"); err != nil {
		t.Fatal(err)
	}
	defer SetDefaultHealthyStatus("")
	if specFor(&Target{}).Match(401) || !specFor(&Target{HealthyStatus: "401"}).Match(401) {
		t.Fatal("global spec applies unless the target has its own")
	}
}
