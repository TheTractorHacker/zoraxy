package loadbalance

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// newTestManager returns a RouteManager without logger or background goroutines
func newTestManager() (*RouteManager, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return &RouteManager{Now: clk.Now}, clk
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func mkUpstreams(weights ...int) []*Upstream {
	ups := make([]*Upstream, len(weights))
	for i, w := range weights {
		ups[i] = &Upstream{OriginIpOrDomain: fmt.Sprintf("10.0.0.%d:8080", i+1), Weight: w}
	}
	return ups
}

func testRequest(remoteIP string) *http.Request {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = remoteIP + ":4000"
	return r
}

func pickN(t *testing.T, m *RouteManager, ups []*Upstream, cfg *Config, n int, mkReq func(i int) *http.Request) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		r := testRequest("203.0.113.1")
		if mkReq != nil {
			r = mkReq(i)
		}
		u, err := m.SelectUpstream(nil, r, ups, &SelectOptions{Config: cfg}) //No sticky session, the writer is never used
		if err != nil {
			t.Fatalf("select failed: %v", err)
		}
		counts[u.OriginIpOrDomain]++
	}
	return counts
}

// within checks that got is within tol (fraction) of want
func within(got, want int, tol float64) bool {
	if want == 0 {
		return got == 0
	}
	return math.Abs(float64(got-want))/float64(want) <= tol
}

func TestAlgorithmDistribution(t *testing.T) {
	const n = 20000
	tests := []struct {
		name    string
		algo    string
		weights []int
		hashReq func(i int) *http.Request
		tol     float64
	}{
		{"random equal", AlgoRandom, []int{1, 1, 1, 1}, nil, 0.08},
		{"random weighted", AlgoRandom, []int{3, 1}, nil, 0.08},
		{"round robin equal", AlgoRoundRobin, []int{1, 1, 1, 1}, nil, 0.001},
		{"round robin ignores weight value", AlgoRoundRobin, []int{5, 1, 1}, nil, 0.001},
		{"smooth wrr", AlgoWeightedRoundRobin, []int{5, 2, 1}, nil, 0.001},
		{"least connections idle", AlgoLeastConnections, []int{1, 1, 1}, nil, 0.1},
		{"least response time idle", AlgoLeastResponseTime, []int{1, 1, 1}, nil, 0.1},
		{"power of two choices", AlgoPowerOfTwoChoices, []int{1, 1, 1, 1}, nil, 0.1},
		{"ip hash", AlgoIPHash, []int{1, 1, 1, 1}, func(i int) *http.Request {
			return testRequest(fmt.Sprintf("198.51.%d.%d", i/250%250, i%250))
		}, 0.15},
		{"ip hash weighted", AlgoIPHash, []int{3, 1}, func(i int) *http.Request {
			return testRequest(fmt.Sprintf("198.51.%d.%d", i/250%250, i%250))
		}, 0.15},
		{"header hash", AlgoHeaderHash, []int{1, 1, 1}, func(i int) *http.Request {
			r := testRequest("203.0.113.1")
			r.Header.Set("X-Tenant", fmt.Sprintf("tenant-%d", i))
			return r
		}, 0.15},
		{"cookie hash", AlgoCookieHash, []int{1, 1, 1}, func(i int) *http.Request {
			r := testRequest("203.0.113.1")
			r.AddCookie(&http.Cookie{Name: "sid", Value: fmt.Sprintf("s%d", i)})
			return r
		}, 0.15},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestManager()
			ups := mkUpstreams(tc.weights...)
			cfg := &Config{Algorithm: tc.algo, HashKey: "X-Tenant"}
			if tc.algo == AlgoCookieHash {
				cfg.HashKey = "sid"
			}
			counts := pickN(t, m, ups, cfg, n, tc.hashReq)

			totalW := 0
			for _, w := range tc.weights {
				totalW += w
			}
			for i, u := range ups {
				want := n * tc.weights[i] / totalW
				if tc.algo == AlgoRoundRobin {
					want = n / len(ups) //Round robin does not use the weight value
				}
				if !within(counts[u.OriginIpOrDomain], want, tc.tol) {
					t.Errorf("%s got %d picks, want about %d (tolerance %.0f%%), all: %v",
						u.OriginIpOrDomain, counts[u.OriginIpOrDomain], want, tc.tol*100, counts)
				}
			}
		})
	}
}

func TestWeightZeroIsFallbackOnly(t *testing.T) {
	for _, algo := range AllAlgorithms {
		t.Run(algo, func(t *testing.T) {
			m, _ := newTestManager()
			ups := mkUpstreams(1, 1, 0)
			cfg := &Config{Algorithm: algo, HashKey: "X-Key"}
			mk := func(i int) *http.Request {
				r := testRequest(fmt.Sprintf("198.51.100.%d", i%200))
				r.Header.Set("X-Key", fmt.Sprint(i))
				r.AddCookie(&http.Cookie{Name: "X-Key", Value: fmt.Sprint(i)})
				return r
			}
			cfg.HashKey = "X-Key"
			counts := pickN(t, m, ups, cfg, 2000, mk)
			if counts[ups[2].OriginIpOrDomain] != 0 {
				t.Fatalf("fallback upstream received traffic while primaries are up: %v", counts)
			}

			//Take both primaries away: the fallback must serve
			ups[0].Draining = true
			ups[1].Draining = true
			counts = pickN(t, m, ups, cfg, 200, mk)
			if counts[ups[2].OriginIpOrDomain] != 200 {
				t.Fatalf("fallback did not take over: %v", counts)
			}
		})
	}
}

func TestSmoothWRRIsSmooth(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(5, 1, 1)
	cfg := &Config{Algorithm: AlgoWeightedRoundRobin}
	var seq []string
	for i := 0; i < 7; i++ {
		u, _ := m.SelectUpstream(httptest.NewRecorder(), testRequest("1.1.1.1"), ups, &SelectOptions{Config: cfg})
		seq = append(seq, u.OriginIpOrDomain)
	}
	//The classic nginx result: a a b a c a a
	want := []string{"10.0.0.1:8080", "10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.1:8080", "10.0.0.3:8080", "10.0.0.1:8080", "10.0.0.1:8080"}
	for i := range want {
		if seq[i] != want[i] {
			t.Fatalf("sequence %v, want %v", seq, want)
		}
	}
}

func TestLeastConnectionsPrefersIdleAndHonorsWeight(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1, 1)
	for i := 0; i < 5; i++ {
		ups[0].Acquire()
		ups[1].Acquire()
	}
	cfg := &Config{Algorithm: AlgoLeastConnections}
	counts := pickN(t, m, ups, cfg, 100, nil)
	if counts[ups[2].OriginIpOrDomain] != 100 {
		t.Fatalf("expected the idle upstream every time: %v", counts)
	}

	//Weighted: 6 in flight on a weight 3 upstream (score 7/3) beats 3 in flight on weight 1 (score 4/1)
	ups = mkUpstreams(3, 1)
	for i := 0; i < 6; i++ {
		ups[0].Acquire()
	}
	for i := 0; i < 3; i++ {
		ups[1].Acquire()
	}
	counts = pickN(t, m, ups, cfg, 50, nil)
	if counts[ups[0].OriginIpOrDomain] != 50 {
		t.Fatalf("weight not honored: %v", counts)
	}
}

func TestLeastResponseTimePrefersFast(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1, 1)
	ups[0].observeLatency(200 * time.Millisecond)
	ups[1].observeLatency(10 * time.Millisecond)
	ups[2].observeLatency(500 * time.Millisecond)
	counts := pickN(t, m, ups, &Config{Algorithm: AlgoLeastResponseTime}, 100, nil)
	if counts[ups[1].OriginIpOrDomain] != 100 {
		t.Fatalf("fast upstream should win: %v", counts)
	}

	//EWMA moves toward new samples
	for i := 0; i < 30; i++ {
		ups[1].observeLatency(2 * time.Second)
	}
	if ups[1].EWMA() < time.Second {
		t.Fatalf("EWMA did not follow the slowdown: %v", ups[1].EWMA())
	}
	counts = pickN(t, m, ups, &Config{Algorithm: AlgoLeastResponseTime}, 100, nil)
	if counts[ups[0].OriginIpOrDomain] != 100 {
		t.Fatalf("traffic did not move to the now fastest upstream: %v", counts)
	}
}

func TestPowerOfTwoNeverPicksBusiestOfThree(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1, 1)
	for i := 0; i < 50; i++ {
		ups[0].Acquire()
	}
	counts := pickN(t, m, ups, &Config{Algorithm: AlgoPowerOfTwoChoices}, 3000, nil)
	if counts[ups[0].OriginIpOrDomain] != 0 {
		t.Fatalf("p2c picked the overloaded upstream: %v", counts)
	}
}

func TestHashIsSticky(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1, 1, 1)
	cfg := &Config{Algorithm: AlgoHeaderHash, HashKey: "X-User"}
	first := map[string]string{}
	for round := 0; round < 3; round++ {
		for i := 0; i < 200; i++ {
			user := fmt.Sprintf("user-%d", i)
			r := testRequest("203.0.113.1")
			r.Header.Set("X-User", user)
			u, _ := m.SelectUpstream(httptest.NewRecorder(), r, ups, &SelectOptions{Config: cfg})
			if prev, ok := first[user]; ok && prev != u.OriginIpOrDomain {
				t.Fatalf("%s moved from %s to %s", user, prev, u.OriginIpOrDomain)
			}
			first[user] = u.OriginIpOrDomain
		}
	}
}

func TestHashMissingKeyFallsBackToRandom(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1)
	counts := pickN(t, m, ups, &Config{Algorithm: AlgoHeaderHash, HashKey: "X-None"}, 2000, nil)
	if len(counts) != 2 {
		t.Fatalf("requests without the key should still be spread: %v", counts)
	}
}

func TestConsistentHashRemapsFewKeys(t *testing.T) {
	const keys = 20000
	assign := func(ups []*Upstream) map[int]string {
		ring := buildRing(ups)
		out := make(map[int]string, keys)
		for k := 0; k < keys; k++ {
			out[k] = ring.pick(hashString(fmt.Sprintf("key-%d", k)), func(*Upstream) bool { return true }).OriginIpOrDomain
		}
		return out
	}
	five := mkUpstreams(1, 1, 1, 1, 1)
	before := assign(five)

	t.Run("remove one", func(t *testing.T) {
		after := assign(five[:4]) //drop upstream 5
		moved, wronglyMoved := 0, 0
		for k := 0; k < keys; k++ {
			if before[k] != after[k] {
				moved++
				if before[k] != five[4].OriginIpOrDomain {
					wronglyMoved++
				}
			}
		}
		if wronglyMoved != 0 {
			t.Errorf("%d keys moved although their upstream was not removed", wronglyMoved)
		}
		if frac := float64(moved) / keys; frac > 0.30 || frac < 0.10 {
			t.Errorf("remapped %.1f%% of keys, expected about 20%%", frac*100)
		}
	})

	t.Run("add one", func(t *testing.T) {
		six := append(append([]*Upstream{}, five...), &Upstream{OriginIpOrDomain: "10.0.0.6:8080", Weight: 1})
		after := assign(six)
		moved := 0
		for k := 0; k < keys; k++ {
			if before[k] != after[k] {
				moved++
				if after[k] != "10.0.0.6:8080" {
					t.Fatalf("key moved between two old upstreams")
				}
			}
		}
		if frac := float64(moved) / keys; frac > 0.25 || frac < 0.08 {
			t.Errorf("remapped %.1f%% of keys, expected about 17%%", frac*100)
		}
	})

	t.Run("unhealthy upstream only moves its own keys", func(t *testing.T) {
		ring := buildRing(five)
		down := five[2]
		for k := 0; k < keys; k++ {
			h := hashString(fmt.Sprintf("key-%d", k))
			got := ring.pick(h, func(u *Upstream) bool { return u != down })
			if before[k] != down.OriginIpOrDomain && got.OriginIpOrDomain != before[k] {
				t.Fatalf("key of a healthy upstream moved")
			}
			if got == down {
				t.Fatalf("picked a rejected upstream")
			}
		}
	})
}

func TestRingWeights(t *testing.T) {
	ups := mkUpstreams(3, 1)
	ring := buildRing(ups)
	counts := map[string]int{}
	for k := 0; k < 30000; k++ {
		counts[ring.pick(hashString(fmt.Sprint("k", k)), func(*Upstream) bool { return true }).OriginIpOrDomain]++
	}
	if !within(counts[ups[0].OriginIpOrDomain], 22500, 0.1) {
		t.Fatalf("weights not reflected on the ring: %v", counts)
	}
}

func TestSelectErrors(t *testing.T) {
	m, _ := newTestManager()
	r := testRequest("1.1.1.1")
	w := httptest.NewRecorder()

	if _, err := m.SelectUpstream(w, r, nil, &SelectOptions{}); err == nil {
		t.Error("expected an error for no upstreams")
	}

	ups := mkUpstreams(1, 1)
	ups[0].MaxInFlight, ups[1].MaxInFlight = 1, 1
	ups[0].Acquire()
	ups[1].Acquire()
	if _, err := m.SelectUpstream(w, r, ups, &SelectOptions{}); !errors.Is(err, ErrUpstreamsBusy) {
		t.Errorf("expected ErrUpstreamsBusy, got %v", err)
	}
	ups[1].Release()
	u, err := m.SelectUpstream(w, r, ups, &SelectOptions{})
	if err != nil || u != ups[1] {
		t.Errorf("the upstream with free capacity must be chosen, got %v %v", u, err)
	}

	ups[1].Draining = true
	if _, err := m.SelectUpstream(w, r, ups, &SelectOptions{}); err == nil {
		t.Error("draining upstream must not receive new requests")
	}
}

func TestDefaultPathSkipsNewChecksForSingleUpstream(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1)
	ups[0].rt.activeUnhealthy = true
	u, err := m.SelectUpstream(httptest.NewRecorder(), testRequest("1.1.1.1"), ups, &SelectOptions{})
	if err != nil || u != ups[0] {
		t.Fatalf("a sole upstream must always be used: %v %v", u, err)
	}
}

func TestAllUnhealthyFailsOpen(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1)
	ups[0].rt.activeUnhealthy = true
	ups[1].rt.activeUnhealthy = true
	if _, err := m.SelectUpstream(httptest.NewRecorder(), testRequest("1.1.1.1"), ups, &SelectOptions{}); err != nil {
		t.Fatalf("when every upstream is unhealthy requests should still be attempted: %v", err)
	}
	ups[1].rt.activeUnhealthy = false
	counts := pickN(t, m, ups, &Config{}, 100, nil)
	if counts[ups[1].OriginIpOrDomain] != 100 {
		t.Fatalf("unhealthy upstream must be skipped: %v", counts)
	}
}

func TestStickySessionTakesPrecedence(t *testing.T) {
	m, _ := newTestManager()
	m.SessionStore = sessions.NewCookieStore([]byte("test-key"))
	ups := mkUpstreams(1, 1, 1)
	cfg := &Config{Algorithm: AlgoRoundRobin}
	opt := &SelectOptions{Config: cfg, UseStickySession: true}

	rec := httptest.NewRecorder()
	first, err := m.SelectUpstream(rec, testRequest("1.1.1.1"), ups, opt)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != STICKY_SESSION_NAME {
		t.Fatalf("expected one sticky cookie, got %v", cookies)
	}
	for i := 0; i < 20; i++ {
		r := testRequest("1.1.1.1")
		r.AddCookie(cookies[0])
		u, err := m.SelectUpstream(httptest.NewRecorder(), r, ups, opt)
		if err != nil || u != first {
			t.Fatalf("session not honored on request %d", i)
		}
	}

	//The session upstream starts draining: the client is moved and gets a new cookie
	first.Draining = true
	r := testRequest("1.1.1.1")
	r.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	u, err := m.SelectUpstream(rec, r, ups, opt)
	if err != nil || u == first {
		t.Fatalf("draining upstream kept a sticky client: %v %v", u, err)
	}
	if len(rec.Result().Cookies()) != 1 {
		t.Fatalf("a new sticky cookie should have been issued")
	}
}

func TestExcludeSkipsTriedUpstreams(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1, 1)
	opt := &SelectOptions{Exclude: []*Upstream{ups[0], ups[1]}}
	for i := 0; i < 50; i++ {
		u, err := m.SelectUpstream(httptest.NewRecorder(), testRequest("1.1.1.1"), ups, opt)
		if err != nil || u != ups[2] {
			t.Fatalf("excluded upstream selected: %v %v", u, err)
		}
	}
}

func TestSlowStartScalesWeight(t *testing.T) {
	m, clk := newTestManager()
	ups := mkUpstreams(1, 1)
	cfg := &Config{SlowStartSeconds: 100}
	//ups[1] just recovered
	ups[1].rt.slowStart = clk.Now()

	counts := pickN(t, m, ups, cfg, 20000, nil)
	// weight 1 vs 0.1 => about 9% of traffic to the recovering one
	if share := float64(counts[ups[1].OriginIpOrDomain]) / 20000; share > 0.13 || share < 0.05 {
		t.Fatalf("recovering upstream share %.3f at the start of slow start", share)
	}
	clk.Advance(50 * time.Second)
	counts = pickN(t, m, ups, cfg, 20000, nil)
	// factor 0.55 => 0.55/1.55 = 35%
	if share := float64(counts[ups[1].OriginIpOrDomain]) / 20000; share > 0.40 || share < 0.30 {
		t.Fatalf("recovering upstream share %.3f halfway", share)
	}
	clk.Advance(60 * time.Second)
	counts = pickN(t, m, ups, cfg, 20000, nil)
	if share := float64(counts[ups[1].OriginIpOrDomain]) / 20000; share > 0.54 || share < 0.46 {
		t.Fatalf("share %.3f after slow start ended", share)
	}
}
