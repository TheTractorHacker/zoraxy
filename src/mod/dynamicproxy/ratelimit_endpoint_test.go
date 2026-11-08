package dynamicproxy

import (
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Traffic to endpoint A must not consume endpoint B's budget for the same IP.
func TestHandleRateLimit_EndpointsAreIsolated(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	a := &ProxyEndpoint{RootOrMatchingDomain: "a.example.com", RequireRateLimit: true, RateLimit: 5}
	b := &ProxyEndpoint{RootOrMatchingDomain: "b.example.com", RequireRateLimit: true, RateLimit: 5}

	//Hammer A well past its limit
	for i := 0; i < 50; i++ {
		router.handleRateLimit(httptest.NewRecorder(), newTestRequest("198.51.100.7:1234", nil), a)
	}

	//B must still have its full budget
	for i := 0; i < 4; i++ {
		w := httptest.NewRecorder()
		if err := router.handleRateLimit(w, newTestRequest("198.51.100.7:1234", nil), b); err != nil {
			t.Fatalf("endpoint B throttled by endpoint A traffic at request %d", i)
		}
	}
}

func newTestLimiter() (*RequestCountPerIpTable, *time.Time) {
	now := time.Unix(1000, 0)
	l := &RequestCountPerIpTable{}
	l.now = func() time.Time { return now }
	return l, &now
}

func TestTokenBucket_BurstDefaultsToRateAndRefills(t *testing.T) {
	l, now := newTestLimiter()
	for i := 0; i < 5; i++ {
		if !l.Allow("e", "1.1.1.1", 5, 0) {
			t.Fatalf("request %d within rate must pass", i)
		}
	}
	if l.Allow("e", "1.1.1.1", 5, 0) {
		t.Fatal("6th immediate request must be limited")
	}
	*now = now.Add(400 * time.Millisecond) //2 tokens
	if !l.Allow("e", "1.1.1.1", 5, 0) || !l.Allow("e", "1.1.1.1", 5, 0) {
		t.Fatal("tokens should refill continuously")
	}
	if l.Allow("e", "1.1.1.1", 5, 0) {
		t.Fatal("only 2 tokens should have refilled")
	}
}

func TestTokenBucket_ExplicitBurst(t *testing.T) {
	l, now := newTestLimiter()
	passed := 0
	for i := 0; i < 50; i++ {
		if l.Allow("e", "1.1.1.1", 2, 20) {
			passed++
		}
	}
	if passed != 20 {
		t.Fatalf("burst of 20 expected, got %d", passed)
	}
	*now = now.Add(10 * time.Second) //refill is capped at burst
	passed = 0
	for i := 0; i < 50; i++ {
		if l.Allow("e", "1.1.1.1", 2, 20) {
			passed++
		}
	}
	if passed != 20 {
		t.Fatalf("refill must cap at burst, got %d", passed)
	}
}

func TestTokenBucket_SweepEvictsIdleOnly(t *testing.T) {
	l, now := newTestLimiter()
	l.Allow("e", "1.1.1.1", 5, 0)
	l.Allow("e", "2.2.2.2", 5, 0)
	*now = now.Add(5 * time.Second)
	l.Allow("e", "2.2.2.2", 5, 0) //keep active
	l.Sweep()
	if l.Has("e", "1.1.1.1") {
		t.Error("idle bucket should be evicted")
	}
	if !l.Has("e", "2.2.2.2") || l.Len() != 1 {
		t.Error("recently used bucket must be kept and size tracked")
	}
}

func TestTokenBucket_ConcurrentRace(t *testing.T) {
	l := &RequestCountPerIpTable{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				l.Allow("e"+strconv.Itoa(g%2), "10.0.0."+strconv.Itoa(i%20), 10, 0)
				if i%100 == 0 {
					l.Sweep()
				}
			}
		}(g)
	}
	wg.Wait()
}
