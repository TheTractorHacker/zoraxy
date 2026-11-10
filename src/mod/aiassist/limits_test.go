package aiassist

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterBudgetRateAndMonth(t *testing.T) {
	dir := t.TempDir()
	l := NewLimiter(dir)
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }

	r, err := l.Reserve("explain", 400, 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	r.Done(300)
	if u := l.Usage(); u.Tokens != 300 || u.Calls != 1 || u.ByFeature["explain"] != 300 {
		t.Fatalf("%+v", u)
	}
	if _, err := l.Reserve("explain", 800, 1000, 100); err != ErrBudget {
		t.Fatalf("budget: %v", err)
	}
	// persisted
	if u := NewLimiter(dir).Usage(); u.Tokens != 300 {
		t.Fatalf("persist: %+v", u)
	}
	// a new month resets the counter lazily
	now = now.AddDate(0, 1, 0)
	if u := l.Usage(); u.Tokens != 0 {
		t.Fatalf("month: %+v", u)
	}
	// cap 0 refuses everything
	if _, err := l.Reserve("x", 1, 0, 10); err != ErrBudget {
		t.Fatal("zero budget must refuse")
	}
	// rate limit: 3 per minute
	for i := 0; i < 3; i++ {
		r, err := l.Reserve("x", 1, 1e9, 3)
		if err != nil {
			t.Fatal(err)
		}
		r.Done(1)
	}
	if _, err := l.Reserve("x", 1, 1e9, 3); err != ErrRateLimited {
		t.Fatalf("rate: %v", err)
	}
	now = now.Add(61 * time.Second)
	if r, err := l.Reserve("x", 1, 1e9, 3); err != nil {
		t.Fatalf("after a minute: %v", err)
	} else {
		r.Cancel()
	}
}

// Parallel callers cannot jointly start above the cap: used + reserved <= cap at every admission.
func TestLimiterConcurrencyDoesNotOvershoot(t *testing.T) {
	l := NewLimiter(t.TempDir())
	const cap, est = 1000, 300
	var admitted, running, maxRunning atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var r *Reservation
			var err error
			for { // callers that find the service busy retry, as a queue would
				if r, err = l.Reserve("x", est, cap, 100000); err != ErrBusy {
					break
				}
				time.Sleep(100 * time.Microsecond)
			}
			if err != nil {
				return
			}
			admitted.Add(1)
			n := running.Add(1)
			for {
				m := maxRunning.Load()
				if n <= m || maxRunning.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			running.Add(-1)
			r.Done(est) // exact estimate: no estimation error
		}()
	}
	wg.Wait()
	u := l.Usage()
	if u.Tokens > cap {
		t.Fatalf("overshoot: %d > %d", u.Tokens, cap)
	}
	if admitted.Load() != 3 || u.Tokens != 900 {
		t.Fatalf("admitted %d calls, %d tokens", admitted.Load(), u.Tokens)
	}
	if maxRunning.Load() > maxInFlight {
		t.Fatalf("in flight %d > %d", maxRunning.Load(), maxInFlight)
	}
}

// With estimation error the overshoot is bounded by maxInFlight x error.
func TestLimiterOvershootBound(t *testing.T) {
	l := NewLimiter(t.TempDir())
	const cap, est, actual = 1000, 300, 450
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := l.Reserve("x", est, cap, 100000); err == nil {
				r.Done(actual)
			}
		}()
	}
	wg.Wait()
	if u := l.Usage(); u.Tokens > cap+maxInFlight*(actual-est) {
		t.Fatalf("overshoot %d beyond the documented bound", u.Tokens-cap)
	}
}
