package statistic

import (
	"sync"
	"time"
)

/*
	Short term rates for the status page: a ring of per-minute counters (60 minutes,
	constant memory) updated on every recorded request.
*/

const rateBuckets = 60

type rateBucket struct {
	minute  int64 // unix minute this bucket belongs to
	total   int64
	errors  int64
	blocked int64
}

type rateRing struct {
	mu sync.Mutex
	b  [rateBuckets]rateBucket
}

func (r *rateRing) add(now time.Time, errored, blocked bool) {
	m := now.Unix() / 60
	r.mu.Lock()
	defer r.mu.Unlock()
	bk := &r.b[m%rateBuckets]
	if bk.minute != m {
		*bk = rateBucket{minute: m}
	}
	bk.total++
	if errored {
		bk.errors++
	}
	if blocked {
		bk.blocked++
	}
}

// Rates is the traffic of the last few complete minutes
type Rates struct {
	Minutes        int     // size of the averaging window
	RequestsPerMin float64 // average requests per minute
	ErrorsPerMin   float64
	BlockedPerMin  float64
	ErrorRate      float64 // errors / requests (0..1)
	Series         []int64 // requests per minute, oldest first, last 30 minutes (the running minute included)
	ErrorSeries    []int64 // error responses per minute, same window as Series
	BlockedSeries  []int64 // requests rejected by Zoraxy per minute, same window as Series
}

// RecentRates averages the last `window` complete minutes (1..30)
func (c *Collector) RecentRates(window int) Rates {
	return c.rates.recent(time.Now(), window)
}

func (r *rateRing) recent(now time.Time, window int) Rates {
	if window < 1 {
		window = 1
	}
	if window > 30 {
		window = 30
	}
	cur := now.Unix() / 60
	r.mu.Lock()
	defer r.mu.Unlock()
	var tot, errs, blk int64
	for i := 1; i <= window; i++ {
		bk := r.b[(cur-int64(i))%rateBuckets]
		if bk.minute == cur-int64(i) {
			tot += bk.total
			errs += bk.errors
			blk += bk.blocked
		}
	}
	out := Rates{Minutes: window, RequestsPerMin: float64(tot) / float64(window), ErrorsPerMin: float64(errs) / float64(window),
		BlockedPerMin: float64(blk) / float64(window), Series: make([]int64, 30),
		ErrorSeries: make([]int64, 30), BlockedSeries: make([]int64, 30)}
	if tot > 0 {
		out.ErrorRate = float64(errs) / float64(tot)
	}
	for i := 0; i < 30; i++ {
		m := cur - int64(29-i)
		if bk := r.b[m%rateBuckets]; bk.minute == m {
			out.Series[i] = bk.total
			out.ErrorSeries[i] = bk.errors
			out.BlockedSeries[i] = bk.blocked
		}
	}
	return out
}
