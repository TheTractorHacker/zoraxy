package dynamicproxy

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

/*
	Token bucket rate limiter

	Buckets are keyed by "<endpoint>|<client ip>" so traffic to one proxy
	endpoint can never consume another endpoint's budget. Each bucket refills
	continuously at `rate` tokens / second and holds at most `burst` tokens
	(burst defaults to rate, which keeps the old "N requests per second"
	meaning). Idle buckets are swept so memory stays bounded.
*/

const (
	rateLimitMaxBuckets    = 200000 //Hard cap on tracked (endpoint, ip) pairs
	rateLimitSweepInterval = 10 * time.Second
)

type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

// RequestCountPerIpTable is a set of token buckets keyed by endpoint + client IP.
// The zero value is ready to use.
type RequestCountPerIpTable struct {
	table sync.Map //string -> *tokenBucket
	size  atomic.Int64
	now   func() time.Time //Test seam, nil means time.Now
}

func (t *RequestCountPerIpTable) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func bucketKey(endpointID string, ip string) string {
	return endpointID + "|" + ip
}

// Allow consumes one token from the (endpoint, ip) bucket. It returns false
// when the bucket is empty. burst <= 0 means burst = rate.
func (t *RequestCountPerIpTable) Allow(endpointID string, ip string, rate int64, burst int64) bool {
	if rate <= 0 {
		//Misconfigured limit (the API rejects this). Keep the historic
		//behaviour of blocking everything
		return false
	}
	if burst <= 0 {
		burst = rate
	}
	now := t.clock()
	key := bucketKey(endpointID, ip)

	v, ok := t.table.Load(key)
	if !ok {
		if t.size.Load() >= rateLimitMaxBuckets {
			t.Sweep()
			if t.size.Load() >= rateLimitMaxBuckets {
				//Still full of active buckets. Fall back to one shared
				//overflow bucket per endpoint instead of growing without bound
				key = bucketKey(endpointID, "*overflow*")
			}
		}
		nb := &tokenBucket{tokens: float64(burst), last: now, rate: float64(rate), burst: float64(burst)}
		actual, loaded := t.table.LoadOrStore(key, nb)
		if !loaded {
			t.size.Add(1)
		}
		v = actual
	}

	b := v.(*tokenBucket)
	b.mu.Lock()
	defer b.mu.Unlock()
	//Pick up config changes
	b.rate, b.burst = float64(rate), float64(burst)
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Sweep removes buckets that have been idle long enough to be full again
// (a full bucket is indistinguishable from a brand new one)
func (t *RequestCountPerIpTable) Sweep() {
	now := t.clock()
	t.table.Range(func(key, value interface{}) bool {
		b := value.(*tokenBucket)
		b.mu.Lock()
		refill := time.Duration(b.burst / b.rate * float64(time.Second))
		if refill < time.Second {
			refill = time.Second
		}
		idle := now.Sub(b.last) >= refill
		b.mu.Unlock()
		if idle {
			if _, deleted := t.table.LoadAndDelete(key); deleted {
				t.size.Add(-1)
			}
		}
		return true
	})
}

// Len returns the number of tracked buckets
func (t *RequestCountPerIpTable) Len() int {
	return int(t.size.Load())
}

// Has reports whether a bucket exists for the endpoint and client IP
func (t *RequestCountPerIpTable) Has(endpointID string, ip string) bool {
	_, ok := t.table.Load(bucketKey(endpointID, ip))
	return ok
}

// Clear the table
func (t *RequestCountPerIpTable) Clear() {
	t.table.Range(func(key, value interface{}) bool {
		if _, deleted := t.table.LoadAndDelete(key); deleted {
			t.size.Add(-1)
		}
		return true
	})
}

func (h *ProxyHandler) handleRateLimitRouting(w http.ResponseWriter, r *http.Request, pe *ProxyEndpoint) error {
	err := h.Parent.handleRateLimit(w, r, pe)
	if err != nil {
		h.Parent.logRequest(r, false, 429, "ratelimit", r.URL.Hostname(), "", pe)
	}
	return err
}

func (router *Router) handleRateLimit(w http.ResponseWriter, r *http.Request, pe *ProxyEndpoint) error {
	//Resolve the client IP using the same trusted proxy gated logic as the access
	//control check, so a header supplied address can neither break the limiter nor
	//be spoofed to escape it
	ip := router.GetClientIPForEndpoint(r, pe)
	if ip == "" {
		//Unable to resolve the client IP. Default allow passthrough
		return nil
	}

	//Each endpoint gets its own bucket per client IP
	if !router.rateLimitCounter.Allow(pe.RootOrMatchingDomain, ip, pe.RateLimit, pe.RateLimitBurst) {
		w.WriteHeader(429)
		return errors.New("rate limit exceeded")
	}

	return nil
}

// Start the ticker routine for sweeping idle rate limit buckets
func (r *Router) startRateLimterCounterResetTicker() error {
	if r.rateLimterStop != nil {
		return errors.New("another rate limiter ticker already running")
	}
	tickerStopChan := make(chan bool)
	r.rateLimterStop = tickerStopChan

	counterResetTicker := time.NewTicker(rateLimitSweepInterval)
	go func() {
		for {
			select {
			case <-tickerStopChan:
				r.rateLimterStop = nil
				return
			case <-counterResetTicker.C:
				r.rateLimitCounter.Sweep()
			}
		}
	}()

	return nil
}
