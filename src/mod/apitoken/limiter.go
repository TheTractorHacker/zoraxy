package apitoken

import (
	"sync"
	"time"
)

const (
	rateBurst       = 30.0 // bucket size per token and per IP
	ratePerSecond   = 10.0
	failLimit       = 10 // failed auths per window per IP before blocking
	failWindow      = time.Minute
	cleanupInterval = 5 * time.Minute
)

type bucket struct {
	tokens float64
	last   time.Time
}

type failEntry struct {
	count int
	start time.Time
}

type limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*bucket
	fails   map[string]*failEntry
	swept   time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, buckets: map[string]*bucket{}, fails: map[string]*failEntry{}, swept: now()}
}

func (l *limiter) take(key string, t time.Time) bool {
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: rateBurst, last: t}
		l.buckets[key] = b
	}
	b.tokens += t.Sub(b.last).Seconds() * ratePerSecond
	if b.tokens > rateBurst {
		b.tokens = rateBurst
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) sweep(t time.Time) {
	if t.Sub(l.swept) < cleanupInterval {
		return
	}
	l.swept = t
	for k, b := range l.buckets {
		if t.Sub(b.last) > cleanupInterval {
			delete(l.buckets, k)
		}
	}
	for k, f := range l.fails {
		if t.Sub(f.start) > failWindow {
			delete(l.fails, k)
		}
	}
}

// allow charges one request to both the token bucket and the IP bucket.
func (l *limiter) allow(tokenID, ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	l.sweep(t)
	okT := l.take("t:"+tokenID, t)
	okI := l.take("i:"+ip, t)
	return okT && okI
}

func (l *limiter) failureAllowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[ip]
	if f == nil {
		return true
	}
	if l.now().Sub(f.start) > failWindow {
		delete(l.fails, ip)
		return true
	}
	return f.count < failLimit
}

func (l *limiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	l.sweep(t)
	f := l.fails[ip]
	if f == nil || t.Sub(f.start) > failWindow {
		l.fails[ip] = &failEntry{count: 1, start: t}
		return
	}
	f.count++
}
