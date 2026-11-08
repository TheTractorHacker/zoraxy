// Package metrics is a small, dependency free Prometheus text exposition
// (format 0.0.4) implementation for Zoraxy.
//
// Design goals: near zero overhead when disabled (every hook is a nil/atomic
// check), no per request allocation on the hot path once an endpoint has been
// seen, and bounded label cardinality. Labels never carry raw paths or client
// addresses; the "endpoint" label is always the configured proxy rule name and
// the number of distinct endpoint labels is capped (overflow is folded into
// OverflowLabel).
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// OverflowLabel replaces label values once a cardinality cap is reached
	OverflowLabel = "__other__"
	// MaxEndpoints caps the number of distinct endpoint label values
	MaxEndpoints = 512
	// MaxEventSeries caps the series of every small event counter vector
	MaxEventSeries = 1024
)

var methodNames = [...]string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE", "OTHER"}
var classNames = [...]string{"1xx", "2xx", "3xx", "4xx", "5xx", "other"}

// DurationBuckets are the upper bounds (seconds) of the request duration histogram
var DurationBuckets = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

func methodIndex(m string) int {
	switch m {
	case "GET":
		return 0
	case "HEAD":
		return 1
	case "POST":
		return 2
	case "PUT":
		return 3
	case "DELETE":
		return 4
	case "PATCH":
		return 5
	case "OPTIONS":
		return 6
	case "CONNECT":
		return 7
	case "TRACE":
		return 8
	}
	return 9
}

func classIndex(status int) int {
	if status >= 100 && status < 600 {
		return status/100 - 1
	}
	return 5
}

// endpointStats holds the lock free counters of one endpoint
type endpointStats struct {
	requests [len(classNames)][len(methodNames)]atomic.Uint64
	inflight atomic.Int64
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	buckets  [len(DurationBuckets) + 1]atomic.Uint64 //non cumulative, last = +Inf
	durCount atomic.Uint64
	durSumNs atomic.Uint64
}

// Collector adds dynamic (pull style) metrics at scrape time
type Collector func(e *Emitter)

// Registry owns all counters. Use New. All methods are safe on a nil
// receiver and do nothing there.
type Registry struct {
	enabled atomic.Bool
	start   time.Time

	mu        sync.RWMutex
	endpoints map[string]*endpointStats

	events [numEvents]eventVec

	collMu     sync.RWMutex
	collectors []Collector
}

// New creates a disabled registry
func New() *Registry {
	r := &Registry{start: time.Now(), endpoints: map[string]*endpointStats{}}
	for i := range r.events {
		r.events[i].series = map[[2]string]*atomic.Uint64{}
	}
	return r
}

// SetEnabled switches recording on or off. Recorded values are kept.
func (r *Registry) SetEnabled(on bool) {
	if r != nil {
		r.enabled.Store(on)
	}
}

// Enabled reports whether hooks should record. Safe on nil.
func (r *Registry) Enabled() bool { return r != nil && r.enabled.Load() }

// AddCollector registers a scrape time collector
func (r *Registry) AddCollector(c Collector) {
	if r == nil || c == nil {
		return
	}
	r.collMu.Lock()
	r.collectors = append(r.collectors, c)
	r.collMu.Unlock()
}

// Uptime returns the time since the registry was created
func (r *Registry) Uptime() time.Duration { return time.Since(r.start) }

func (r *Registry) endpoint(name string) *endpointStats {
	r.mu.RLock()
	e := r.endpoints[name]
	r.mu.RUnlock()
	if e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.endpoints[name]; e != nil {
		return e
	}
	if len(r.endpoints) >= MaxEndpoints {
		name = OverflowLabel
		if e = r.endpoints[name]; e != nil {
			return e
		}
	}
	e = &endpointStats{}
	r.endpoints[name] = e
	return e
}

// EndpointCount returns the number of distinct endpoint label values in use
func (r *Registry) EndpointCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.endpoints)
}

// EventKind identifies an event counter
type EventKind int

const (
	EventRateLimited EventKind = iota
	EventAccessBlocked
	EventCaptchaChallenge
	EventCaptchaVerified
	EventCaptchaFailed
	numEvents
)

type eventVec struct {
	mu     sync.RWMutex
	series map[[2]string]*atomic.Uint64
}

// Event counts one event. detail must come from a small fixed set (for
// example "blacklist" / "whitelist"), never from request data.
func (r *Registry) Event(kind EventKind, endpoint, detail string) {
	if !r.Enabled() || kind < 0 || kind >= numEvents {
		return
	}
	v := &r.events[kind]
	key := [2]string{endpoint, detail}
	v.mu.RLock()
	c := v.series[key]
	v.mu.RUnlock()
	if c == nil {
		v.mu.Lock()
		if c = v.series[key]; c == nil {
			if len(v.series) >= MaxEventSeries {
				key = [2]string{OverflowLabel, OverflowLabel}
				c = v.series[key]
			}
			if c == nil {
				c = &atomic.Uint64{}
				v.series[key] = c
			}
		}
		v.mu.Unlock()
	}
	c.Add(1)
}

func observeDuration(e *endpointStats, d time.Duration) {
	s := d.Seconds()
	i := 0
	for i < len(DurationBuckets) && s > DurationBuckets[i] {
		i++
	}
	e.buckets[i].Add(1)
	e.durCount.Add(1)
	ns := d.Nanoseconds()
	if ns < 0 {
		ns = 0
	}
	e.durSumNs.Add(uint64(ns))
}
