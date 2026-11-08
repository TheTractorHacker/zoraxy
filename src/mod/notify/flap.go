package notify

import (
	"sync"
	"time"
)

/*
	Flap suppression for the uptime monitor and spike detection for WAF blocks.

	FlapTracker turns a stream of individual health check results into debounced
	state transitions: a target is only reported down after FailThreshold consecutive
	failures, and reported up again after RecoverThreshold consecutive successes.
*/

// Transition is a debounced state change
type Transition struct {
	ID       string
	Down     bool          // true = went down, false = recovered
	Failures int           // consecutive failures at the time of going down
	Downtime time.Duration // only for recoveries
}

type flapState struct {
	down      bool
	fails     int
	oks       int
	downSince time.Time
}

// FlapTracker is safe for concurrent use
type FlapTracker struct {
	mu      sync.Mutex
	states  map[string]*flapState
	fail    func() int
	recover func() int
}

// NewFlapTracker creates a tracker; thresholds are read on every observation so rule changes apply at once
func NewFlapTracker(failThreshold, recoverThreshold func() int) *FlapTracker {
	return &FlapTracker{states: map[string]*flapState{}, fail: failThreshold, recover: recoverThreshold}
}

const maxFlapTargets = 4096

// Observe records one check result and returns a Transition when the debounced state changed
func (f *FlapTracker) Observe(id string, ok bool, now time.Time) *Transition {
	failN, recN := 3, 2
	if f.fail != nil {
		failN = f.fail()
	}
	if f.recover != nil {
		recN = f.recover()
	}
	if failN < 1 {
		failN = 1
	}
	if recN < 1 {
		recN = 1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.states[id]
	if st == nil {
		if len(f.states) >= maxFlapTargets {
			return nil
		}
		st = &flapState{}
		f.states[id] = st
	}
	if ok {
		st.fails = 0
		if !st.down {
			st.oks = 0
			return nil
		}
		st.oks++
		if st.oks >= recN {
			st.down, st.oks = false, 0
			return &Transition{ID: id, Down: false, Downtime: now.Sub(st.downSince)}
		}
		return nil
	}
	st.oks = 0
	st.fails++
	if !st.down && st.fails >= failN {
		st.down, st.downSince = true, now
		return &Transition{ID: id, Down: true, Failures: st.fails}
	}
	return nil
}

// Forget removes state of targets that no longer exist
func (f *FlapTracker) Forget(keep map[string]bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id := range f.states {
		if !keep[id] {
			delete(f.states, id)
		}
	}
}

// SpikeDetector raises a signal when a key sees at least N hits within a window,
// at most once per cooldown. Keys are bounded.
type SpikeDetector struct {
	mu    sync.Mutex
	hits  map[string]*spikeState
	conf  func() (n int, window, cooldown time.Duration)
	limit int
}

type spikeState struct {
	times []time.Time
	last  time.Time
}

// NewSpikeDetector creates a detector with a live configuration
func NewSpikeDetector(conf func() (int, time.Duration, time.Duration)) *SpikeDetector {
	return &SpikeDetector{hits: map[string]*spikeState{}, conf: conf, limit: 512}
}

// Hit records one occurrence; it returns the count in the window when a spike is raised, else 0
func (d *SpikeDetector) Hit(key string, now time.Time) int {
	n, window, cooldown := d.conf()
	if n <= 0 || window <= 0 {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.hits[key]
	if st == nil {
		if len(d.hits) >= d.limit {
			return 0 // bounded: ignore new keys when full
		}
		st = &spikeState{}
		d.hits[key] = st
	}
	cut := now.Add(-window)
	i := 0
	for i < len(st.times) && st.times[i].Before(cut) {
		i++
	}
	st.times = append(st.times[i:], now)
	if len(st.times) > n+1 { // never keep more than needed
		st.times = st.times[len(st.times)-n-1:]
	}
	if len(st.times) >= n && (st.last.IsZero() || now.Sub(st.last) >= cooldown) {
		st.last = now
		return len(st.times)
	}
	return 0
}
