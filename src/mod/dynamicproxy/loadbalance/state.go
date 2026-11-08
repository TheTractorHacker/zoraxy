package loadbalance

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

/*
	Per upstream runtime state

	Everything here lives in memory only (never serialized). A freshly created
	Upstream starts healthy with no history. All time dependent functions take
	the current time as a parameter so they can be tested with a fake clock.
*/

const (
	ewmaAlpha          = 0.3  //Weight of the newest time-to-first-byte sample
	slowStartMinFactor = 0.1  //Initial weight fraction when slow start begins
	minEWMASeconds     = 1e-6 //Floor for scoring so an unmeasured upstream still compares by load
)

type upstreamRuntime struct {
	inflight atomic.Int64
	ewmaBits atomic.Uint64 //float64 seconds, 0 = no sample yet

	mu           sync.Mutex
	consecFails  int       //Consecutive passive failures
	ejectedUntil time.Time //Zero = not ejected
	slowStart    time.Time //When the weight ramp began (zero = none)
	ejections    int64     //Total number of passive ejections, informational

	activeUnhealthy bool
	activeRise      int //Consecutive successful probes while unhealthy
	activeFall      int //Consecutive failed probes while healthy
	lastCheck       time.Time
	lastCheckErr    string
}

// UpstreamState is a snapshot of the live state of an upstream, for the admin UI
type UpstreamState struct {
	State               string //healthy, unhealthy, ejected, draining, slow_start
	InFlight            int64
	EWMAMillis          float64 //EWMA of time to first byte, 0 = no sample yet
	ConsecutiveFailures int
	EjectedUntil        int64 //Unix seconds, 0 = not ejected
	ActiveHealthy       bool
	LastCheck           int64 //Unix seconds of last active probe, 0 = never
	LastCheckError      string
	SlowStartFactor     float64 //1 = full weight
	Ejections           int64
}

// Acquire marks the start of a request on this upstream
func (u *Upstream) Acquire() { u.rt.inflight.Add(1) }

// Release marks the end of a request on this upstream
func (u *Upstream) Release() { u.rt.inflight.Add(-1) }

// InFlight returns the number of requests currently being served by this upstream
func (u *Upstream) InFlight() int64 { return u.rt.inflight.Load() }

// atCapacity returns true if MaxInFlight is set and reached
func (u *Upstream) atCapacity() bool {
	return u.MaxInFlight > 0 && u.rt.inflight.Load() >= int64(u.MaxInFlight)
}

// EWMA returns the smoothed time to first byte, 0 if there is no sample yet
func (u *Upstream) EWMA() time.Duration {
	return time.Duration(math.Float64frombits(u.rt.ewmaBits.Load()) * float64(time.Second))
}

// observeLatency feeds a time to first byte sample into the EWMA
func (u *Upstream) observeLatency(d time.Duration) {
	sample := d.Seconds()
	if sample <= 0 {
		sample = minEWMASeconds
	}
	for {
		old := u.rt.ewmaBits.Load()
		prev := math.Float64frombits(old)
		next := sample
		if prev > 0 {
			next = ewmaAlpha*sample + (1-ewmaAlpha)*prev
		}
		if u.rt.ewmaBits.CompareAndSwap(old, math.Float64bits(next)) {
			return
		}
	}
}

// isEjected returns true while the passive cooldown has not passed yet
func (u *Upstream) isEjected(now time.Time) bool {
	u.rt.mu.Lock()
	defer u.rt.mu.Unlock()
	return now.Before(u.rt.ejectedUntil)
}

// isHealthy returns false if the upstream is ejected or failed active checks
func (u *Upstream) isHealthy(now time.Time) bool {
	u.rt.mu.Lock()
	defer u.rt.mu.Unlock()
	return !u.rt.activeUnhealthy && !now.Before(u.rt.ejectedUntil)
}

// slowStartFactor returns the fraction (slowStartMinFactor..1) of the weight to use now
func (u *Upstream) slowStartFactor(now time.Time, d time.Duration) float64 {
	if d <= 0 {
		return 1
	}
	u.rt.mu.Lock()
	start := u.rt.slowStart
	u.rt.mu.Unlock()
	if start.IsZero() || !now.After(start) {
		if start.IsZero() {
			return 1
		}
		return slowStartMinFactor
	}
	elapsed := now.Sub(start)
	if elapsed >= d {
		return 1
	}
	return slowStartMinFactor + (1-slowStartMinFactor)*float64(elapsed)/float64(d)
}

// reportPassive records the outcome of a real request. Returns true if this call ejected the upstream
func (u *Upstream) reportPassive(p PassiveHealthCheck, failed bool, now time.Time) bool {
	u.rt.mu.Lock()
	defer u.rt.mu.Unlock()
	if !failed {
		u.rt.consecFails = 0
		return false
	}
	u.rt.consecFails++
	if u.rt.consecFails < p.FailThreshold || now.Before(u.rt.ejectedUntil) {
		return false
	}
	//Eject. The failure counter is kept so a single failure after the
	//cooldown ejects again (half-open behaviour)
	cool := time.Duration(p.CooldownSeconds) * time.Second
	u.rt.ejectedUntil = now.Add(cool)
	u.rt.slowStart = u.rt.ejectedUntil //Ramp starts when the cooldown ends
	u.rt.ejections++
	return true
}

// reportActive feeds one active probe result into the rise/fall state machine.
// Returns true if the healthy state changed
func (u *Upstream) reportActive(hc ActiveHealthCheck, ok bool, errText string, now time.Time) bool {
	u.rt.mu.Lock()
	defer u.rt.mu.Unlock()
	u.rt.lastCheck = now
	u.rt.lastCheckErr = errText
	if u.rt.activeUnhealthy {
		if !ok {
			u.rt.activeRise = 0
			return false
		}
		u.rt.activeRise++
		if u.rt.activeRise >= hc.Rise {
			u.rt.activeUnhealthy = false
			u.rt.activeRise, u.rt.activeFall = 0, 0
			u.rt.slowStart = now
			return true
		}
		return false
	}
	if ok {
		u.rt.activeFall = 0
		return false
	}
	u.rt.activeFall++
	if u.rt.activeFall >= hc.Fall {
		u.rt.activeUnhealthy = true
		u.rt.activeRise, u.rt.activeFall = 0, 0
		return true
	}
	return false
}

// resetActive clears the active health state (used when checks get disabled)
func (u *Upstream) resetActive() {
	u.rt.mu.Lock()
	u.rt.activeUnhealthy = false
	u.rt.activeRise, u.rt.activeFall = 0, 0
	u.rt.lastCheck = time.Time{}
	u.rt.lastCheckErr = ""
	u.rt.mu.Unlock()
}

// GetState returns a snapshot of the live state of this upstream
func (u *Upstream) GetState(now time.Time, cfg *Config) UpstreamState {
	factor := u.slowStartFactor(now, cfg.slowStart())
	u.rt.mu.Lock()
	st := UpstreamState{
		InFlight:            u.rt.inflight.Load(),
		EWMAMillis:          math.Float64frombits(u.rt.ewmaBits.Load()) * 1000,
		ConsecutiveFailures: u.rt.consecFails,
		ActiveHealthy:       !u.rt.activeUnhealthy,
		LastCheckError:      u.rt.lastCheckErr,
		SlowStartFactor:     factor,
		Ejections:           u.rt.ejections,
	}
	if !u.rt.lastCheck.IsZero() {
		st.LastCheck = u.rt.lastCheck.Unix()
	}
	ejected := now.Before(u.rt.ejectedUntil)
	if ejected {
		st.EjectedUntil = u.rt.ejectedUntil.Unix()
	}
	unhealthy := u.rt.activeUnhealthy
	u.rt.mu.Unlock()

	switch {
	case u.Draining:
		st.State = "draining"
	case ejected:
		st.State = "ejected"
	case unhealthy:
		st.State = "unhealthy"
	case factor < 1:
		st.State = "slow_start"
	default:
		st.State = "healthy"
	}
	return st
}
