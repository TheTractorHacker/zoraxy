package aiassist

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

/*
	Budget and rate limit, enforced server side before any network access.

	A call RESERVES an upper estimate (input estimate + max_tokens) of tokens before it starts and
	settles with the real usage afterwards, so parallel calls cannot jointly start above the cap:
	  used + sum(reserved) <= cap   at every reservation.
	Because the estimate of the input is not exact, the counter can still end above the cap by the
	estimation error of the calls that were in flight; with maxInFlight calls this is bounded by
	maxInFlight * (real input tokens - estimated input tokens), and the estimate is deliberately
	conservative (2 bytes per token), so in practice there is no overshoot. When the cap is
	reached, every further call is refused until the month changes (or the admin raises the cap).

	The counter is per calendar month (local time), persisted in usage.json, and reset lazily on
	the first call of a new month: no timer, no goroutine.
*/

const maxInFlight = 2

var (
	ErrBudget      = errors.New("the monthly token budget is used up; raise it in the AI assistant settings or wait for next month")
	ErrRateLimited = errors.New("rate limit reached; try again in a minute")
	ErrBusy        = errors.New("too many AI requests are running at the same time; try again in a moment")
)

// Usage is the persisted monthly counter.
type Usage struct {
	Month     string           `json:"month"` // 2006-01
	Tokens    int64            `json:"tokens"`
	Calls     int64            `json:"calls"`
	ByFeature map[string]int64 `json:"by_feature,omitempty"`
}

// Limiter enforces the budget and the rate.
type Limiter struct {
	mu       sync.Mutex
	path     string
	now      func() time.Time
	u        Usage
	loaded   bool
	reserved int64
	inflight int
	recent   []time.Time
}

// NewLimiter keeps usage.json in dir.
func NewLimiter(dir string) *Limiter {
	return &Limiter{path: filepath.Join(dir, "usage.json"), now: time.Now}
}

func (l *Limiter) loadLocked() {
	if !l.loaded {
		l.loaded = true
		if b, err := os.ReadFile(l.path); err == nil {
			_ = json.Unmarshal(b, &l.u)
		}
	}
	if m := l.now().Format("2006-01"); l.u.Month != m {
		l.u = Usage{Month: m}
	}
	if l.u.ByFeature == nil {
		l.u.ByFeature = map[string]int64{}
	}
}

func (l *Limiter) saveLocked() {
	b, _ := json.Marshal(l.u)
	_ = writeFileAtomic(l.path, b, 0o600)
}

// Usage returns a copy of the counter.
func (l *Limiter) Usage() Usage {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loadLocked()
	u := l.u
	u.ByFeature = map[string]int64{}
	for k, v := range l.u.ByFeature {
		u.ByFeature[k] = v
	}
	return u
}

// Reservation is released with Done.
type Reservation struct {
	l       *Limiter
	est     int64
	feature string
	done    bool
}

// Reserve admits a call that may use up to est tokens.
func (l *Limiter) Reserve(feature string, est, cap int64, perMin int) (*Reservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loadLocked()
	now := l.now()
	cut := now.Add(-time.Minute)
	k := 0
	for _, t := range l.recent {
		if t.After(cut) {
			l.recent[k] = t
			k++
		}
	}
	l.recent = l.recent[:k]
	if l.inflight >= maxInFlight {
		return nil, ErrBusy
	}
	if l.u.Tokens+l.reserved+est > cap {
		return nil, ErrBudget
	}
	if len(l.recent) >= perMin {
		return nil, ErrRateLimited
	}
	l.recent = append(l.recent, now)
	l.reserved += est
	l.inflight++
	return &Reservation{l: l, est: est, feature: feature}, nil
}

// Done settles the reservation with the real token usage (0 = unknown: the estimate is charged).
func (r *Reservation) Done(actual int64) {
	l := r.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.done {
		return
	}
	r.done = true
	l.reserved -= r.est
	l.inflight--
	l.loadLocked()
	if actual <= 0 {
		actual = r.est
	}
	l.u.Tokens += actual
	l.u.Calls++
	l.u.ByFeature[r.feature] += actual
	l.saveLocked()
}

// Cancel releases a reservation for a call that never reached the network (nothing is charged).
func (r *Reservation) Cancel() {
	l := r.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.done {
		return
	}
	r.done = true
	l.reserved -= r.est
	l.inflight--
	if n := len(l.recent); n > 0 {
		l.recent = l.recent[:n-1]
	}
}

// Fail settles a call that produced no answer and no usage report (network error, 401, cancelled
// context): nothing is known to be billed, so no tokens are added. The rate-limit slot stays used.
func (r *Reservation) Fail() {
	l := r.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.done {
		return
	}
	r.done = true
	l.reserved -= r.est
	l.inflight--
	l.loadLocked()
	l.u.Calls++
	l.saveLocked()
}
