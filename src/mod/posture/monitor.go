package posture

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

/*
	Monitor decides when a change of the posture is worth one notification. It is off by default (the host only
	calls Observe when the administrator enabled it) and at most one notification is raised per MinGap.

	A notification is raised when the score fell by DropPoints or more since the baseline, or when a check that
	was not failing at the baseline fails now. The baseline is the last accepted state: it moves up when things
	improve, and is replaced by the current state when a notification is raised. Small declines do not move it,
	so a slow slide still adds up to a drop.
*/

const (
	// DropPoints is the score loss that raises a notification
	DropPoints = 10
	// MinGap is the minimum time between two notifications
	MinGap = 6 * time.Hour
)

// Baseline is the state the monitor compares with
type Baseline struct {
	Score        int       `json:"score"`
	Failing      []string  `json:"failing"`
	LastNotified time.Time `json:"lastNotified"`
}

// BaselineStore persists the baseline
type BaselineStore interface {
	Load() (Baseline, bool)
	Save(Baseline)
}

// Monitor compares evaluations with the baseline
type Monitor struct {
	Store BaselineStore
	// Emit raises the notification: a short subject and a longer description
	Emit func(subject, detail string)
	Now  func() time.Time
}

func failingIDs(rep Report) []string {
	var ids []string
	for _, c := range rep.Checks {
		if c.Status == StatusFail {
			ids = append(ids, c.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func titleOf(rep Report, id string) string {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c.Title
		}
	}
	return id
}

// Observe compares one evaluation with the baseline. It returns true when a notification was raised.
func (m *Monitor) Observe(rep Report) bool {
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	cur := Baseline{Score: rep.Score.Value, Failing: failingIDs(rep)}
	base, ok := m.Store.Load()
	if !ok {
		m.Store.Save(cur)
		return false
	}
	known := map[string]bool{}
	for _, id := range base.Failing {
		known[id] = true
	}
	var fresh []string
	for _, id := range cur.Failing {
		if !known[id] {
			fresh = append(fresh, id)
		}
	}
	dropped := base.Score-cur.Score >= DropPoints
	if (dropped || len(fresh) > 0) && (base.LastNotified.IsZero() || now.Sub(base.LastNotified) >= MinGap) {
		var why []string
		if dropped {
			why = append(why, fmt.Sprintf("the score fell from %d to %d", base.Score, cur.Score))
		}
		if len(fresh) > 0 {
			var t []string
			for _, id := range fresh {
				t = append(t, titleOf(rep, id))
			}
			why = append(why, "newly failing: "+strings.Join(t, "; "))
		}
		if m.Emit != nil {
			m.Emit(fmt.Sprintf("Security score %d (%s)", cur.Score, rep.Score.Label), strings.Join(why, ", "))
		}
		cur.LastNotified = now
		m.Store.Save(cur)
		return true
	}
	// no notification: move the baseline up on improvement, forget failures that went away
	next := Baseline{Score: base.Score, LastNotified: base.LastNotified}
	if cur.Score > next.Score {
		next.Score = cur.Score
	}
	now2 := map[string]bool{}
	for _, id := range cur.Failing {
		now2[id] = true
	}
	for _, id := range base.Failing {
		if now2[id] {
			next.Failing = append(next.Failing, id)
		}
	}
	m.Store.Save(next)
	return false
}
