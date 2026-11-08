package notify

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
	Delivery rules applied to the channels (not to the legacy webhooks / command hook):

	  - dedupe:     an identical event (type + subject) is sent at most once per window
	  - rate limit: at most N notifications per channel per hour
	  - quiet hours: non critical events are held and delivered as one digest afterwards
	  - digest:     optionally hold all non critical events and send one summary every N minutes
	  - test events always pass.
*/

// QuietHours is a daily window in local time
type QuietHours struct {
	Enabled      bool   `json:"enabled"`
	Start        string `json:"start"`        // "22:00"
	End          string `json:"end"`          // "07:00" (may be earlier than start: window crosses midnight)
	CriticalPass bool   `json:"criticalPass"` // critical events are still delivered immediately
}

// Digest batches non critical events
type Digest struct {
	Enabled         bool `json:"enabled"`
	IntervalMinutes int  `json:"intervalMinutes"`
}

// Rules is the global delivery policy
type Rules struct {
	Quiet            QuietHours `json:"quiet"`
	Digest           Digest     `json:"digest"`
	DedupeSeconds    int        `json:"dedupeSeconds"`    // 0 = off
	RatePerHour      int        `json:"ratePerHour"`      // per channel, 0 = unlimited
	FailThreshold    int        `json:"failThreshold"`    // consecutive failed health checks before uptime.down (min 1)
	RecoverThreshold int        `json:"recoverThreshold"` // consecutive good checks before uptime.up (min 1)
	WAFSpikeBlocks   int        `json:"wafSpikeBlocks"`   // WAF blocks within WAFSpikeWindow that raise waf.spike (0 = off)
	WAFSpikeWindow   int        `json:"wafSpikeWindow"`   // seconds
	WAFSpikeCooldown int        `json:"wafSpikeCooldown"` // seconds between two waf.spike events of one site
}

// DefaultRules are used until the administrator saves their own
func DefaultRules() Rules {
	return Rules{
		Quiet:         QuietHours{Start: "22:00", End: "07:00", CriticalPass: true},
		Digest:        Digest{IntervalMinutes: 60},
		DedupeSeconds: 300, RatePerHour: 60,
		FailThreshold: 3, RecoverThreshold: 2,
		WAFSpikeBlocks: 100, WAFSpikeWindow: 60, WAFSpikeCooldown: 900,
	}
}

func parseHM(s string) (int, bool) {
	p := strings.Split(strings.TrimSpace(s), ":")
	if len(p) != 2 {
		return 0, false
	}
	h, e1 := strconv.Atoi(p[0])
	m, e2 := strconv.Atoi(p[1])
	if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// Validate normalises the rules
func (r *Rules) Validate() error {
	if r.Quiet.Enabled {
		if _, ok := parseHM(r.Quiet.Start); !ok {
			return fmt.Errorf("invalid quiet hours start (use HH:MM)")
		}
		if _, ok := parseHM(r.Quiet.End); !ok {
			return fmt.Errorf("invalid quiet hours end (use HH:MM)")
		}
	}
	if r.Digest.IntervalMinutes < 1 {
		r.Digest.IntervalMinutes = 60
	}
	if r.Digest.IntervalMinutes > 1440 {
		return fmt.Errorf("digest interval must be at most 1440 minutes")
	}
	if r.DedupeSeconds < 0 || r.DedupeSeconds > 86400 || r.RatePerHour < 0 || r.RatePerHour > 100000 {
		return fmt.Errorf("dedupe or rate limit out of range")
	}
	if r.FailThreshold < 1 {
		r.FailThreshold = 1
	}
	if r.RecoverThreshold < 1 {
		r.RecoverThreshold = 1
	}
	if r.FailThreshold > 100 || r.RecoverThreshold > 100 {
		return fmt.Errorf("flap thresholds must be at most 100")
	}
	if r.WAFSpikeBlocks < 0 || r.WAFSpikeWindow < 0 || r.WAFSpikeCooldown < 0 || r.WAFSpikeWindow > 86400 {
		return fmt.Errorf("WAF spike values out of range")
	}
	if r.WAFSpikeBlocks > 0 && r.WAFSpikeWindow == 0 {
		r.WAFSpikeWindow = 60
	}
	return nil
}

// InQuiet reports whether t falls inside the quiet window
func (q QuietHours) InQuiet(t time.Time) bool {
	if !q.Enabled {
		return false
	}
	s, ok1 := parseHM(q.Start)
	e, ok2 := parseHM(q.End)
	if !ok1 || !ok2 || s == e {
		return false
	}
	cur := t.Hour()*60 + t.Minute()
	if s < e {
		return cur >= s && cur < e
	}
	return cur >= s || cur < e
}

// Decision of the gate
type Decision int

const (
	DecSend Decision = iota
	DecDedupe
	DecRate
	DecHeld // buffered for a digest
)

const (
	maxHeldPerChannel = 100
	maxDedupeKeys     = 2000
)

type held struct {
	line string
	at   time.Time
}

type gate struct {
	mu       sync.Mutex
	seen     map[string]time.Time   // channel|event|subject -> last sent
	sent     map[string][]time.Time // channel -> send times within the last hour
	buf      map[string][]held      // channel -> held events
	dropped  map[string]int
	lastFlus map[string]time.Time
}

func newGate() *gate {
	return &gate{seen: map[string]time.Time{}, sent: map[string][]time.Time{}, buf: map[string][]held{}, dropped: map[string]int{}, lastFlus: map[string]time.Time{}}
}

func eventLine(ev Event, now time.Time) string {
	t, _ := Describe(ev)
	return now.Format("15:04") + " " + t
}

// check decides what to do with an event for a channel and records the outcome
func (g *gate) check(rules Rules, chID string, ev Event, now time.Time) Decision {
	if ev.Event == EventTest || ev.Event == EventDigest {
		return DecSend
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	sev := SeverityOf(ev.Event)

	if rules.DedupeSeconds > 0 {
		key := chID + "|" + ev.Event + "|" + ev.Subject
		if t, ok := g.seen[key]; ok && now.Sub(t) < time.Duration(rules.DedupeSeconds)*time.Second {
			return DecDedupe
		}
		if len(g.seen) >= maxDedupeKeys {
			for k, t := range g.seen {
				if now.Sub(t) > time.Duration(rules.DedupeSeconds)*time.Second {
					delete(g.seen, k)
				}
			}
			if len(g.seen) >= maxDedupeKeys { // still full: forget everything rather than grow
				g.seen = map[string]time.Time{}
			}
		}
		g.seen[key] = now
	}

	critical := sev == SevCritical
	hold := false
	if rules.Quiet.InQuiet(now) && !(critical && rules.Quiet.CriticalPass) {
		hold = true
	}
	if rules.Digest.Enabled && !critical {
		hold = true
	}
	if hold {
		if len(g.buf[chID]) >= maxHeldPerChannel {
			g.dropped[chID]++
		} else {
			g.buf[chID] = append(g.buf[chID], held{eventLine(ev, now), now})
		}
		return DecHeld
	}

	if rules.RatePerHour > 0 {
		list := g.sent[chID][:0:0]
		for _, t := range g.sent[chID] {
			if now.Sub(t) < time.Hour {
				list = append(list, t)
			}
		}
		if len(list) >= rules.RatePerHour {
			g.sent[chID] = list
			return DecRate
		}
		g.sent[chID] = append(list, now)
	}
	return DecSend
}

// takeHeld returns the digest to send for a channel now (nil when nothing is due)
func (g *gate) takeHeld(rules Rules, chID string, now time.Time) *Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	items := g.buf[chID]
	if len(items) == 0 {
		return nil
	}
	if rules.Quiet.InQuiet(now) {
		return nil
	}
	if rules.Digest.Enabled {
		last, ok := g.lastFlus[chID]
		if !ok {
			g.lastFlus[chID] = items[0].at
			last = items[0].at
		}
		if now.Sub(last) < time.Duration(rules.Digest.IntervalMinutes)*time.Minute {
			return nil
		}
	}
	g.lastFlus[chID] = now
	lines := make([]string, 0, len(items)+1)
	for _, h := range items {
		lines = append(lines, h.line)
	}
	if d := g.dropped[chID]; d > 0 {
		lines = append(lines, fmt.Sprintf("... and %d more event(s) not shown", d))
	}
	g.buf[chID] = nil
	g.dropped[chID] = 0
	sort.Strings(lines[:len(items)])
	return &Event{Event: EventDigest, Time: now.UTC(), Source: "notify", Extra: map[string]string{"count": strconv.Itoa(len(items)), "lines": strings.Join(lines, "\n")}}
}

// forget drops all state of a deleted channel
func (g *gate) forget(chID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.sent, chID)
	delete(g.buf, chID)
	delete(g.dropped, chID)
	delete(g.lastFlus, chID)
	for k := range g.seen {
		if strings.HasPrefix(k, chID+"|") {
			delete(g.seen, k)
		}
	}
}
