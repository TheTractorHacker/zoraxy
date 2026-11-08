package waf

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

/*
	events.go

	WAF audit events: structured JSON lines written to the Zoraxy log folder
	(via an AuditSink, normally a logger.Logger so rotation matches the rest of
	the system), a ring buffer of recent events for the UI, and per rule /
	per endpoint counters.
*/

const ringSize = 1000

// RuleHit is one rule that matched during a transaction
type RuleHit struct {
	ID       int      `json:"id"`
	Message  string   `json:"msg"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	Data     string   `json:"data,omitempty"` // Matched data, truncated
}

// Event is one WAF decision that matched at least one rule
type Event struct {
	Time          time.Time `json:"time"`
	TransactionID string    `json:"txid"`
	Endpoint      string    `json:"endpoint"`
	ClientIP      string    `json:"client_ip"`
	Method        string    `json:"method"`
	Host          string    `json:"host"`
	Path          string    `json:"path"`
	URI           string    `json:"uri"`
	Action        string    `json:"action"` // "blocked" or "detected"
	WouldBlock    bool      `json:"would_block"`
	Mode          string    `json:"mode"`
	Rules         []RuleHit `json:"rules"`
}

// AuditSink receives one JSON line per event
type AuditSink interface {
	LogRaw(line string)
}

// Stats is a snapshot of the counters
type Stats struct {
	Total       uint64            `json:"total"`
	Blocked     uint64            `json:"blocked"`
	PerRule     map[string]uint64 `json:"per_rule"`
	PerEndpoint map[string]uint64 `json:"per_endpoint"`
}

type eventStore struct {
	mu       sync.Mutex
	ring     []Event
	next     int
	full     bool
	total    uint64
	blocked  uint64
	perRule  map[int]uint64
	perEndpt map[string]uint64
	sink     AuditSink
}

func newEventStore() *eventStore {
	return &eventStore{
		ring:     make([]Event, ringSize),
		perRule:  map[int]uint64{},
		perEndpt: map[string]uint64{},
	}
}

func (s *eventStore) setSink(sink AuditSink) {
	s.mu.Lock()
	s.sink = sink
	s.mu.Unlock()
}

func (s *eventStore) add(ev Event) {
	s.mu.Lock()
	s.ring[s.next] = ev
	s.next = (s.next + 1) % len(s.ring)
	if s.next == 0 {
		s.full = true
	}
	s.total++
	if ev.Action == "blocked" {
		s.blocked++
	}
	s.perEndpt[ev.Endpoint]++
	for _, r := range ev.Rules {
		s.perRule[r.ID]++
	}
	sink := s.sink
	s.mu.Unlock()

	if sink != nil {
		if line, err := json.Marshal(ev); err == nil {
			sink.LogRaw(string(line))
		}
	}
}

// recent returns events newest first, optionally filtered by endpoint
func (s *eventStore) recent(limit int, endpoint string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.next
	if s.full {
		n = len(s.ring)
	}
	out := make([]Event, 0, 64)
	for i := 1; i <= n; i++ {
		idx := (s.next - i + len(s.ring)) % len(s.ring)
		ev := s.ring[idx]
		if endpoint != "" && ev.Endpoint != endpoint {
			continue
		}
		out = append(out, ev)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func (s *eventStore) stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Total: s.total, Blocked: s.blocked, PerRule: map[string]uint64{}, PerEndpoint: map[string]uint64{}}
	ids := make([]int, 0, len(s.perRule))
	for id := range s.perRule {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		st.PerRule[itoa(id)] = s.perRule[id]
	}
	for k, v := range s.perEndpt {
		st.PerEndpoint[k] = v
	}
	return st
}
