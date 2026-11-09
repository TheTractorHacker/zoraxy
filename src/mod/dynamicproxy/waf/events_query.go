package waf

import (
	"sort"
	"time"
)

// EventFilter selects events from the ring buffer. Zero fields match everything.
type EventFilter struct {
	Limit    int
	Endpoint string
	RuleID   int       // events that matched this rule
	Action   string    // blocked / detected
	ClientIP string    // exact match
	Since    time.Time // events at or after

	// --- Response inspection filters ---
	Kind  string // "request" (rule events), "response" (leak events); empty = both
	Group string // response protection group
}

func (f EventFilter) match(ev *Event) bool {
	if f.Endpoint != "" && ev.Endpoint != f.Endpoint {
		return false
	}
	if f.Action != "" && ev.Action != f.Action {
		return false
	}
	if f.ClientIP != "" && ev.ClientIP != f.ClientIP {
		return false
	}
	if !f.Since.IsZero() && ev.Time.Before(f.Since) {
		return false
	}
	if f.Kind != "" && (f.Kind == KindResponse) != (ev.Kind == KindResponse) {
		return false
	}
	if f.Group != "" && (ev.Response == nil || ev.Response.Group != f.Group) {
		return false
	}
	if f.RuleID != 0 {
		found := false
		for _, r := range ev.Rules {
			if r.ID == f.RuleID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *eventStore) query(f EventFilter) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.next
	if s.full {
		n = len(s.ring)
	}
	out := make([]Event, 0, 64)
	for i := 1; i <= n; i++ {
		ev := &s.ring[(s.next-i+len(s.ring))%len(s.ring)]
		if !f.match(ev) {
			continue
		}
		out = append(out, *ev)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

// Count is a name with a number
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Summary aggregates the buffered events
type Summary struct {
	Events       int     `json:"events"`
	Blocked      int     `json:"blocked"`
	Detected     int     `json:"detected"`
	TopRules     []Count `json:"top_rules"`
	TopClientIPs []Count `json:"top_client_ips"`
	TopEndpoints []Count `json:"top_endpoints"`
	Response     int     `json:"response,omitempty"` // response inspection events among Events
}

func topN(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *eventStore) summary(since time.Time, top int) Summary {
	evs := s.query(EventFilter{Since: since})
	var sum Summary
	rules, ips, eps := map[string]int{}, map[string]int{}, map[string]int{}
	for _, ev := range evs {
		sum.Events++
		if ev.Action == "blocked" {
			sum.Blocked++
		} else {
			sum.Detected++
		}
		if ev.Kind == KindResponse {
			sum.Response++
		}
		ips[ev.ClientIP]++
		eps[ev.Endpoint]++
		for _, r := range ev.Rules {
			rules[itoa(r.ID)]++
		}
	}
	sum.TopRules, sum.TopClientIPs, sum.TopEndpoints = topN(rules, top), topN(ips, top), topN(eps, top)
	return sum
}
