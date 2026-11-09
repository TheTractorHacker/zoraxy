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

const (
	ringSize       = 1000
	maxHourBuckets = 24 * 7
)

// RuleHit is one rule that matched during a transaction
type RuleHit struct {
	ID       int      `json:"id"`
	Message  string   `json:"msg"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	Data     string   `json:"data,omitempty"` // Matched data, truncated

	// Matched variable (tuning assistant): Variable is "COLLECTION:name" as Coraza reports it (name keeps its
	// case, e.g. "REQUEST_COOKIES:ph_phc_x_posthog"), VarNorm is the canonical form used for grouping and
	// exclusions (ARGS_GET/ARGS_POST folded into ARGS, name lower-cased). Both empty when the rule did not
	// match a request variable (e.g. anomaly score rules).
	Variable string `json:"variable,omitempty"`
	VarNorm  string `json:"var_norm,omitempty"`
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
	Action        string    `json:"action"` // "blocked", "detected", "challenged" or "challenge_passed"
	WouldBlock    bool      `json:"would_block"`
	Mode          string    `json:"mode"`
	Source        string    `json:"source,omitempty"` // global, profile:X, custom, endpoint
	Rules         []RuleHit `json:"rules"`

	// Graduated response (bands.go)
	Score int    `json:"score,omitempty"` // final inbound anomaly score of the transaction
	Band  string `json:"band,omitempty"`  // "challenge" when the score was in the challenge band, whatever the action
	// --- Response inspection (outbound leak detection), see respinspect.go ---
	Kind     string       `json:"kind,omitempty"`     // "" = request event, "response" = response / leak event
	Response *ResponseHit `json:"response,omitempty"` // set when Kind is "response"
	// API protection events (apiguard.go): Kind is "api" (see EventKindAPI) and Violation the violated limit / rule code
	Violation string `json:"violation,omitempty"`
}

// EventKindAPI marks events produced by the API protection
const EventKindAPI = "api"

// AuditSink receives one JSON line per event
type AuditSink interface {
	LogRaw(line string)
}

// Stats is a snapshot of the counters
type Stats struct {
	Total       uint64            `json:"total"`
	Blocked     uint64            `json:"blocked"`
	Challenged  uint64            `json:"challenged"`       // challenge page served (graduated response)
	Passed      uint64            `json:"challenge_passed"` // request in the challenge band let through by a valid challenge cookie
	PerRule     map[string]uint64 `json:"per_rule"`
	PerEndpoint map[string]uint64 `json:"per_endpoint"`
	PerHour     []HourStat        `json:"per_hour,omitempty"` // last 24 * 7 hours with events, oldest first

	// --- Response inspection counters (also included in Total / Blocked) ---
	Response        uint64            `json:"response,omitempty"`
	ResponseBlocked uint64            `json:"response_blocked,omitempty"`
	PerSignature    map[string]uint64 `json:"per_signature,omitempty"`
	// API protection (included in Total / Blocked above)
	API          uint64            `json:"api"`
	APIBlocked   uint64            `json:"api_blocked"`
	PerViolation map[string]uint64 `json:"per_violation,omitempty"`
}

// HourStat is the event count of one hour
type HourStat struct {
	Hour    int64  `json:"hour"` // unix seconds at the start of the hour
	Total   uint64 `json:"total"`
	Blocked uint64 `json:"blocked"`

	Challenged uint64 `json:"challenged,omitempty"`
	Passed     uint64 `json:"challenge_passed,omitempty"`
}

type eventStore struct {
	mu       sync.Mutex
	ring     []Event
	next     int
	full     bool
	total    uint64
	blocked  uint64
	chall    uint64
	passed   uint64
	perRule  map[int]uint64
	perEndpt map[string]uint64
	perHour  map[int64]*HourStat
	sink     AuditSink

	respTotal       uint64            // response inspection events
	respBlocked     uint64            // response events that replaced the response
	perSig          map[string]uint64 // response events per signature id
	api, apiBlocked uint64
	perViolation    map[string]uint64
}

func newEventStore() *eventStore {
	return &eventStore{
		ring:     make([]Event, ringSize),
		perRule:  map[int]uint64{},
		perEndpt: map[string]uint64{},
		perHour:  map[int64]*HourStat{},
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
	if ev.Action == ActionChallenged {
		s.chall++
	}
	if ev.Action == ActionChallengePassed {
		s.passed++
	}
	s.perEndpt[ev.Endpoint]++
	if ev.Kind == EventKindAPI {
		s.api++
		if ev.Action == "blocked" {
			s.apiBlocked++
		}
		if s.perViolation == nil {
			s.perViolation = map[string]uint64{}
		}
		s.perViolation[ev.Violation]++
	}
	hr := ev.Time.Truncate(time.Hour).Unix()
	hs := s.perHour[hr]
	if hs == nil {
		hs = &HourStat{Hour: hr}
		s.perHour[hr] = hs
		if len(s.perHour) > maxHourBuckets {
			oldest := hr
			for k := range s.perHour {
				if k < oldest {
					oldest = k
				}
			}
			delete(s.perHour, oldest)
		}
	}
	hs.Total++
	if ev.Action == "blocked" {
		hs.Blocked++
	}
	if ev.Action == ActionChallenged {
		hs.Challenged++
	}
	if ev.Action == ActionChallengePassed {
		hs.Passed++
	}
	for _, r := range ev.Rules {
		s.perRule[r.ID]++
	}
	if ev.Kind == KindResponse && ev.Response != nil {
		s.respTotal++
		if ev.Action == "blocked" {
			s.respBlocked++
		}
		if s.perSig == nil {
			s.perSig = map[string]uint64{}
		}
		s.perSig[ev.Response.Signature]++
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
	st := Stats{Total: s.total, Blocked: s.blocked, Challenged: s.chall, Passed: s.passed, PerRule: map[string]uint64{}, PerEndpoint: map[string]uint64{}}
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
	st.API, st.APIBlocked = s.api, s.apiBlocked
	if len(s.perViolation) > 0 {
		st.PerViolation = map[string]uint64{}
		for k, v := range s.perViolation {
			st.PerViolation[k] = v
		}
	}
	for _, h := range s.perHour {
		st.PerHour = append(st.PerHour, *h)
	}
	sort.Slice(st.PerHour, func(i, j int) bool { return st.PerHour[i].Hour < st.PerHour[j].Hour })
	st.Response, st.ResponseBlocked = s.respTotal, s.respBlocked
	if len(s.perSig) > 0 {
		st.PerSignature = map[string]uint64{}
		for k, v := range s.perSig {
			st.PerSignature[k] = v
		}
	}
	return st
}
