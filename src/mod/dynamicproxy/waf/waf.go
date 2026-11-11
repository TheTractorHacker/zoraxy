package waf

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

/*
	waf.go

	Instance: a compiled WAF for one configuration, shared by every endpoint
	that has the same effective settings.
	Inspect: runs one request through the WAF.
*/

func itoa(i int) string { return strconv.Itoa(i) }

// anomalyEvaluationRuleID is the CRS rule that evaluates the inbound anomaly
// score. If it matched, the request reached the blocking threshold.
const anomalyEvaluationRuleID = 949110

// Instance is a compiled WAF plus its settings. Safe for concurrent use.
type Instance struct {
	cfg    Config
	waf    coraza.WAF
	events *eventStore
}

// RequestInfo carries what the waf package needs to know about the endpoint
// and the (trusted) client without importing the dynamicproxy package.
type RequestInfo struct {
	Endpoint string // Endpoint identifier for logs and counters
	ClientIP string // Trusted client IP (as resolved by the router)
	Source   string // Where the effective config comes from (global, profile:X, custom, endpoint)
	// OnBlock writes the response for a blocked request. txID is the
	// transaction ID to show to the user. If nil a plain 403 is written.
	OnBlock func(w http.ResponseWriter, r *http.Request, txID string)
	// OnEvent (optional) receives the audit event of a transaction that matched at least one rule,
	// before OnBlock runs. Used to tell the blocked-request log which rule blocked the request.
	OnEvent func(ev Event)

	// Graduated response (bands.go). Both optional.
	// ChallengeValid reports whether the request carries a valid challenge cookie (client IP, User-Agent and
	// endpoint bound). OnChallenge writes the challenge page (the existing CAPTCHA machinery). When OnChallenge
	// is nil, or the client cannot render a page (see CanChallenge), a request in the challenge band is blocked.
	ChallengeValid func(r *http.Request) bool
	OnChallenge    func(w http.ResponseWriter, r *http.Request, txID string)
}

// Mode returns the effective mode
func (in *Instance) Mode() string { return in.cfg.Mode }

// shouldBypass reports requests that must be passed through without any inspection
func shouldBypass(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if len(ct) >= 16 && strings.EqualFold(ct[:16], "application/grpc") {
		return true
	}
	// WebSocket (and any other protocol upgrade) is handled by the hijacking
	// path of the proxy, which must not be wrapped or delayed.
	if r.Header.Get("Upgrade") != "" {
		return true
	}
	return false
}

// Inspect runs the request through the WAF. It returns true if the request
// was blocked and a response has already been written; the caller must stop.
// In detection_only mode it never returns true. The request body (if any) is
// replayed so the upstream receives identical bytes.
func (in *Instance) Inspect(w http.ResponseWriter, r *http.Request, info RequestInfo) (blocked bool) {
	if in == nil || shouldBypass(r) {
		return false
	}
	// A WAF problem must never take the proxy down: fail open on panic.
	defer func() {
		if rec := recover(); rec != nil {
			blocked = false
		}
	}()

	tx := in.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	it := in.process(tx, r, info)
	hits := collectHits(tx)
	if len(hits) == 0 && it == nil {
		return false
	}

	wouldBlock := it != nil
	for _, h := range hits {
		if h.ID == anomalyEvaluationRuleID {
			wouldBlock = true
		}
	}
	doBlock := in.cfg.Mode == ModeBlock && it != nil

	// Graduated response: an uninterrupted transaction whose score reached the challenge threshold
	score := anomalyScore(tx)
	band, doChallenge := "", false
	if in.cfg.Mode == ModeBlock && !doBlock && in.cfg.ChallengeThreshold > 0 && score >= in.cfg.ChallengeThreshold {
		band = "challenge"
	}
	passed := false
	if band != "" {
		switch {
		case info.ChallengeValid != nil && info.ChallengeValid(r):
			passed = true
		case info.OnChallenge != nil && CanChallenge(r):
			doChallenge = true
		default:
			doBlock = true // no provider / client cannot show a page: the safe answer is the block band
		}
	}

	if len(hits) > 0 {
		action := "detected"
		switch {
		case doBlock:
			action = "blocked"
		case doChallenge:
			action = ActionChallenged
		case passed:
			action = ActionChallengePassed
		}
		ev := Event{
			Time:          time.Now(),
			TransactionID: tx.ID(),
			Endpoint:      info.Endpoint,
			ClientIP:      info.ClientIP,
			Method:        r.Method,
			Host:          r.Host,
			Path:          r.URL.Path,
			URI:           truncate(r.URL.RequestURI(), 512),
			Action:        action,
			WouldBlock:    wouldBlock,
			Mode:          in.cfg.Mode,
			Source:        info.Source,
			Rules:         hits,
			Score:         score,
			Band:          band,
		}
		in.events.add(ev)
		if info.OnEvent != nil {
			info.OnEvent(ev)
		}
	}

	if doChallenge {
		info.OnChallenge(w, r, tx.ID())
		return true
	}
	if doBlock {
		if info.OnBlock != nil {
			info.OnBlock(w, r, tx.ID())
		} else {
			http.Error(w, "403 Forbidden (request ID "+tx.ID()+")", http.StatusForbidden)
		}
		return true
	}
	return false
}

// process feeds the request to the transaction and returns an interruption, if any
func (in *Instance) process(tx types.Transaction, r *http.Request, info RequestInfo) *types.Interruption {
	host, portStr, err := net.SplitHostPort(info.ClientIP)
	if err != nil {
		host, portStr = info.ClientIP, "0"
	}
	port, _ := strconv.Atoi(portStr)
	tx.ProcessConnection(host, port, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it
	}

	if r.Body == nil || r.Body == http.NoBody || !tx.IsRequestBodyAccessible() {
		return bodyDone(tx)
	}

	limit := in.cfg.MaxBodyBytes
	if r.ContentLength > limit {
		// Known to be too large: pass through untouched, headers only
		return bodyDone(tx)
	}

	orig := r.Body
	buf, readErr := io.ReadAll(io.LimitReader(orig, limit+1))
	switch {
	case readErr != nil:
		// Client went away or errored mid body. Hand the upstream what we
		// have plus the same error, and skip body inspection.
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf), errReader{readErr}), closer: orig}
		return bodyDone(tx)
	case int64(len(buf)) > limit:
		// Larger than the limit: replay what was buffered (bounded by the
		// limit) followed by the rest of the stream, uninspected.
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf), orig), closer: orig}
		return bodyDone(tx)
	}
	r.Body = &replayBody{Reader: bytes.NewReader(buf), closer: orig}
	if len(buf) > 0 {
		if it, _, err := tx.WriteRequestBody(buf); err != nil || it != nil {
			return it
		}
	}
	return bodyDone(tx)
}

func bodyDone(tx types.Transaction) *types.Interruption {
	it, _ := tx.ProcessRequestBody()
	return it
}

type replayBody struct {
	io.Reader
	closer io.Closer
}

func (b *replayBody) Close() error { return b.closer.Close() }

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func collectHits(tx types.Transaction) []RuleHit {
	var hits []RuleHit
	for _, mr := range tx.MatchedRules() {
		rid := mr.Rule().ID()
		isBookkeeping := (rid >= 190000 && rid < 202000) || (rid >= 900000 && rid < 902000)
		if isBookkeeping || (mr.Message() == "" && rid < 1000000) {
			continue // init / setvar rules, not detections
		}
		rule := mr.Rule()
		var data string
		for _, md := range mr.MatchedDatas() {
			if md.Value() != "" {
				data = truncate(md.Value(), 120)
				break
			}
		}
		variable, varNorm := matchedVariable(mr)
		hits = append(hits, RuleHit{
			ID:       rule.ID(),
			Message:  truncate(mr.Message(), 200),
			Severity: rule.Severity().String(),
			Tags:     rule.Tags(),
			Data:     data,
			Variable: variable,
			VarNorm:  varNorm,
		})
	}
	return hits
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

/*
	Manager: cache of compiled instances, shared event store
*/

const maxCachedInstances = 48

// Manager owns the compiled-instance cache and the event store
type Manager struct {
	mu     sync.Mutex
	cache  map[string]*Instance
	order  []string // oldest first
	events *eventStore
}

// NewManager creates an empty manager
func NewManager() *Manager {
	return &Manager{cache: map[string]*Instance{}, events: newEventStore()}
}

// Default is the process wide manager
var Default = NewManager()

// SetAuditSink sets where JSON audit lines are written (nil disables file output)
func (m *Manager) SetAuditSink(s AuditSink) { m.events.setSink(s) }

// Get returns the instance for a config, compiling it if needed. It returns
// (nil, nil) when the config is nil or the mode is off, and an error when
// the config or custom rules are invalid.
func (m *Manager) Get(c *Config) (*Instance, error) {
	if c == nil {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	n := c.Normalize()
	if n.Mode == ModeOff {
		return nil, nil
	}
	key := c.Hash()

	m.mu.Lock()
	if in, ok := m.cache[key]; ok {
		m.mu.Unlock()
		return in, nil
	}
	m.mu.Unlock()

	// Compile outside the lock; it takes a moment.
	w, err := compile(n)
	if err != nil {
		return nil, err
	}
	in := &Instance{cfg: n, waf: w, events: m.events}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.cache[key]; ok {
		return existing, nil
	}
	m.cache[key] = in
	m.order = append(m.order, key)
	for len(m.order) > maxCachedInstances {
		delete(m.cache, m.order[0])
		m.order = m.order[1:]
	}
	return in, nil
}

// Validate compiles the config to check it, without keeping it active
func (m *Manager) Validate(c *Config) error {
	_, err := m.Get(c)
	return err
}

// RecentEvents returns recent events, newest first
func (m *Manager) RecentEvents(limit int, endpoint string) []Event {
	return m.events.recent(limit, endpoint)
}

// QueryEvents returns recent events matching the filter, newest first
func (m *Manager) QueryEvents(f EventFilter) []Event { return m.events.query(f) }

// Summary aggregates the buffered events newer than since
func (m *Manager) Summary(since time.Time, top int) Summary { return m.events.summary(since, top) }

// CacheSize returns the number of compiled instances currently cached
func (m *Manager) CacheSize() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cache)
}

// Stats returns a snapshot of the counters
func (m *Manager) Stats() Stats { return m.events.stats() }

// mainHit is the rule that decided the event (the anomaly score evaluation only when nothing else matched)
func (ev Event) mainHit() *RuleHit {
	for i := range ev.Rules {
		if ev.Rules[i].ID != anomalyEvaluationRuleID {
			return &ev.Rules[i]
		}
	}
	if len(ev.Rules) > 0 {
		return &ev.Rules[0]
	}
	return nil
}

// BlockRuleID is the ID of the rule that decided the event, 0 when none matched (API protection events)
func (ev Event) BlockRuleID() int {
	if m := ev.mainHit(); m != nil {
		return m.ID
	}
	return 0
}

// BlockSummary returns a short human readable description of the rules that decided the event: the
// matched rules other than the generic anomaly score evaluation first, e.g.
// "942100 SQL Injection Attack Detected via libinjection (+2 more) [tx abc]".
func (ev Event) BlockSummary() string {
	main := ev.mainHit()
	if main == nil {
		return "tx " + ev.TransactionID
	}
	out := itoa(main.ID)
	if main.Message != "" {
		out += " " + main.Message
	}
	if n := len(ev.Rules) - 1; n > 0 {
		out += " (+" + itoa(n) + " more)"
	}
	return out + " [tx " + ev.TransactionID + "]"
}
