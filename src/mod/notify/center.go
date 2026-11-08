package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	Notification centre: channels, delivery rules, delivery log and the event sources
	that need state (uptime flap suppression, WAF spike detection).
	The legacy webhooks and the command hook keep working unchanged next to it.
*/

// testTLS lets tests trust a self-signed receiver; always nil in production
var testTLS *tls.Config

const (
	maxChannels      = 32
	deliveryLogSize  = 200
	maxTemplateBytes = 4096
	maxBodyBytes     = 64 << 10
)

// DeliveryRecord is one line of the delivery log (kept in memory only)
type DeliveryRecord struct {
	Time    time.Time `json:"time"`
	Channel string    `json:"channel"`
	Kind    string    `json:"kind"` // channel type, "webhook" or "command"
	Event   string    `json:"event"`
	Subject string    `json:"subject,omitempty"`
	Status  string    `json:"status"` // sent, failed, suppressed:dedupe, suppressed:rate-limit, held
	Error   string    `json:"error,omitempty"`
}

type deliveryLog struct {
	mu   sync.Mutex
	list []DeliveryRecord
}

func (l *deliveryLog) add(r DeliveryRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.list) >= deliveryLogSize {
		copy(l.list, l.list[1:])
		l.list = l.list[:deliveryLogSize-1]
	}
	l.list = append(l.list, r)
}

func (l *deliveryLog) snapshot() []DeliveryRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]DeliveryRecord, len(l.list))
	for i, r := range l.list { // newest first
		out[len(l.list)-1-i] = r
	}
	return out
}

type center struct {
	log   deliveryLog
	gate  *gate
	flap  *FlapTracker
	spike *SpikeDetector
	now   func() time.Time
	stop  chan struct{}
}

func (m *Manager) initCenter() {
	c := &center{gate: newGate(), now: time.Now}
	c.flap = NewFlapTracker(func() int { return m.Rules().FailThreshold }, func() int { return m.Rules().RecoverThreshold })
	c.spike = NewSpikeDetector(func() (int, time.Duration, time.Duration) {
		r := m.Rules()
		return r.WAFSpikeBlocks, time.Duration(r.WAFSpikeWindow) * time.Second, time.Duration(r.WAFSpikeCooldown) * time.Second
	})
	m.center = c
}

// SetClock replaces the clock (tests)
func (m *Manager) SetClock(now func() time.Time) { m.center.now = now }

// Rules returns the active delivery rules
func (m *Manager) Rules() Rules {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg.Rules == nil {
		return DefaultRules()
	}
	return *m.cfg.Rules
}

// ---- sinks ----

type loggedSink struct {
	inner Sink
	kind  string
	m     *Manager
}

func (s *loggedSink) Name() string        { return s.inner.Name() }
func (s *loggedSink) Wants(e string) bool { return s.inner.Wants(e) }
func (s *loggedSink) Deliver(ctx context.Context, ev Event) error {
	err := s.inner.Deliver(ctx, ev)
	s.m.record(s.inner.Name(), s.kind, ev, err)
	return err
}

type gatedSink struct {
	inner *ChannelSink
	m     *Manager
	rules Rules
}

func (s *gatedSink) Name() string        { return s.inner.Name() }
func (s *gatedSink) Wants(e string) bool { return s.inner.Wants(e) }
func (s *gatedSink) Deliver(ctx context.Context, ev Event) error {
	now := s.m.center.now()
	switch s.m.center.gate.check(s.rules, s.inner.Cfg.ID, ev, now) {
	case DecDedupe:
		s.m.recordStatus(s.inner.Cfg.Name, s.inner.Cfg.Type, ev, "suppressed:dedupe", "")
		return nil
	case DecRate:
		s.m.recordStatus(s.inner.Cfg.Name, s.inner.Cfg.Type, ev, "suppressed:rate-limit", "")
		return nil
	case DecHeld:
		s.m.recordStatus(s.inner.Cfg.Name, s.inner.Cfg.Type, ev, "held", "")
		return nil
	}
	err := s.inner.Deliver(ctx, ev)
	s.m.record(s.inner.Cfg.Name, s.inner.Cfg.Type, ev, err)
	return err
}

func (m *Manager) record(name, kind string, ev Event, err error) {
	if err != nil {
		m.recordStatus(name, kind, ev, "failed", err.Error())
		return
	}
	m.recordStatus(name, kind, ev, "sent", "")
}

func (m *Manager) recordStatus(name, kind string, ev Event, status, errText string) {
	if m.center == nil {
		return
	}
	m.center.log.add(DeliveryRecord{Time: m.center.now(), Channel: name, Kind: kind, Event: ev.Event, Subject: cleanText(ev.Subject, 120), Status: status, Error: cleanText(errText, 300)})
}

func (m *Manager) channelSinks() []Sink {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rules := DefaultRules()
	if m.cfg.Rules != nil {
		rules = *m.cfg.Rules
	}
	out := []Sink{}
	for _, c := range m.cfg.Channels {
		out = append(out, &gatedSink{inner: &ChannelSink{Cfg: c, Offline: m.offline, tlsConfig: testTLS}, m: m, rules: rules})
	}
	return out
}

// ---- channel management ----

// SaveChannel creates (empty ID) or updates a channel and returns its ID. A secret
// equal to SecretMask keeps the stored value.
func (m *Manager) SaveChannel(c ChannelConfig) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := -1
	if c.ID != "" {
		for i := range m.cfg.Channels {
			if m.cfg.Channels[i].ID == c.ID {
				idx = i
			}
		}
		if idx < 0 {
			return "", errors.New("channel not found")
		}
		old := m.cfg.Channels[idx]
		for k := range old.secretKeys() {
			if c.Settings != nil && c.Settings[k] == SecretMask {
				c.Settings[k] = old.Settings[k]
			}
		}
		if c.Type == "" {
			c.Type = old.Type
		}
		if c.Type != old.Type {
			return "", errors.New("the type of a channel cannot be changed")
		}
	} else {
		if len(m.cfg.Channels) >= maxChannels {
			return "", errors.New("too many channels")
		}
		for k := range (&ChannelConfig{Type: c.Type}).secretKeys() {
			if c.Settings != nil && c.Settings[k] == SecretMask {
				c.Settings[k] = ""
			}
		}
	}
	if err := c.Validate(); err != nil {
		return "", err
	}
	if idx >= 0 {
		m.cfg.Channels[idx] = c
		return c.ID, m.save()
	}
	c.ID = newID()
	m.cfg.Channels = append(m.cfg.Channels, c)
	return c.ID, m.save()
}

// DeleteChannel removes a channel
func (m *Manager) DeleteChannel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.cfg.Channels {
		if m.cfg.Channels[i].ID == id {
			m.cfg.Channels = append(m.cfg.Channels[:i], m.cfg.Channels[i+1:]...)
			m.center.gate.forget(id)
			return m.save()
		}
	}
	return errors.New("channel not found")
}

// SaveRules validates and stores the delivery rules
func (m *Manager) SaveRules(r Rules) error {
	if err := r.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Rules = &r
	return m.save()
}

// TestChannel sends a test notification synchronously (single attempt, bypasses the rules)
func (m *Manager) TestChannel(id string) error {
	m.mu.RLock()
	var found *ChannelConfig
	for i := range m.cfg.Channels {
		if m.cfg.Channels[i].ID == id {
			c := m.cfg.Channels[i]
			found = &c
		}
	}
	m.mu.RUnlock()
	if found == nil {
		return errors.New("channel not found")
	}
	found.Enabled = true
	sink := &ChannelSink{Cfg: *found, Offline: m.offline, Attempts: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ev := Event{Event: EventTest, Time: time.Now().UTC(), Source: "test", Subject: "test notification"}
	err := sink.Deliver(ctx, ev)
	m.record(found.Name, found.Type, ev, err)
	return err
}

// FlushDigests delivers held events whose time has come; returns the number of digests sent
func (m *Manager) FlushDigests() int {
	now := m.center.now()
	rules := m.Rules()
	m.mu.RLock()
	chans := append([]ChannelConfig{}, m.cfg.Channels...)
	m.mu.RUnlock()
	n := 0
	for _, c := range chans {
		ev := m.center.gate.takeHeld(rules, c.ID, now)
		if ev == nil {
			continue
		}
		c.Enabled = true
		sink := &ChannelSink{Cfg: c, Offline: m.offline, Attempts: 3}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := sink.Deliver(ctx, *ev)
		cancel()
		m.record(c.Name, c.Type, *ev, err)
		n++
	}
	return n
}

// StartCenter runs the digest flusher until StopCenter
func (m *Manager) StartCenter() {
	if m.center.stop != nil {
		return
	}
	m.center.stop = make(chan struct{})
	go func(stop chan struct{}) {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				m.FlushDigests()
			}
		}
	}(m.center.stop)
}

// StopCenter stops the digest flusher
func (m *Manager) StopCenter() {
	if m.center.stop != nil {
		close(m.center.stop)
		m.center.stop = nil
	}
}

// ---- event sources with state ----

// ObserveUptime feeds one health check result of an upstream. It emits uptime.down after
// FailThreshold consecutive failures and uptime.up after RecoverThreshold good checks.
func (m *Manager) ObserveUptime(id, name, url string, online bool, statusCode int) {
	tr := m.center.flap.Observe(id, online, m.center.now())
	if tr == nil {
		return
	}
	ev := Event{Source: "uptime", Subject: name, Extra: map[string]string{"url": url, "target_id": id}}
	if tr.Down {
		ev.Event = EventUptimeDown
		ev.Extra["failures"] = itoa(tr.Failures)
		if statusCode > 0 {
			ev.Extra["status_code"] = itoa(statusCode)
		}
	} else {
		ev.Event = EventUptimeUp
		ev.Extra["downtime"] = tr.Downtime.Round(time.Second).String()
	}
	m.Emit(ev)
}

// ObserveWAFBlock counts a WAF block of a site and emits waf.spike when the rate threshold is hit
func (m *Manager) ObserveWAFBlock(site string) {
	if n := m.center.spike.Hit(site, m.center.now()); n > 0 {
		r := m.Rules()
		m.Emit(Event{Event: EventWAFSpike, Source: "waf", Subject: site,
			Extra: map[string]string{"blocks": itoa(n), "window_seconds": itoa(r.WAFSpikeWindow)}})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// ---- webhook JSON templates ----

var templateFuncs = template.FuncMap{
	"json": func(v any) (string, error) { b, err := json.Marshal(v); return string(b), err },
}

// ValidateTemplate checks a webhook body template by rendering a sample event
func ValidateTemplate(tpl string) error {
	if tpl == "" {
		return nil
	}
	sample := Event{Event: EventTest, Time: time.Now().UTC(), Source: "test", Subject: "sample"}
	_, err := RenderTemplate(tpl, sample)
	return err
}

// RenderTemplate renders a webhook body. Available: {{.Event}} {{.Source}} {{.Subject}} {{.Error}} {{.Time}}
// {{.Domains}} {{.Extra.key}} and the function json (e.g. {{json .Subject}}). The output must be valid JSON.
func RenderTemplate(tpl string, ev Event) ([]byte, error) {
	if len(tpl) > maxTemplateBytes {
		return nil, errors.New("template too long")
	}
	t, err := template.New("body").Funcs(templateFuncs).Option("missingkey=zero").Parse(tpl)
	if err != nil {
		return nil, errors.New("invalid template: " + err.Error())
	}
	title, lines := Describe(ev)
	data := map[string]any{
		"Event": ev.Event, "Source": ev.Source, "Subject": ev.Subject, "Error": ev.Error, "Time": ev.Time.UTC().Format(time.RFC3339),
		"Domains": ev.Domains, "Extra": ev.Extra, "CA": ev.CA, "Title": title, "Text": strings.Join(append([]string{title}, lines...), "\n"),
		"Severity": SeverityOf(ev.Event),
	}
	var buf bytes.Buffer
	if err := t.Execute(&limitWriter{w: &buf, left: maxBodyBytes}, data); err != nil {
		return nil, errors.New("template error: " + err.Error())
	}
	if !json.Valid(buf.Bytes()) {
		return nil, errors.New("template does not produce valid JSON (use {{json .Field}} for strings)")
	}
	return buf.Bytes(), nil
}

type limitWriter struct {
	w    *bytes.Buffer
	left int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if len(p) > l.left {
		return 0, errors.New("template output too large")
	}
	l.left -= len(p)
	return l.w.Write(p)
}

// ---- HTTP API ----

// CenterView is the API representation (secrets masked)
func (m *Manager) CenterView() map[string]any {
	m.mu.RLock()
	chans := make([]ChannelConfig, 0, len(m.cfg.Channels))
	for _, c := range m.cfg.Channels {
		chans = append(chans, c.Masked())
	}
	m.mu.RUnlock()
	return map[string]any{
		"channels": chans, "channelTypes": ChannelTypes, "rules": m.Rules(), "events": Catalog,
		"offline": m.offline != nil && m.offline(),
	}
}

// HandleCenter serves /api/notify/center. GET returns channels (masked), rules and the event catalogue;
// POST takes a JSON body {op, ...}: saveChannel{channel}, deleteChannel{id}, testChannel{id}, saveRules{rules}.
func (m *Manager) HandleCenter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, m.CenterView())
		return
	}
	var req struct {
		Op      string         `json:"op"`
		ID      string         `json:"id"`
		Channel *ChannelConfig `json:"channel"`
		Rules   *Rules         `json:"rules"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		utils.SendErrorResponse(w, "invalid JSON body")
		return
	}
	fail := func(err error) { utils.SendErrorResponse(w, strings.ReplaceAll(err.Error(), `"`, `'`)) }
	switch req.Op {
	case "saveChannel":
		if req.Channel == nil {
			fail(errors.New("channel missing"))
			return
		}
		id, err := m.SaveChannel(*req.Channel)
		if err != nil {
			fail(err)
			return
		}
		jsonOut(w, map[string]string{"id": id})
	case "deleteChannel":
		if err := m.DeleteChannel(req.ID); err != nil {
			fail(err)
			return
		}
		utils.SendOK(w)
	case "testChannel":
		if err := m.TestChannel(req.ID); err != nil {
			fail(err)
			return
		}
		utils.SendOK(w)
	case "saveRules":
		if req.Rules == nil {
			fail(errors.New("rules missing"))
			return
		}
		if err := m.SaveRules(*req.Rules); err != nil {
			fail(err)
			return
		}
		utils.SendOK(w)
	default:
		utils.SendErrorResponse(w, "invalid operation")
	}
}

// HandleDeliveries serves GET /api/notify/deliveries: the most recent deliveries, newest first
func (m *Manager) HandleDeliveries(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, m.center.log.snapshot())
}

// Deliveries returns the recent delivery log, newest first
func (m *Manager) Deliveries() []DeliveryRecord { return m.center.log.snapshot() }
