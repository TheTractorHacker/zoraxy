// Package notify delivers system events (certificate issued / renewal failed / about to expire, and
// later uptime or WAF events) to outgoing webhooks and, when explicitly enabled, a command hook.
//
// Event sources call Dispatcher.Emit; destinations implement Sink. Adding a new source later only
// needs a new Event type constant and an Emit call, adding a new destination only needs a Sink.
package notify

import (
	"context"
	"log"
	"sync"
	"time"
)

// Event type names. Sources outside the certificate area should add theirs here.
const (
	EventCertIssued      = "certificate.issued"
	EventCertRenewFailed = "certificate.renewal_failed"
	EventCertExpiring    = "certificate.expiring"
	EventTest            = "test"
)

// AllCertEvents are the events the certificate subsystem emits.
var AllCertEvents = []string{EventCertIssued, EventCertRenewFailed, EventCertExpiring}

// Event is the payload delivered to sinks. It is serialised as the webhook JSON body.
type Event struct {
	Event    string            `json:"event"`
	Time     time.Time         `json:"time"`
	Source   string            `json:"source"`            // subsystem, e.g. "certificate"
	Subject  string            `json:"subject,omitempty"` // e.g. certificate store name
	Domains  []string          `json:"domains,omitempty"`
	Expiry   *time.Time        `json:"expiry,omitempty"`
	DaysLeft *int              `json:"days_left,omitempty"`
	CA       string            `json:"ca,omitempty"`
	Error    string            `json:"error,omitempty"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// Sink is a destination for events.
type Sink interface {
	Name() string
	// Wants reports whether this sink is interested in the event type
	Wants(eventType string) bool
	// Deliver sends the event; the context carries the overall deadline. Errors are logged by the dispatcher.
	Deliver(ctx context.Context, ev Event) error
}

// Dispatcher fans events out to sinks asynchronously so a slow receiver never blocks the emitter
// (e.g. an ACME issuance).
type Dispatcher struct {
	mu    sync.RWMutex
	sinks func() []Sink // evaluated per event, so config changes apply immediately
	wg    sync.WaitGroup

	// Logf receives delivery failures; defaults to the standard logger
	Logf func(format string, args ...any)
	// Timeout bounds one sink delivery including retries
	Timeout time.Duration
}

// NewDispatcher creates a dispatcher; sinks is called for each event to obtain the current sink list.
func NewDispatcher(sinks func() []Sink) *Dispatcher {
	return &Dispatcher{sinks: sinks, Logf: log.Printf, Timeout: 2 * time.Minute}
}

// Emit stamps and queues the event for every interested sink and returns immediately.
func (d *Dispatcher) Emit(ev Event) {
	if d == nil || d.sinks == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	for _, s := range d.sinks() {
		if !s.Wants(ev.Event) {
			continue
		}
		d.wg.Add(1)
		go func(s Sink) {
			defer d.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					d.Logf("[notify] sink %s panicked: %v", s.Name(), r)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
			defer cancel()
			if err := s.Deliver(ctx, ev); err != nil {
				d.Logf("[notify] delivering %s to %s failed: %v", ev.Event, s.Name(), err)
			}
		}(s)
	}
}

// Wait blocks until all queued deliveries finished (used by tests and on shutdown).
func (d *Dispatcher) Wait() { d.wg.Wait() }
