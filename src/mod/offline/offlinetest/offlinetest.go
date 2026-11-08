// Package offlinetest is a test helper: it replaces http.DefaultTransport with one whose dialer always
// fails and counts every attempt, so tests can assert that code paths open no connection.
package offlinetest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/offline"
)

// Dials counts connection attempts since Install.
type Dials struct{ n atomic.Int64 }

// Count returns the number of dial attempts.
func (d *Dials) Count() int64 { return d.n.Load() }

// Install swaps http.DefaultTransport for a failing, counting transport and restores it on cleanup.
// It also resets offline mode when the test ends.
func Install(t testing.TB) *Dials {
	t.Helper()
	d := &Dials{}
	old := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d.n.Add(1)
			return nil, errors.New("offlinetest: dial attempted to " + addr)
		},
	}
	t.Cleanup(func() {
		http.DefaultTransport = old
		offline.Set(false)
	})
	return d
}

// FailingDial is a DialContext function that counts and fails, for components that take an injected dialer.
func (d *Dials) FailingDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.n.Add(1)
	return nil, errors.New("offlinetest: dial attempted to " + addr)
}
