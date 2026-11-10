package aiassist

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Budget semantics: once the request has been sent, a call is charged (real usage, else the
// reservation estimate) unless the provider cleanly refused it; only calls that never left are free.

func chargeService(t *testing.T, h http.HandlerFunc) (*Service, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s := newTestService(t, nil, nil)
	st := localSettings(srv.URL + "/v1")
	st.RatePerMin = 120
	if _, err := s.Save(SettingsUpdate{Settings: st, APIKey: fakeKey}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{FeatureExplain, FeatureSuggest, featureRule, FeatureAudit} {
		if err := s.Ack(f); err != nil {
			t.Fatal(err)
		}
	}
	return s, srv
}

func TestBudgetChargedForFailuresAfterSend(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"200 not json": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>not json")) },
		"oversized": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(strings.Repeat("a", maxResponseBytes+100)))
		},
		"500":                   func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); w.Write([]byte("boom")) },
		"408":                   func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(408) },
		"200 no choices":        func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"choices":[]}`)) },
		"connection cut midway": cutMidway,
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := chargeService(t, h)
			if _, err := s.Explain(context.Background(), EventInput{WAF: wafEvent()}); err == nil {
				t.Fatal("expected an error")
			}
			if u := s.Usage(); u.Tokens <= 0 || u.Calls != 1 {
				t.Fatalf("a sent request was not charged: %+v", u)
			}
		})
	}
}

func cutMidway(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	c, _, _ := hj.Hijack()
	c.Close()
}

func TestBudgetFreeForCleanRefusalsAndUnsentRequests(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 429} {
		code := code
		s, _ := chargeService(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte(`{"error":{"message":"no"}}`))
		})
		if _, err := s.Explain(context.Background(), EventInput{WAF: wafEvent()}); err == nil {
			t.Fatalf("%d: expected an error", code)
		}
		if u := s.Usage(); u.Tokens != 0 {
			t.Errorf("HTTP %d was charged: %+v", code, u)
		}
	}
	// connection refused: nothing was sent
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	s := newTestService(t, nil, nil)
	if _, err := s.Save(SettingsUpdate{Settings: localSettings("http://" + addr + "/v1"), APIKey: fakeKey}); err != nil {
		t.Fatal(err)
	}
	s.Ack(FeatureExplain)
	if _, err := s.Explain(context.Background(), EventInput{WAF: wafEvent()}); err == nil {
		t.Fatal("expected a dial error")
	}
	if u := s.Usage(); u.Tokens != 0 {
		t.Errorf("dial error was charged: %+v", u)
	}
	// a context that is already cancelled never sends anything
	s2, _ := chargeService(t, func(w http.ResponseWriter, r *http.Request) { t.Error("request must not arrive") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s2.Explain(ctx, EventInput{WAF: wafEvent()}); err == nil {
		t.Fatal("expected an error")
	}
	if u := s2.Usage(); u.Tokens != 0 {
		t.Errorf("unsent request was charged: %+v", u)
	}
}

// The admin closes the tab right after the request went out: the provider may bill it, so we do too.
func TestBudgetChargedWhenClientAbortsAfterSend(t *testing.T) {
	arrived := make(chan struct{}, 16)
	s, _ := chargeService(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) // reading the body arms the server's disconnect detection
		arrived <- struct{}{}
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Explain(ctx, EventInput{WAF: wafEvent()}); done <- err }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never arrived")
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("expected a cancel error")
	}
	if u := s.Usage(); u.Tokens <= 0 {
		t.Fatalf("aborted call not charged: %+v", u)
	}
}

// Repeated aborts must exhaust the monthly cap instead of running forever, and the limiter must
// end with nothing reserved and nothing in flight even with concurrent aborts.
func TestConcurrentAbortsCountAgainstTheCap(t *testing.T) {
	s, _ := chargeService(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	})
	st := s.View().Settings
	st.MonthlyCap, st.RatePerMin = 6000, 120
	if _, err := s.Save(SettingsUpdate{Settings: st}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	budgetHit := false
	for round := 0; round < 40 && !budgetHit; round++ {
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
				defer cancel()
				if _, err := s.Explain(ctx, EventInput{WAF: wafEvent()}); err == ErrBudget {
					mu.Lock()
					budgetHit = true
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}
	if !budgetHit {
		t.Fatalf("aborting clients never hit the cap: %+v", s.Usage())
	}
	if u := s.Usage(); u.Tokens <= 0 {
		t.Fatalf("no tokens charged: %+v", u)
	}
	s.lim.mu.Lock()
	defer s.lim.mu.Unlock()
	if s.lim.reserved != 0 || s.lim.inflight != 0 {
		t.Fatalf("limiter leaked: reserved=%d inflight=%d", s.lim.reserved, s.lim.inflight)
	}
}

func TestSettleKind(t *testing.T) {
	if settleKind(nil, perrUnbilled("x")) != settleFree || settleKind(nil, perr("x")) != settleCharge ||
		settleKind(&Response{}, perr("x")) != settleCharge || settleKind(nil, perrUnbilled("invalid endpoint")) != settleCancel ||
		settleKind(nil, nil) != settleCharge {
		t.Fatal("settleKind table")
	}
	for st, want := range map[int]bool{200: false, 301: true, 400: true, 401: true, 403: true, 408: false, 429: true, 500: false, 503: false} {
		if cleanRefusal(st) != want {
			t.Errorf("cleanRefusal(%d) != %v", st, want)
		}
	}
}
