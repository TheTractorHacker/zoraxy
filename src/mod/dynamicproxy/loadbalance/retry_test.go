package loadbalance

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gorilla/sessions"
	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
)

// scriptedServe returns a ServeFunc whose behavior is chosen per upstream origin
type attempt struct {
	origin string
	body   string
}

type scripted struct {
	mu       sync.Mutex
	attempts []attempt
	// behavior by origin: status to write, or an error to return without writing
	status map[string]int
	err    map[string]error
	// partial makes the upstream write the header and some body, then fail
	partial map[string]bool
}

func (s *scripted) serve(w http.ResponseWriter, r *http.Request, u *Upstream) (int, error) {
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}
	s.mu.Lock()
	s.attempts = append(s.attempts, attempt{u.OriginIpOrDomain, body})
	s.mu.Unlock()

	if e := s.err[u.OriginIpOrDomain]; e != nil {
		return http.StatusBadGateway, e
	}
	code := s.status[u.OriginIpOrDomain]
	if code == 0 {
		code = 200
	}
	w.Header().Set("X-Origin", u.OriginIpOrDomain)
	w.WriteHeader(code)
	w.Write([]byte("from " + u.OriginIpOrDomain))
	if s.partial[u.OriginIpOrDomain] {
		return code, errors.New("connection reset mid body")
	}
	return code, nil
}

func (s *scripted) origins() []string {
	var o []string
	for _, a := range s.attempts {
		o = append(o, a.origin)
	}
	return o
}

func firstAndServe(t *testing.T, m *RouteManager, ups []*Upstream, cfg *Config, r *http.Request, s *scripted) (ServeResult, *httptest.ResponseRecorder) {
	t.Helper()
	opt := &SelectOptions{Config: cfg}
	rec := httptest.NewRecorder()
	// Always start on upstream 1 so the scenario is deterministic
	res := m.ServeWithRetry(rec, r, ups, ups[0], opt, s.serve)
	return res, rec
}

func TestRetryRules(t *testing.T) {
	connErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	tests := []struct {
		name         string
		method       string
		body         string
		chunked      bool
		retry        *RetryConfig
		s1           func(*scripted)
		wantOrigins  int // number of attempts
		wantStatus   int
		wantErr      bool
		wantBodyEach string // body each attempt must have seen
	}{
		{"GET retried on connection error", "GET", "", false, &RetryConfig{Enabled: true},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 2, 200, false, ""},
		{"HEAD retried", "HEAD", "", false, &RetryConfig{Enabled: true},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 2, 200, false, ""},
		{"OPTIONS retried", "OPTIONS", "", false, &RetryConfig{Enabled: true},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 2, 200, false, ""},
		{"POST not retried by default", "POST", "", false, &RetryConfig{Enabled: true},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 1, 502, true, ""},
		{"POST with body not retried by default", "POST", "payload", false, &RetryConfig{Enabled: true},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 1, 502, true, "payload"},
		{"POST retried when enabled, body replayed whole", "POST", "payload", false, &RetryConfig{Enabled: true, ExtraMethods: []string{"POST"}},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 2, 200, false, "payload"},
		{"POST with unknown length body never retried", "POST", "payload", true, &RetryConfig{Enabled: true, ExtraMethods: []string{"POST"}},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 1, 502, true, "payload"},
		{"body above limit never retried", "POST", strings.Repeat("x", 2048), false, &RetryConfig{Enabled: true, ExtraMethods: []string{"POST"}, MaxBodyKB: 1},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 1, 502, true, strings.Repeat("x", 2048)},
		{"retry disabled", "GET", "", false, &RetryConfig{Enabled: false},
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 1, 502, true, ""},
		{"no retry config", "GET", "", false, nil,
			func(s *scripted) { s.err["10.0.0.1:8080"] = connErr }, 1, 502, true, ""},
		{"configured status retried before anything is sent", "GET", "", false, &RetryConfig{Enabled: true, RetryStatuses: []int{503}},
			func(s *scripted) { s.status["10.0.0.1:8080"] = 503 }, 2, 200, false, ""},
		{"status not configured is passed through", "GET", "", false, &RetryConfig{Enabled: true, RetryStatuses: []int{502}},
			func(s *scripted) { s.status["10.0.0.1:8080"] = 503 }, 1, 503, false, ""},
		{"default has no status retry", "GET", "", false, &RetryConfig{Enabled: true},
			func(s *scripted) { s.status["10.0.0.1:8080"] = 503 }, 1, 503, false, ""},
		{"error after response started is never retried", "GET", "", false, &RetryConfig{Enabled: true},
			func(s *scripted) { s.partial["10.0.0.1:8080"] = true }, 1, 200, true, ""},
		{"max retries respected", "GET", "", false, &RetryConfig{Enabled: true, MaxRetries: 1},
			func(s *scripted) {
				s.err["10.0.0.1:8080"] = connErr
				s.err["10.0.0.2:8080"] = connErr
			}, 2, 502, true, ""},
		{"retries walk through upstreams", "GET", "", false, &RetryConfig{Enabled: true, MaxRetries: 5},
			func(s *scripted) {
				s.err["10.0.0.1:8080"] = connErr
				s.err["10.0.0.2:8080"] = connErr
			}, 3, 200, false, ""},
		{"client cancel is not retried", "GET", "", false, &RetryConfig{Enabled: true},
			func(s *scripted) { s.err["10.0.0.1:8080"] = context.Canceled }, 1, 502, true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestManager()
			ups := mkUpstreams(1, 1, 1)
			s := &scripted{status: map[string]int{}, err: map[string]error{}, partial: map[string]bool{}}
			tc.s1(s)
			cfg := &Config{Retry: tc.retry, Algorithm: AlgoRoundRobin}

			var rdr io.Reader
			if tc.body != "" {
				rdr = strings.NewReader(tc.body)
			}
			r := httptest.NewRequest(tc.method, "http://example.com/x", rdr)
			if tc.chunked {
				r.ContentLength = -1
			}
			res, rec := firstAndServe(t, m, ups, cfg, r, s)

			if len(s.attempts) != tc.wantOrigins {
				t.Fatalf("attempts %v, want %d", s.origins(), tc.wantOrigins)
			}
			if s.attempts[0].origin != "10.0.0.1:8080" {
				t.Fatalf("first attempt on %s", s.attempts[0].origin)
			}
			seen := map[string]bool{}
			for _, a := range s.attempts {
				if seen[a.origin] {
					t.Fatalf("upstream %s tried twice in %v", a.origin, s.origins())
				}
				seen[a.origin] = true
				if tc.body != "" && a.body != tc.wantBodyEach {
					t.Fatalf("attempt on %s saw body %q, want the complete original", a.origin, a.body)
				}
			}
			if res.Status != tc.wantStatus {
				t.Errorf("status %d, want %d", res.Status, tc.wantStatus)
			}
			if (res.Err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", res.Err, tc.wantErr)
			}
			if res.Attempts != tc.wantOrigins {
				t.Errorf("Attempts = %d", res.Attempts)
			}
			if res.Err == nil && rec.Code != tc.wantStatus {
				t.Errorf("client saw %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestRetryNeverMixesResponses(t *testing.T) {
	// The first upstream answers 503 with its own header and body, the retry succeeds.
	// The client must see only the second upstream's response.
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1)
	s := &scripted{status: map[string]int{"10.0.0.1:8080": 503}, err: map[string]error{}, partial: map[string]bool{}}
	cfg := &Config{Retry: &RetryConfig{Enabled: true, RetryStatuses: []int{503}}}
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Keep", "yes") // header set before the proxy ran must survive
	res := m.ServeWithRetry(rec, r, ups, ups[0], &SelectOptions{Config: cfg}, s.serve)
	if res.Err != nil || rec.Code != 200 {
		t.Fatalf("result %+v code %d", res, rec.Code)
	}
	if got := rec.Body.String(); got != "from 10.0.0.2:8080" {
		t.Fatalf("body %q", got)
	}
	if rec.Header().Get("X-Origin") != "10.0.0.2:8080" || rec.Header().Get("X-Keep") != "yes" {
		t.Fatalf("headers leaked or lost: %v", rec.Header())
	}
}

func TestRetryNoAlternativeKeepsTheResponse(t *testing.T) {
	// A single upstream answering 503: there is nobody to retry on, so the client gets the real 503
	m, _ := newTestManager()
	ups := mkUpstreams(1)
	s := &scripted{status: map[string]int{"10.0.0.1:8080": 503}, err: map[string]error{}, partial: map[string]bool{}}
	cfg := &Config{Retry: &RetryConfig{Enabled: true, RetryStatuses: []int{503}}}
	res, rec := firstAndServe(t, m, ups, cfg, httptest.NewRequest("GET", "http://example.com/", nil), s)
	if res.Err != nil || rec.Code != 503 || rec.Body.String() != "from 10.0.0.1:8080" {
		t.Fatalf("got %+v code %d body %q", res, rec.Code, rec.Body.String())
	}
}

func TestRetrySkipsUpgradeRequests(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1)
	s := &scripted{status: map[string]int{}, err: map[string]error{"10.0.0.1:8080": errors.New("boom")}, partial: map[string]bool{}}
	cfg := &Config{Retry: &RetryConfig{Enabled: true}}
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Upgrade", "tcp")
	res, _ := firstAndServe(t, m, ups, cfg, r, s)
	if res.Attempts != 1 || res.Err == nil {
		t.Fatalf("upgrade request was retried: %+v", res)
	}
}

func TestRetryStickyReselectionReplacesCookie(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1)
	s := &scripted{status: map[string]int{}, err: map[string]error{"10.0.0.1:8080": errors.New("refused")}, partial: map[string]bool{}}
	cfg := &Config{Retry: &RetryConfig{Enabled: true}}
	opt := &SelectOptions{Config: cfg, UseStickySession: true}
	m.SessionStore = sessions.NewCookieStore([]byte("test-key"))

	rec := httptest.NewRecorder()
	r := testRequest("1.1.1.1")
	// Simulate the first selection having bound the client to upstream 1
	if err := m.setSessionHandler(rec, r, ups[0].OriginIpOrDomain, 0); err != nil {
		t.Fatal(err)
	}
	res := m.ServeWithRetry(rec, r, ups, ups[0], opt, s.serve)
	if res.Err != nil || res.Upstream != ups[1] {
		t.Fatalf("result %+v", res)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected exactly one sticky cookie, got %d", len(cookies))
	}
	// The cookie must point to the upstream that actually served
	r2 := testRequest("1.1.1.1")
	r2.AddCookie(cookies[0])
	idx, err := m.getSessionHandler(r2, ups)
	if err != nil || idx != 1 {
		t.Fatalf("sticky cookie points to %d (%v), want upstream 2", idx, err)
	}
}

func TestPassiveReportingThroughServe(t *testing.T) {
	m, clk := newTestManager()
	ups := mkUpstreams(1, 1)
	cfg := &Config{PassiveHealthCheck: &PassiveHealthCheck{Enabled: true, FailThreshold: 2, CooldownSeconds: 60}}
	s := &scripted{status: map[string]int{"10.0.0.1:8080": 502}, err: map[string]error{}, partial: map[string]bool{}}

	for i := 0; i < 2; i++ {
		m.ServeWithRetry(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), ups, ups[0], &SelectOptions{Config: cfg}, s.serve)
	}
	if ups[0].isHealthy(clk.Now()) {
		t.Fatal("two 502 answers in a row should eject the upstream")
	}
	if !ups[1].isHealthy(clk.Now()) {
		t.Fatal("the other upstream must be unaffected")
	}

	// A client that goes away is not the upstream's fault
	s2 := &scripted{status: map[string]int{}, err: map[string]error{"10.0.0.2:8080": context.Canceled}, partial: map[string]bool{}}
	for i := 0; i < 5; i++ {
		m.ServeWithRetry(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), ups, ups[1], &SelectOptions{Config: cfg}, s2.serve)
	}
	if !ups[1].isHealthy(clk.Now()) {
		t.Fatal("canceled requests must not eject")
	}
}

func TestInFlightAndLatencyTracking(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1)
	cfg := &Config{Algorithm: AlgoLeastResponseTime}

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.ServeWithRetry(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), ups, ups[0], &SelectOptions{Config: cfg},
			func(w http.ResponseWriter, r *http.Request, u *Upstream) (int, error) {
				close(started)
				<-release
				w.WriteHeader(200)
				return 200, nil
			})
	}()
	<-started
	if ups[0].InFlight() != 1 {
		t.Fatalf("in flight = %d", ups[0].InFlight())
	}
	close(release)
	<-done
	if ups[0].InFlight() != 0 {
		t.Fatalf("in flight after finish = %d", ups[0].InFlight())
	}
	if ups[0].EWMA() <= 0 {
		t.Fatal("no latency sample recorded")
	}
}

func TestNilConfigCountsInFlightOnly(t *testing.T) {
	m, _ := newTestManager()
	ups := mkUpstreams(1, 1)
	var seen atomic.Int64
	res := m.ServeWithRetry(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), ups, ups[0], &SelectOptions{},
		func(w http.ResponseWriter, r *http.Request, u *Upstream) (int, error) {
			seen.Store(u.InFlight())
			return 200, nil
		})
	if res.Attempts != 1 || seen.Load() != 1 || ups[0].InFlight() != 0 {
		t.Fatalf("res %+v seen %d inflight %d", res, seen.Load(), ups[0].InFlight())
	}
}

// End to end through the real proxy core (dpcore) and real HTTP servers
func TestRetryEndToEnd(t *testing.T) {
	var liveHits, liveBodyBytes atomic.Int64
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		liveHits.Add(1)
		b, _ := io.ReadAll(r.Body)
		liveBodyBytes.Add(int64(len(b)))
		w.Write([]byte("live:" + string(b)))
	}))
	defer live.Close()

	// A port nobody listens on
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := ln.Addr().String()
	ln.Close()

	dead := &Upstream{OriginIpOrDomain: deadAddr, Weight: 1}
	good := &Upstream{OriginIpOrDomain: strings.TrimPrefix(live.URL, "http://"), Weight: 1}
	for _, u := range []*Upstream{dead, good} {
		if err := u.StartProxy(""); err != nil {
			t.Fatal(err)
		}
	}
	ups := []*Upstream{dead, good}
	m, _ := newTestManager()
	serve := func(w http.ResponseWriter, r *http.Request, u *Upstream) (int, error) {
		return u.ServeHTTP(w, r, &dpcore.ResponseRewriteRuleSet{ProxyDomain: u.OriginIpOrDomain, OriginalHost: "example.com", Version: "test"})
	}

	run := func(cfg *Config, method, body string) (ServeResult, *httptest.ResponseRecorder) {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		r := httptest.NewRequest(method, "http://example.com/p", rdr)
		rec := httptest.NewRecorder()
		return m.ServeWithRetry(rec, r, ups, dead, &SelectOptions{Config: cfg}, serve), rec
	}

	// GET: dead upstream fails to connect, retried on the live one
	res, rec := run(&Config{Retry: &RetryConfig{Enabled: true}}, "GET", "")
	if res.Err != nil || rec.Code != 200 || res.Upstream != good || res.Attempts != 2 {
		t.Fatalf("GET: %+v code %d", res, rec.Code)
	}

	// POST with body, retry enabled for POST: the live upstream receives the body exactly once, intact
	liveBodyBytes.Store(0)
	res, rec = run(&Config{Retry: &RetryConfig{Enabled: true, ExtraMethods: []string{"POST"}}}, "POST", "hello-body")
	if res.Err != nil || rec.Body.String() != "live:hello-body" || liveBodyBytes.Load() != int64(len("hello-body")) {
		t.Fatalf("POST: %+v body %q live bytes %d", res, rec.Body.String(), liveBodyBytes.Load())
	}

	// POST without opt in: one attempt, no hit on the live server
	before := liveHits.Load()
	res, _ = run(&Config{Retry: &RetryConfig{Enabled: true}}, "POST", "hello-body")
	if res.Err == nil || res.Attempts != 1 || liveHits.Load() != before {
		t.Fatalf("POST without opt in was retried: %+v", res)
	}
}
