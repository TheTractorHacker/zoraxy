package metrics

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type sample struct {
	name   string
	labels map[string]string
	value  float64
}

var sampleRe = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+(\S+)$`)
var labelRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)

// parseExposition is a strict-enough parser of the text format used to verify
// the output round trips: every sample must have a TYPE, and HELP/TYPE appear
// at most once per family.
func parseExposition(t *testing.T, text string) ([]sample, map[string]string) {
	t.Helper()
	types := map[string]string{}
	helps := map[string]bool{}
	var out []sample
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			t.Fatalf("empty line in exposition")
		}
		if strings.HasPrefix(line, "# HELP ") {
			n := strings.Fields(line)[2]
			if helps[n] {
				t.Fatalf("duplicate HELP for %s", n)
			}
			helps[n] = true
			continue
		}
		if strings.HasPrefix(line, "# TYPE ") {
			f := strings.Fields(line)
			if _, dup := types[f[2]]; dup {
				t.Fatalf("duplicate TYPE for %s", f[2])
			}
			types[f[2]] = f[3]
			continue
		}
		m := sampleRe.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("invalid sample line: %q", line)
		}
		v, err := strconv.ParseFloat(m[4], 64)
		if err != nil && m[4] != "+Inf" {
			t.Fatalf("invalid value in %q", line)
		}
		s := sample{name: m[1], labels: map[string]string{}, value: v}
		for _, lm := range labelRe.FindAllStringSubmatch(m[3], -1) {
			s.labels[lm[1]] = lm[2]
		}
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(s.name, "_bucket"), "_sum"), "_count")
		if _, ok := types[s.name]; !ok {
			if types[base] != "histogram" {
				t.Fatalf("sample %q has no TYPE", s.name)
			}
		}
		out = append(out, s)
	}
	return out, types
}

func scrape(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func find(ss []sample, name string, kv ...string) (sample, bool) {
outer:
	for _, s := range ss {
		if s.name != name {
			continue
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if s.labels[kv[i]] != kv[i+1] {
				continue outer
			}
		}
		return s, true
	}
	return sample{}, false
}

func serve(r *Registry, endpoint string, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	w, rq, done := r.Begin(rec, req, endpoint)
	h(w, rq)
	done()
	return rec
}

func TestDisabledByDefaultAndNoOp(t *testing.T) {
	r := New()
	if r.Enabled() {
		t.Fatal("registry must be disabled by default")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	w, rq, done := r.Begin(rec, req, "a")
	if w != http.ResponseWriter(rec) || rq != req {
		t.Fatal("disabled Begin must pass the writer and request through untouched")
	}
	done()
	r.Event(EventRateLimited, "a", "x")
	if r.EndpointCount() != 0 {
		t.Fatal("disabled registry recorded something")
	}
	// handler answers 503 when disabled
	srv := httptest.NewRecorder()
	r.Handler().ServeHTTP(srv, httptest.NewRequest("GET", "/metrics", nil))
	if srv.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled handler status %d", srv.Code)
	}
	// nil receiver is safe
	var nilReg *Registry
	nilReg.Event(EventAccessBlocked, "a", "b")
	nilReg.SetEnabled(true)
	if nilReg.Enabled() {
		t.Fatal("nil registry enabled")
	}
	_, _, d := nilReg.Begin(rec, req, "a")
	d()
}

func TestExpositionRoundTrip(t *testing.T) {
	r := New()
	r.SetEnabled(true)
	serve(r, "app.example.com", func(w http.ResponseWriter, rq *http.Request) {
		io.Copy(io.Discard, rq.Body)
		w.WriteHeader(404)
		w.Write([]byte("hello"))
	}, httptest.NewRequest("POST", "/x", strings.NewReader("12345678")))
	serve(r, "app.example.com", func(w http.ResponseWriter, rq *http.Request) {
		w.Write([]byte("ok"))
	}, httptest.NewRequest("GET", "/", nil))
	serve(r, "weird\"name\\\n", func(w http.ResponseWriter, rq *http.Request) {}, httptest.NewRequest("BREW", "/", nil))
	r.Event(EventRateLimited, "app.example.com", "limit")
	r.Event(EventAccessBlocked, "app.example.com", "blacklist")
	r.Event(EventCaptchaChallenge, "app.example.com", "required")

	r.AddCollector(func(e *Emitter) {
		e.Gauge("zoraxy_test_gauge", "a gauge", 1.5, "k", "v")
		e.Gauge("zoraxy_test_gauge", "a gauge", 2, "k", "w")
	})
	r.AddCollector(func(e *Emitter) { panic("boom") }) //must not break the scrape

	text := scrape(t, r)
	ss, types := parseExposition(t, text)

	if types["zoraxy_http_requests_total"] != "counter" || types["zoraxy_http_request_duration_seconds"] != "histogram" {
		t.Fatalf("types: %v", types)
	}
	if s, ok := find(ss, "zoraxy_http_requests_total", "endpoint", "app.example.com", "status_class", "4xx", "method", "POST"); !ok || s.value != 1 {
		t.Fatalf("missing 4xx POST sample: %v", ok)
	}
	if s, ok := find(ss, "zoraxy_http_requests_total", "endpoint", "app.example.com", "status_class", "2xx", "method", "GET"); !ok || s.value != 1 {
		t.Fatal("missing 2xx GET sample")
	}
	if _, ok := find(ss, "zoraxy_http_requests_total", "method", "OTHER"); !ok {
		t.Fatal("unknown methods must fold into OTHER")
	}
	if s, _ := find(ss, "zoraxy_http_request_bytes_total", "endpoint", "app.example.com"); s.value != 8 {
		t.Fatalf("bytes in = %v", s.value)
	}
	if s, _ := find(ss, "zoraxy_http_response_bytes_total", "endpoint", "app.example.com"); s.value != 7 {
		t.Fatalf("bytes out = %v", s.value)
	}
	if s, _ := find(ss, "zoraxy_http_requests_in_flight", "endpoint", "app.example.com"); s.value != 0 {
		t.Fatal("in flight not back to zero")
	}
	// histogram: cumulative buckets, +Inf == _count
	var last float64 = -1
	n := 0
	for _, s := range ss {
		if s.name == "zoraxy_http_request_duration_seconds_bucket" && s.labels["endpoint"] == "app.example.com" {
			if s.value < last {
				t.Fatal("histogram buckets not cumulative")
			}
			last = s.value
			n++
		}
	}
	if n != len(DurationBuckets)+1 {
		t.Fatalf("bucket count %d", n)
	}
	if c, _ := find(ss, "zoraxy_http_request_duration_seconds_count", "endpoint", "app.example.com"); c.value != 2 || last != 2 {
		t.Fatalf("count %v inf %v", c.value, last)
	}
	if _, ok := find(ss, "zoraxy_ratelimit_rejected_total", "endpoint", "app.example.com", "reason", "limit"); !ok {
		t.Fatal("rate limit event missing")
	}
	if _, ok := find(ss, "zoraxy_access_blocked_total", "reason", "blacklist"); !ok {
		t.Fatal("access event missing")
	}
	if _, ok := find(ss, "zoraxy_test_gauge", "k", "w"); !ok {
		t.Fatal("collector sample missing")
	}
	// escaping of the weird endpoint label
	if !strings.Contains(text, `endpoint="weird\"name\\\n"`) {
		t.Fatalf("label escaping wrong:\n%s", text)
	}
}

func TestEndpointCardinalityCap(t *testing.T) {
	r := New()
	r.SetEnabled(true)
	for i := 0; i < MaxEndpoints+300; i++ {
		serve(r, fmt.Sprintf("host%d.example", i), func(w http.ResponseWriter, rq *http.Request) {}, httptest.NewRequest("GET", "/", nil))
	}
	if n := r.EndpointCount(); n > MaxEndpoints+1 {
		t.Fatalf("endpoint labels not capped: %d", n)
	}
	ss, _ := parseExposition(t, scrape(t, r))
	s, ok := find(ss, "zoraxy_http_requests_total", "endpoint", OverflowLabel)
	if !ok || s.value != 300 {
		t.Fatalf("overflow series missing or wrong: %v %v", ok, s.value)
	}
	for i := 0; i < MaxEventSeries+200; i++ {
		r.Event(EventAccessBlocked, fmt.Sprintf("e%d", i), "blacklist")
	}
	r.events[EventAccessBlocked].mu.RLock()
	n := len(r.events[EventAccessBlocked].series)
	r.events[EventAccessBlocked].mu.RUnlock()
	if n > MaxEventSeries+1 {
		t.Fatalf("event series not capped: %d", n)
	}
}

func TestStatusAndInterfaces(t *testing.T) {
	r := New()
	r.SetEnabled(true)
	// handler that never writes counts as 200; informational 1xx ignored
	serve(r, "e", func(w http.ResponseWriter, rq *http.Request) {}, httptest.NewRequest("GET", "/", nil))
	serve(r, "e", func(w http.ResponseWriter, rq *http.Request) {
		w.WriteHeader(103)
		w.WriteHeader(502)
	}, httptest.NewRequest("GET", "/", nil))
	var flusher, unwrap bool
	serve(r, "e", func(w http.ResponseWriter, rq *http.Request) {
		_, flusher = w.(http.Flusher)
		_, unwrap = w.(interface{ Unwrap() http.ResponseWriter })
		_, hij := w.(http.Hijacker)
		if !hij {
			t.Error("recorder must expose http.Hijacker")
		}
		w.(http.Flusher).Flush()
	}, httptest.NewRequest("GET", "/", nil))
	if !flusher || !unwrap {
		t.Fatal("Flusher/Unwrap lost")
	}
	ss, _ := parseExposition(t, scrape(t, r))
	if s, _ := find(ss, "zoraxy_http_requests_total", "status_class", "5xx"); s.value != 1 {
		t.Fatal("5xx not counted")
	}
	if s, _ := find(ss, "zoraxy_http_requests_total", "status_class", "2xx"); s.value != 2 {
		t.Fatalf("2xx = %v", s.value)
	}
}

func TestBearerAuthAndSeparateServer(t *testing.T) {
	r := New()
	r.SetEnabled(true)
	srv := httptest.NewServer(r.NewServer("", "s3cret").Handler)
	defer srv.Close()

	get := func(path, auth, method string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if c := get("/metrics", "", "GET").StatusCode; c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c := get("/metrics", "Bearer wrong", "GET").StatusCode; c != 401 {
		t.Fatalf("wrong token: %d", c)
	}
	if c := get("/metrics", "Basic s3cret", "GET").StatusCode; c != 401 {
		t.Fatalf("wrong scheme: %d", c)
	}
	resp := get("/metrics", "Bearer s3cret", "GET")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != ContentType {
		t.Fatalf("good token: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if c := get("/metrics", "Bearer s3cret", "POST").StatusCode; c != 405 {
		t.Fatalf("POST: %d", c)
	}
	if c := get("/other", "Bearer s3cret", "GET").StatusCode; c != 404 {
		t.Fatalf("other path: %d", c)
	}
	// no token configured => open
	open := httptest.NewServer(r.NewServer("", "").Handler)
	defer open.Close()
	resp2, _ := http.Get(open.URL + "/metrics")
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("open: %d", resp2.StatusCode)
	}
}

func TestConcurrency(t *testing.T) {
	r := New()
	r.SetEnabled(true)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				serve(r, fmt.Sprintf("ep%d", i%7), func(w http.ResponseWriter, rq *http.Request) {
					w.Write([]byte("x"))
				}, httptest.NewRequest("GET", "/", nil))
				r.Event(EventRateLimited, fmt.Sprintf("ep%d", i%5), "limit")
				if i%50 == 0 {
					var b strings.Builder
					r.Write(&b)
				}
			}
		}(g)
	}
	wg.Wait()
	ss, _ := parseExposition(t, scrape(t, r))
	total := 0.0
	for _, s := range ss {
		if s.name == "zoraxy_http_requests_total" {
			total += s.value
		}
	}
	if total != 16*300 {
		t.Fatalf("lost updates: %v", total)
	}
}

func BenchmarkBeginDisabled(b *testing.B) {
	r := New()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, d := r.Begin(rec, req, "a")
		d()
	}
}
