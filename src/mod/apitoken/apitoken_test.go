package apitoken

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type memKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemKV() *memKV                 { return &memKV{data: map[string][]byte{}} }
func (k *memKV) NewTable(string) error { return nil }
func (k *memKV) Write(t, key string, v interface{}) error {
	b, _ := json.Marshal(v)
	k.mu.Lock()
	k.data[key] = b
	k.mu.Unlock()
	return nil
}
func (k *memKV) Delete(t, key string) error {
	k.mu.Lock()
	delete(k.data, key)
	k.mu.Unlock()
	return nil
}
func (k *memKV) ListTable(string) ([][][]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := [][][]byte{}
	for key, v := range k.data {
		out = append(out, [][]byte{[]byte(key), v})
	}
	return out, nil
}

type memLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *memLog) PrintAndLog(t, m string, e error) {
	l.mu.Lock()
	l.lines = append(l.lines, t+" "+m)
	l.mu.Unlock()
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func setup(t *testing.T) (*Manager, *memKV, *memLog, *fakeClock, http.Handler) {
	kv, lg := newMemKV(), &memLog{}
	m, err := NewManager(kv, lg)
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	m.SetClock(clk.now)
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	return m, kv, lg, clk, h
}

func do(h http.Handler, method, tok, ip string, hdr ...string) int {
	r := httptest.NewRequest(method, "/api/v1/x", nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	if ip == "" {
		ip = "10.0.0.1"
	}
	r.RemoteAddr = ip + ":4000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestScopeEnforcement(t *testing.T) {
	m, _, _, _, h := setup(t)
	ro, _, _ := m.Create("ro", ScopeRead, 0, nil)
	rw, _, _ := m.Create("rw", ScopeReadWrite, 0, nil)
	for _, c := range []struct {
		tok, method string
		want        int
	}{
		{ro, "GET", 200}, {ro, "HEAD", 200}, {ro, "POST", 403}, {ro, "PUT", 403}, {ro, "DELETE", 403}, {ro, "PATCH", 403},
		{rw, "GET", 200}, {rw, "POST", 200}, {rw, "DELETE", 200},
	} {
		if got := do(h, c.method, c.tok, ""); got != c.want {
			t.Errorf("%s %s: got %d want %d", c.tok[:6], c.method, got, c.want)
		}
	}
}

func TestExpiryRevokeUnknown(t *testing.T) {
	m, _, _, clk, h := setup(t)
	exp, _, err := m.Create("e", ScopeRead, clk.now().Unix()+100, nil)
	if err != nil {
		t.Fatal(err)
	}
	if do(h, "GET", exp, "") != 200 {
		t.Fatal("should work before expiry")
	}
	clk.add(101 * time.Second)
	if do(h, "GET", exp, "") != 401 {
		t.Fatal("expired token accepted")
	}
	if _, _, err := m.Create("past", ScopeRead, clk.now().Unix()-1, nil); err == nil {
		t.Fatal("past expiry should be rejected")
	}
	tok, info, _ := m.Create("r", ScopeRead, 0, nil)
	if do(h, "GET", tok, "") != 200 {
		t.Fatal()
	}
	m.Revoke(info.ID)
	if do(h, "GET", tok, "") != 401 {
		t.Fatal("revoked token accepted")
	}
	if do(h, "GET", "zrx_"+strings.Repeat("A", 43), "") != 401 {
		t.Fatal("unknown token accepted")
	}
}

func TestIPAllowList(t *testing.T) {
	m, _, _, _, h := setup(t)
	tok, _, err := m.Create("ip", ScopeRead, 0, []string{"192.168.1.0/24", "203.0.113.7", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if do(h, "GET", tok, "192.168.1.50") != 200 || do(h, "GET", tok, "203.0.113.7") != 200 || do(h, "GET", tok, "2001:db8::5") != 200 {
		t.Fatal("allowed IP rejected")
	}
	if do(h, "GET", tok, "192.168.2.1") != 403 {
		t.Fatal("disallowed IP accepted")
	}
	// X-Forwarded-For must not bypass the list
	if do(h, "GET", tok, "10.9.9.9", "X-Forwarded-For", "192.168.1.5", "X-Real-Ip", "192.168.1.5") != 403 {
		t.Fatal("forwarding header trusted")
	}
	if _, _, err := m.Create("bad", ScopeRead, 0, []string{"not-an-ip"}); err == nil {
		t.Fatal("bad cidr accepted")
	}
}

func TestMalformedHeaders(t *testing.T) {
	m, _, _, _, h := setup(t)
	tok, _, _ := m.Create("m", ScopeRead, 0, nil)
	for _, v := range []string{"", "Bearer", "Bearer ", "Basic " + tok, tok, "Bearer  x y", "Bearer " + tok + " extra", "Bearer abc", "Bearer " + strings.Repeat("z", 500)} {
		r := httptest.NewRequest("GET", "/api/v1/x", nil)
		if v != "" {
			r.Header.Set("Authorization", v)
		}
		r.RemoteAddr = "10.1.1.1:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("header %q: got %d", v, w.Code)
		}
	}
	// lowercase scheme is valid
	r := httptest.NewRequest("GET", "/api/v1/x", nil)
	r.Header.Set("Authorization", "bearer "+tok)
	r.RemoteAddr = "10.1.1.2:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("lowercase scheme: %d", w.Code)
	}
}

func TestNoCSRFNeededForTokenAndNoCookieFallback(t *testing.T) {
	// The middleware is self contained: a valid token is enough, no cookie or
	// CSRF header is consulted; a cookie alone is not enough.
	m, _, _, _, h := setup(t)
	tok, _, _ := m.Create("rw", ScopeReadWrite, 0, nil)
	if do(h, "POST", tok, "") != 200 {
		t.Fatal("token POST without CSRF must pass")
	}
	if do(h, "POST", "", "", "Cookie", "zoraxy=session; csrf=abc", "X-CSRF-Token", "abc") != 401 {
		t.Fatal("cookie auth must not be accepted by the token middleware")
	}
}

func TestStorageHashOnlyAndListNoSecret(t *testing.T) {
	m, kv, _, _, _ := setup(t)
	tok, _, _ := m.Create("s", ScopeRead, 0, nil)
	if !strings.HasPrefix(tok, "zrx_") || len(tok) < 4+43 {
		t.Fatalf("token format %q", tok)
	}
	for _, v := range kv.data {
		if strings.Contains(string(v), tok) || strings.Contains(string(v), strings.TrimPrefix(tok, "zrx_")) {
			t.Fatal("clear token persisted")
		}
		if !strings.Contains(string(v), `"Hash":"`) {
			t.Fatal("hash not stored")
		}
	}
	// list API
	w := httptest.NewRecorder()
	m.HandleList(w, httptest.NewRequest("GET", "/", nil))
	body := w.Body.String()
	if strings.Contains(body, tok) || strings.Contains(strings.ToLower(body), "hash") {
		t.Fatalf("list leaks secrets: %s", body)
	}
	// reload from storage keeps working
	m2, err := NewManager(kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	h2 := m2.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if do(h2, "GET", tok, "") != 200 {
		t.Fatal("token lost after reload")
	}
}

func TestCreateHandlerShowsTokenOnce(t *testing.T) {
	m, _, _, _, _ := setup(t)
	form := url.Values{"name": {"ci"}, "scope": {"read"}, "cidrs": {"10.0.0.0/8, 192.168.0.1"}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	m.HandleCreate(w, r)
	var out struct {
		Token string
		Info  Info
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Token == "" || len(out.Info.AllowedCIDRs) != 2 {
		t.Fatalf("bad create response %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	m.HandleList(w, httptest.NewRequest("GET", "/", nil))
	if strings.Contains(w.Body.String(), out.Token) {
		t.Fatal("token visible after creation")
	}
	w = httptest.NewRecorder()
	m.HandleCreate(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 405 {
		t.Fatal("create must be POST only")
	}
}

func TestAuditLogNeverContainsToken(t *testing.T) {
	m, _, lg, _, h := setup(t)
	tok, _, _ := m.Create("audited", ScopeRead, 0, nil)
	do(h, "GET", tok, "")
	do(h, "POST", tok, "")
	do(h, "GET", "zrx_"+strings.Repeat("B", 43), "")
	if len(lg.lines) != 3 {
		t.Fatalf("expected 3 audit lines, got %v", lg.lines)
	}
	all := strings.Join(lg.lines, "\n")
	if strings.Contains(all, tok) || strings.Contains(all, strings.TrimPrefix(tok, "zrx_")) || strings.Contains(all, "BBBBBB") {
		t.Fatal("token in logs")
	}
	for _, want := range []string{"token=audited", "method=GET", "route=/api/v1/x", "ip=10.0.0.1", "status=200", "status=403", "status=401"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in %s", want, all)
		}
	}
}

func TestRateLimitPerTokenAndFailureThrottle(t *testing.T) {
	m, _, _, clk, h := setup(t)
	tok, _, _ := m.Create("rl", ScopeRead, 0, nil)
	limited := 0
	for i := 0; i < 100; i++ {
		if do(h, "GET", tok, "10.5.5.5") == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("no rate limiting")
	}
	clk.add(10 * time.Second)
	if do(h, "GET", tok, "10.5.5.5") != 200 {
		t.Fatal("bucket should refill")
	}
	// failed auth throttling per IP
	for i := 0; i < failLimit; i++ {
		do(h, "GET", "zrx_bad", "10.6.6.6")
	}
	if do(h, "GET", tok, "10.6.6.6") != 429 {
		t.Fatal("failed-auth throttle missing (even valid token blocked from abusive IP)")
	}
	if do(h, "GET", tok, "10.7.7.7") != 200 {
		t.Fatal("other IP must be unaffected")
	}
	clk.add(2 * time.Minute)
	if do(h, "GET", tok, "10.6.6.6") != 200 {
		t.Fatal("throttle should expire")
	}
}

func TestLastUsed(t *testing.T) {
	m, _, _, _, h := setup(t)
	tok, info, _ := m.Create("lu", ScopeRead, 0, nil)
	if info.LastUsed != 0 {
		t.Fatal()
	}
	do(h, "GET", tok, "")
	if m.List()[0].LastUsed == 0 {
		t.Fatal("last used not recorded")
	}
}

// A lifetime far beyond 10 years became "Invalid Date" in the UI: refused at creation.
func TestExpiryTooFarRefused(t *testing.T) {
	m, _, _, clk, _ := setup(t)
	if _, _, err := m.Create("far", ScopeRead, clk.now().Unix()+MaxExpirySeconds+10, nil); err == nil {
		t.Fatal("expiry beyond the maximum lifetime must be rejected")
	}
	if _, _, err := m.Create("ok", ScopeRead, clk.now().Unix()+MaxExpirySeconds-10, nil); err != nil {
		t.Fatalf("expiry inside the maximum lifetime must work: %v", err)
	}
}
