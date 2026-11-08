package dynamicproxy

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"imuslab.com/zoraxy/mod/abuse"
)

func newAbuseRouter(t *testing.T, status int, mod func(*abuse.Config)) (*Router, *ProxyEndpoint, *abuse.Manager) {
	t.Helper()
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
		w.WriteHeader(status)
		return true
	}
	m := abuse.New("")
	c := abuse.DefaultConfig()
	c.Enabled = true
	c.Detectors[abuse.KindNotFound] = abuse.Detector{Enabled: true, Threshold: 3, WindowSec: 60}
	c.Detectors[abuse.KindForbidden] = abuse.Detector{Enabled: true, Threshold: 3, WindowSec: 60}
	if mod != nil {
		mod(&c)
	}
	if err := m.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	router.Option.Abuse = m
	return router, sep, m
}

func TestAbuseBanFlow(t *testing.T) {
	router, sep, m := newAbuseRouter(t, 404, nil)
	for i := 0; i < 3; i++ {
		if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.5:1000"); w.Code != 404 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.5:1000"); w.Code != 403 {
		t.Fatalf("banned client got %d, want 403", w.Code)
	}
	if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.6:1000"); w.Code != 404 {
		t.Fatalf("other client affected: %d", w.Code)
	}
	if !m.Unban("198.51.100.5", "") {
		t.Fatal("unban")
	}
	if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.5:1000"); w.Code != 404 {
		t.Fatalf("unbanned client still blocked: %d", w.Code)
	}
}

// Spoofed forwarded headers from an untrusted peer must neither ban a victim nor evade a ban
func TestAbuseSpoofedForwardedHeaders(t *testing.T) {
	router, sep, m := newAbuseRouter(t, 404, nil)
	rule, _ := router.Option.AccessController.GetAccessRuleByID("default")
	rule.TrustProxyHeadersOnly = true
	send := func(remote, xff string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com/x", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Real-IP", xff)
		router.handleNonTLSRequest(w, r, sep)
		return w.Code
	}
	for i := 0; i < 10; i++ {
		send("198.51.100.5:1", "192.0.2.77") //attacker claims to be 192.0.2.77
	}
	if _, banned := m.IsBanned("192.0.2.77", ""); banned {
		t.Fatal("victim banned through a spoofed X-Forwarded-For")
	}
	if _, banned := m.IsBanned("198.51.100.5", ""); !banned {
		t.Fatal("real peer was not banned")
	}
	if code := send("198.51.100.5:1", "192.0.2.78"); code != 403 {
		t.Fatalf("attacker evaded the ban with a spoofed header: %d", code)
	}
}

func TestAbuseNeverBansLoopbackOrDisabled(t *testing.T) {
	router, sep, m := newAbuseRouter(t, 404, nil)
	for i := 0; i < 20; i++ {
		serveNonTLS(router, sep, "http://app.example.com/x", "127.0.0.1:1000")
		serveNonTLS(router, sep, "http://app.example.com/x", "[::1]:1000")
		serveNonTLS(router, sep, "http://app.example.com/x", "192.168.1.5:1000")
	}
	if len(m.List()) != 0 {
		t.Fatalf("private clients banned: %+v", m.List())
	}
	router.Option.Abuse = nil
	for i := 0; i < 20; i++ {
		if w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.5:1000"); w.Code != 404 {
			t.Fatal("nil manager changed behaviour")
		}
	}
}

func TestAbuseStatusKinds(t *testing.T) {
	router, sep, m := newAbuseRouter(t, 403, nil)
	for i := 0; i < 3; i++ {
		serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.5:1000")
	}
	l := m.List()
	if len(l) != 1 || l[0].Source != string(abuse.KindForbidden) {
		t.Fatalf("403 responses should ban via the forbidden detector: %+v", l)
	}
	// 200s never count
	router2, sep2, m2 := newAbuseRouter(t, 200, nil)
	for i := 0; i < 50; i++ {
		serveNonTLS(router2, sep2, "http://app.example.com/x", "198.51.100.5:1000")
	}
	if len(m2.List()) != 0 {
		t.Fatal("successful responses banned a client")
	}
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

func TestAbuseDropConnection(t *testing.T) {
	router, sep, m := newAbuseRouter(t, 404, func(c *abuse.Config) { c.DropConnection = true })
	m.ManualBan("198.51.100.5", "", "t", "manual", 600)

	// HTTP/1: hijack + close, no bytes written
	srv, cli := net.Pipe()
	defer cli.Close()
	w := &hijackRecorder{httptest.NewRecorder(), srv}
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.RemoteAddr = "198.51.100.5:1"
	router.handleNonTLSRequest(w, r, sep)
	buf := make([]byte, 1)
	if n, err := cli.Read(buf); n != 0 || err == nil {
		t.Fatalf("connection not closed without data: n=%d err=%v", n, err)
	}
	if w.Body.Len() != 0 {
		t.Fatal("a response was written to a dropped client")
	}

	// HTTP/2 style writer (no Hijacker): handler aborts so net/http resets the stream
	defer func() {
		if rec := recover(); rec != http.ErrAbortHandler {
			t.Fatalf("expected ErrAbortHandler panic, got %v", rec)
		}
	}()
	w2 := httptest.NewRecorder()
	router.handleNonTLSRequest(w2, r, sep)
	t.Fatal("not reached")
}

// the observing writer must keep websocket upgrades (Hijack) and Flush working
func TestAbuseRecorderKeepsHijackAndFlush(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	var w http.ResponseWriter = &abuseRecorder{ResponseWriter: &hijackRecorder{httptest.NewRecorder(), srv}}
	if _, ok := w.(http.Hijacker); !ok {
		t.Fatal("no Hijacker")
	}
	if _, _, err := w.(http.Hijacker).Hijack(); err != nil {
		t.Fatal(err)
	}
	w.(http.Flusher).Flush()
}
