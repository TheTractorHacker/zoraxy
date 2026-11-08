package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/sablier"
)

type sablierFixture struct {
	router   *Router
	sep      *ProxyEndpoint
	upstream atomic.Int32
	calls    atomic.Int32
	state    atomic.Value // "ready" | "starting" | "error"
}

func newSablierFixture(t *testing.T) *sablierFixture {
	f := &sablierFixture{}
	f.state.Store("starting")
	sab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		switch f.state.Load().(string) {
		case "ready":
			w.Header().Set(sablier.StatusHeader, "ready")
		case "starting":
			w.Header().Set(sablier.StatusHeader, "not-ready")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<html>WAITING PAGE</html>"))
		default:
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(sab.Close)
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) { f.upstream.Add(1); w.Write([]byte("upstream:" + r.URL.Path)) })
	f.router, f.sep = newOpsTestRouter(t, be)
	f.sep.Sablier = &SablierConfig{Config: sablier.Config{Enabled: true, URL: sab.URL, Names: []string{"app"}}}
	return f
}

func TestSablierWaitingPageThenProxy(t *testing.T) {
	f := newSablierFixture(t)
	w := serveOps(f.router, "GET", "/", map[string]string{"Accept": "text/html"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "WAITING PAGE") || f.upstream.Load() != 0 {
		t.Fatalf("starting: %d %q upstream=%d", w.Code, w.Body.String(), f.upstream.Load())
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("headers %v", w.Header())
	}
	f.state.Store("ready")
	w = serveOps(f.router, "GET", "/page", nil)
	if w.Body.String() != "upstream:/page" {
		t.Fatalf("ready: %d %q", w.Code, w.Body.String())
	}
	//Ready is cached: further asset requests do not call Sablier again
	before := f.calls.Load()
	for i := 0; i < 10; i++ {
		serveOps(f.router, "GET", "/asset.js", nil)
	}
	if f.calls.Load() != before {
		t.Fatalf("ready answer not cached: %d extra calls", f.calls.Load()-before)
	}
	if f.upstream.Load() != 11 {
		t.Fatalf("upstream hits %d", f.upstream.Load())
	}
}

func TestSablierWebSocketAndAPIClientsGetPlain503(t *testing.T) {
	f := newSablierFixture(t)
	w := serveOps(f.router, "GET", "/ws", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"})
	if w.Code != 503 || strings.Contains(w.Body.String(), "WAITING PAGE") || w.Header().Get("Retry-After") == "" || f.upstream.Load() != 0 {
		t.Fatalf("websocket: %d %q", w.Code, w.Body.String())
	}
	w = serveOps(f.router, "GET", "/api/x", map[string]string{"Accept": "application/json"})
	if w.Code != 503 || strings.Contains(w.Body.String(), "WAITING PAGE") {
		t.Fatalf("json client: %d %q", w.Code, w.Body.String())
	}
	//A ready workload passes websocket upgrades through untouched
	f.state.Store("ready")
	w = serveOps(f.router, "GET", "/ws", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"})
	if f.upstream.Load() == 0 {
		t.Fatalf("ready websocket not proxied: %d", w.Code)
	}
}

func TestSablierFailClosedAndOpen(t *testing.T) {
	f := newSablierFixture(t)
	f.state.Store("error")
	w := serveOps(f.router, "GET", "/", map[string]string{"X-Request-Id": "rid-9"})
	if w.Code != 503 || f.upstream.Load() != 0 || !strings.Contains(w.Body.String(), "rid-9") {
		t.Fatalf("fail closed: %d %q", w.Code, w.Body.String())
	}
	f.sep.Sablier = &SablierConfig{Config: f.sep.Sablier.Config}
	f.sep.Sablier.FailOpen = true
	w = serveOps(f.router, "GET", "/", nil)
	if w.Body.String() != "upstream:/" {
		t.Fatalf("fail open: %d %q", w.Code, w.Body.String())
	}
	//Unreachable Sablier
	f.sep.Sablier = &SablierConfig{Config: sablier.Config{Enabled: true, URL: "http://127.0.0.1:1", Names: []string{"app"}}}
	if w := serveOps(f.router, "GET", "/", nil); w.Code != 503 {
		t.Fatalf("unreachable, fail closed: %d", w.Code)
	}
}

func TestSablierBypassPathsAndDisabled(t *testing.T) {
	f := newSablierFixture(t)
	f.sep.Sablier.BypassPaths = []string{"/healthz"}
	f.sep.Sablier = &SablierConfig{Config: f.sep.Sablier.Config}
	if w := serveOps(f.router, "GET", "/healthz", nil); w.Body.String() != "upstream:/healthz" || f.calls.Load() != 0 {
		t.Fatalf("bypass: %d %q calls=%d", w.Code, w.Body.String(), f.calls.Load())
	}
	f.sep.Sablier = &SablierConfig{Config: sablier.Config{Enabled: false, URL: f.sep.Sablier.URL, Names: []string{"app"}}}
	if w := serveOps(f.router, "GET", "/", nil); w.Body.String() != "upstream:/" || f.calls.Load() != 0 {
		t.Fatalf("disabled gate must be transparent: %q", w.Body.String())
	}
	f.sep.Sablier = nil
	if w := serveOps(f.router, "GET", "/", nil); w.Body.String() != "upstream:/" {
		t.Fatal("no config must be transparent")
	}
}

func TestSablierHandlerModeScriptDoesNotWakeWorkload(t *testing.T) {
	f := newSablierFixture(t)
	f.sep.Script = &ScriptConfig{Enabled: true, Mode: ScriptModeHandler, Code: `respond(200, "static")`}
	w := serveOps(f.router, "GET", "/", nil)
	if w.Body.String() != "static" || f.calls.Load() != 0 {
		t.Fatalf("a script handler replaces the upstream, Sablier must not be called: %q calls=%d", w.Body.String(), f.calls.Load())
	}
}

func TestSablierConfigRoundTrip(t *testing.T) {
	sep := &ProxyEndpoint{Sablier: &SablierConfig{Config: sablier.Config{Enabled: true, URL: "http://s:10000", Strategy: "blocking", Names: []string{"a"}, FailOpen: true}}}
	cp := CopyEndpoint(sep)
	if cp.Sablier == nil || !cp.Sablier.Enabled || cp.Sablier.URL != "http://s:10000" || cp.Sablier.Strategy != "blocking" || !cp.Sablier.FailOpen || cp.Sablier.Names[0] != "a" {
		t.Fatalf("%+v", cp.Sablier)
	}
	if err := cp.Sablier.Validate(); err != nil {
		t.Fatal(err)
	}
}
