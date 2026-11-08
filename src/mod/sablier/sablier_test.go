package sablier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSablier struct {
	*httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	lastQ  url.Values
	lastP  string
	handle func(w http.ResponseWriter, r *http.Request)
}

func newFake(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *fakeSablier {
	f := &fakeSablier{handle: h}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		f.lastQ, f.lastP = r.URL.Query(), r.URL.Path
		f.mu.Unlock()
		f.handle(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func ready(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(StatusHeader, "ready")
	w.Write([]byte("ok"))
}

func gate(t *testing.T, f *fakeSablier, mut func(*Config)) *Gate {
	t.Helper()
	cfg := Config{Enabled: true, URL: f.URL, Names: []string{"whoami"}, SessionDuration: "1m"}
	if mut != nil {
		mut(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestReadyIsCachedBriefly(t *testing.T) {
	f := newFake(t, ready)
	g := gate(t, f, nil)
	now := time.Now()
	g.now = func() time.Time { return now }
	for i := 0; i < 20; i++ {
		out, err := g.Check(context.Background())
		if err != nil || !out.Ready {
			t.Fatal(out, err)
		}
	}
	if f.hits.Load() != 1 {
		t.Fatalf("20 asset requests within the cache window made %d calls to Sablier", f.hits.Load())
	}
	now = now.Add(4 * time.Second) //default cache is 3 s
	if out, _ := g.Check(context.Background()); !out.Ready || f.hits.Load() != 2 {
		t.Fatalf("cache did not expire: hits=%d", f.hits.Load())
	}
}

func TestCacheDisabledAndCustom(t *testing.T) {
	f := newFake(t, ready)
	g := gate(t, f, func(c *Config) { c.ReadyCacheSeconds = -1 })
	for i := 0; i < 3; i++ {
		g.Check(context.Background())
	}
	if f.hits.Load() != 3 {
		t.Fatalf("disabled cache: %d hits", f.hits.Load())
	}
}

func TestNotReadyIsNeverCached(t *testing.T) {
	var starting atomic.Bool
	starting.Store(true)
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if starting.Load() {
			w.Header().Set(StatusHeader, "not-ready")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<html>starting</html>"))
			return
		}
		ready(w, r)
	})
	g := gate(t, f, nil)
	out, err := g.Check(context.Background())
	if err != nil || out.Ready || out.Status != 200 || out.Type != "text/html; charset=utf-8" || string(out.Body) != "<html>starting</html>" {
		t.Fatalf("%+v %v", out, err)
	}
	starting.Store(false)
	out, err = g.Check(context.Background())
	if err != nil || !out.Ready {
		t.Fatalf("workload became ready but the gate still waits: %+v %v", out, err)
	}
}

func TestSablierStatusIsPassedThrough(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(StatusHeader, "not-ready")
		w.WriteHeader(503)
		w.Write([]byte("down"))
	})
	out, err := gate(t, f, nil).Check(context.Background())
	if err != nil || out.Ready || out.Status != 503 || string(out.Body) != "down" {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestRequestURLDynamicAndBlocking(t *testing.T) {
	f := newFake(t, ready)
	g := gate(t, f, func(c *Config) {
		c.Names = []string{"a", "stack_b"}
		c.DisplayName = "My App & Co"
		c.Theme = "hacker-terminal"
		c.RefreshFrequency = "10s"
		c.ShowDetails = true
	})
	g.Check(context.Background())
	if f.lastP != "/api/strategies/dynamic" {
		t.Fatal(f.lastP)
	}
	q := f.lastQ
	if strings.Join(q["names"], ",") == "" || q.Get("session_duration") != "1m" || q.Get("display_name") != "My App & Co" ||
		q.Get("theme") != "hacker-terminal" || q.Get("refresh_frequency") != "10s" || q.Get("show_details") != "true" || q.Get("timeout") != "" || q.Get("group") != "" {
		t.Fatalf("dynamic query: %v", q)
	}
	if len(q["names"]) != 2 {
		t.Fatalf("names must be repeated parameters: %v", q["names"])
	}

	f2 := newFake(t, ready)
	g2 := gate(t, f2, func(c *Config) {
		c.Strategy = StrategyBlocking
		c.Names = nil
		c.Group = "mygroup"
		c.BlockingTimeout = "45s"
		c.Theme = "ignored-for-blocking"
	})
	g2.Check(context.Background())
	if f2.lastP != "/api/strategies/blocking" || f2.lastQ.Get("group") != "mygroup" || f2.lastQ.Get("timeout") != "45s" || f2.lastQ.Get("theme") != "" || len(f2.lastQ["names"]) != 0 {
		t.Fatalf("blocking: %s %v", f2.lastP, f2.lastQ)
	}
}

func TestErrorsFromSablier(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"500 without header": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"200 auth portal":    func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>login</html>")) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/latest", http.StatusFound)
		},
		"huge": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(StatusHeader, "not-ready")
			w.Write([]byte(strings.Repeat("x", maxBodyBytes+10)))
		},
	} {
		f := newFake(t, h)
		out, err := gate(t, f, nil).Check(context.Background())
		if err == nil {
			t.Errorf("%s: expected an error, got %+v", name, out)
		}
	}
}

func TestTimeout(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
		ready(w, r)
	})
	g := gate(t, f, func(c *Config) { c.RequestTimeoutSeconds = 1 })
	start := time.Now()
	_, err := g.Check(context.Background())
	if err == nil || time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("timeout not honoured: %v after %v", err, time.Since(start))
	}
	//The shared call keeps its own deadline, an impatient client only abandons the wait
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := g.Check(ctx); err == nil {
		t.Fatal("client context not honoured")
	}
}

func TestConcurrentCallsShareOneRequest(t *testing.T) {
	release := make(chan struct{})
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) { <-release; ready(w, r) })
	g := gate(t, f, nil)
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if out, err := g.Check(context.Background()); err != nil || !out.Ready {
				t.Error(out, err)
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()
	if f.hits.Load() != 1 {
		t.Fatalf("thundering herd: %d calls to Sablier", f.hits.Load())
	}
}

func TestValidation(t *testing.T) {
	base := func() Config { return Config{Enabled: true, URL: "http://sablier:10000", Names: []string{"web"}} }
	if err := (&Config{}).Validate(); err != nil {
		t.Fatal("empty config must be valid (feature off)")
	}
	if err := (func() *Config { c := base(); return &c })().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Config){
		"scheme":           func(c *Config) { c.URL = "file:///etc/passwd" },
		"ftp":              func(c *Config) { c.URL = "ftp://x" },
		"credentials":      func(c *Config) { c.URL = "http://u:p@sablier" },
		"query":            func(c *Config) { c.URL = "http://sablier?x=1" },
		"metadata v4":      func(c *Config) { c.URL = "http://169.254.169.254/" },
		"metadata v6":      func(c *Config) { c.URL = "http://[fe80::1]/" },
		"alibaba":          func(c *Config) { c.URL = "http://100.100.100.200/" },
		"no names":         func(c *Config) { c.Names = nil },
		"names and group":  func(c *Config) { c.Group = "g" },
		"bad name":         func(c *Config) { c.Names = []string{"a&b=c"} },
		"newline name":     func(c *Config) { c.Names = []string{"a\nb"} },
		"strategy":         func(c *Config) { c.Strategy = "magic" },
		"duration":         func(c *Config) { c.SessionDuration = "soon" },
		"short session":    func(c *Config) { c.SessionDuration = "1s" },
		"refresh":          func(c *Config) { c.RefreshFrequency = "0s" },
		"blocking timeout": func(c *Config) { c.BlockingTimeout = "24h" },
		"theme":            func(c *Config) { c.Theme = "../../x" },
		"display name ctl": func(c *Config) { c.DisplayName = "a\r\nb" },
		"cache":            func(c *Config) { c.ReadyCacheSeconds = 600 },
		"bypass":           func(c *Config) { c.BypassPaths = []string{"healthz"} },
		"timeout":          func(c *Config) { c.RequestTimeoutSeconds = 9999 },
		"too many names":   func(c *Config) { c.Names = make([]string, 40) },
	}
	for name, mut := range bad {
		c := base()
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := base()
	c.URL = "http://169.254.169.254/"
	c.AllowMetadataAddress = true
	if c.Validate() != nil {
		t.Error("explicit allow must work")
	}
}

func TestSSRFBlockedAtDialTime(t *testing.T) {
	//The dial control runs on the resolved peer address, so a host name resolving to a metadata address is refused too
	c := newClient(Config{})
	for _, target := range []string{"http://169.254.169.254:81/", "http://[fe80::1]:81/", "http://100.100.100.200:81/", "http://[::ffff:169.254.169.254]:81/", "http://0.0.0.0:81/"} {
		_, err := c.Get(target)
		if err == nil || !strings.Contains(err.Error(), "refused") {
			t.Errorf("%s: want a refused error, got %v", target, err)
		}
	}
	//With the explicit allow the dial control steps aside (the connection then fails for lack of a listener, not by policy)
	_, err := newClient(Config{AllowMetadataAddress: true}).Get("http://169.254.169.254:81/")
	if err != nil && strings.Contains(err.Error(), "refused") {
		t.Errorf("allow option ignored: %v", err)
	}
	//Loopback and private addresses are fine: Sablier normally runs next to the proxy
	f := newFake(t, ready)
	if out, err := gate(t, f, nil).Check(context.Background()); err != nil || !out.Ready {
		t.Fatalf("loopback sablier refused: %v", err)
	}
}

func TestBypass(t *testing.T) {
	c := Config{BypassPaths: []string{"/healthz", "/static/"}}
	for path, want := range map[string]bool{"/healthz": true, "/healthz/x": true, "/healthzz": false, "/static/a.css": true, "/static": false, "/other": false} {
		if c.Bypass(path) != want {
			t.Errorf("%s: want %v", path, want)
		}
	}
}
