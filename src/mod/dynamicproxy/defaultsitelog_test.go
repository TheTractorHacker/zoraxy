package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultSiteLogger_TokenBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	d := &defaultSiteLogger{now: func() time.Time { return now }}
	for i := 0; i < defaultSiteLogBurst; i++ {
		if ok, dropped := d.allow(); !ok || dropped != 0 {
			t.Fatalf("burst line %d: ok=%v dropped=%d", i, ok, dropped)
		}
	}
	for i := 0; i < 100; i++ {
		if ok, _ := d.allow(); ok {
			t.Fatal("line allowed beyond the burst without time passing")
		}
	}
	//One second later: defaultSiteLogPerSecond tokens, the first reports the 100 dropped lines
	now = now.Add(time.Second)
	ok, dropped := d.allow()
	if !ok || dropped != 100 {
		t.Fatalf("after refill: ok=%v dropped=%d, want true/100", ok, dropped)
	}
	ok, dropped = d.allow()
	if !ok || dropped != 0 {
		t.Fatalf("second line after refill: ok=%v dropped=%d", ok, dropped)
	}
	//Long idle never banks more than the burst
	now = now.Add(time.Hour)
	allowed := 0
	for i := 0; i < 1000; i++ {
		if ok, _ := d.allow(); ok {
			allowed++
		}
	}
	if allowed != defaultSiteLogBurst {
		t.Fatalf("allowed %d after idle, want %d", allowed, defaultSiteLogBurst)
	}
}

func rootRequest(router *Router) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://unknown.example.org/", nil)
	r.RemoteAddr = "198.51.100.1:1000"
	router.mux.(*ProxyHandler).ServeHTTP(w, r)
	return w
}

func TestDefaultSiteLogging_OffByDefaultAndRateLimited(t *testing.T) {
	router, _, _ := newNonTLSTestRouter(t)
	router.Root = &ProxyEndpoint{ProxyType: ProxyTypeRoot, DefaultSiteOption: DefaultSite_NotFoundPage, parent: router}

	for i := 0; i < 50; i++ {
		if w := rootRequest(router); w.Code != 404 {
			t.Fatalf("default site answered %d", w.Code)
		}
	}
	if n := router.DefaultSiteLogStats(); n != 0 {
		t.Fatalf("logged %d default site lines with the switch off", n)
	}

	router.SetDefaultSiteLogging(true)
	for i := 0; i < 200; i++ {
		rootRequest(router)
	}
	n := router.DefaultSiteLogStats()
	if n < 1 || n > defaultSiteLogBurst+int64(defaultSiteLogPerSecond)*5 {
		t.Fatalf("logged %d lines for a 200 request flood, expected about the burst of %d", n, defaultSiteLogBurst)
	}
	if router.defaultSiteLog.suppressed.Load() == 0 {
		t.Fatal("no suppressed lines counted")
	}

	router.SetDefaultSiteLogging(false)
	before := router.DefaultSiteLogStats()
	rootRequest(router)
	if router.DefaultSiteLogStats() != before {
		t.Fatal("logged after the switch was turned off")
	}
}
