package dynamicproxy

import (
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/statistic"
	"imuslab.com/zoraxy/mod/visitors"
)

// The visitor list must attribute requests with the trusted-proxy aware client IP:
// CF-Connecting-IP counts only when the TCP peer is a trusted proxy.
func TestVisitorAttributionBehindCloudflare(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	rule.TrustProxyHeadersOnly = true
	router.Option.AccessController.AddTrustedProxy("173.245.48.0/20", "cloudflare")

	tr := visitors.New("", visitors.DefaultSettings())
	tr.Start()
	defer tr.Close()
	router.Option.VisitorTracker = tr

	do := func(remote string, hdr map[string]string, path string) {
		r := httptest.NewRequest("GET", "http://app.example.com"+path, nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		r.Header.Set("User-Agent", "test-agent")
		router.logRequest(r, true, 200, "host-http", "app.example.com", "up", sep)
	}
	waitFor := func(n int) {
		for i := 0; i < 400 && tr.Stats().Recorded < uint64(n); i++ {
			time.Sleep(5 * time.Millisecond)
		}
	}

	// 1. genuine Cloudflare hit: peer is a Cloudflare address, real client in CF-Connecting-IP
	do("173.245.48.10:5555", map[string]string{"CF-Connecting-IP": "203.0.113.50", "X-Forwarded-For": "203.0.113.50"}, "/a?secret=1")
	// 2. attacker talks directly and forges CF-Connecting-IP: must be recorded under its own address, direct
	do("198.51.100.77:6666", map[string]string{"CF-Connecting-IP": "203.0.113.99"}, "/b")
	waitFor(2)

	v, recent := tr.Get("203.0.113.50")
	if v == nil || v.Via != visitors.ViaCloudflare || v.ViaHeader != "CF-Connecting-IP" {
		t.Fatalf("cloudflare visitor not attributed: %+v", v)
	}
	if len(recent) != 1 || recent[0].Path != "/a" {
		t.Fatalf("query string must be stripped: %+v", recent)
	}
	if v, _ := tr.Get("203.0.113.99"); v != nil {
		t.Fatal("spoofed CF-Connecting-IP from an untrusted peer was used as the client address")
	}
	a, _ := tr.Get("198.51.100.77")
	if a == nil || a.Via != visitors.ViaDirect {
		t.Fatalf("attacker should be recorded as direct under its own address: %+v", a)
	}
	if v, _ := tr.Get("173.245.48.10"); v != nil {
		t.Fatal("the proxy's own address must not be listed as a visitor")
	}
}

func TestVisitorExclusionAndOptOut(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	tr := visitors.New("", visitors.DefaultSettings())
	tr.Start()
	defer tr.Close()
	router.Option.VisitorTracker = tr
	var excludeBlocked atomic.Bool
	tr.SetExcludeBlocked(excludeBlocked.Load)
	tr.SetExcluder(func(ip string) bool { return ip == "192.0.2.1" })

	send := func(remote, ft string) {
		r := httptest.NewRequest("GET", "http://app.example.com/", nil)
		r.RemoteAddr = remote + ":1"
		router.logRequest(r, ft == "host-http", 200, ft, "app.example.com", "up", sep)
	}
	send("192.0.2.1", "host-http") // excluded address
	send("192.0.2.2", "waf-blocked")
	time.Sleep(100 * time.Millisecond) // the hook records from a goroutine; let it finish before flipping the switch
	excludeBlocked.Store(true)
	send("192.0.2.3", "waf-blocked") // excluded: blocked requests are left out
	sep.DisableStatisticCollection = true
	send("192.0.2.4", "host-http") // rule opted out of statistics
	sep.DisableStatisticCollection = false
	send("192.0.2.5", "host-http")

	for i := 0; i < 400 && tr.Stats().Recorded < 2; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	for ip, want := range map[string]bool{"192.0.2.1": false, "192.0.2.2": true, "192.0.2.3": false, "192.0.2.4": false, "192.0.2.5": true} {
		if v, _ := tr.Get(ip); (v != nil) != want {
			t.Errorf("%s recorded=%v want %v", ip, v != nil, want)
		}
	}
	if v, _ := tr.Get("192.0.2.2"); v == nil || v.Blocked != 1 {
		t.Errorf("blocked hit not counted: %+v", v)
	}
	_ = statistic.IsBlockedForwardType
}
