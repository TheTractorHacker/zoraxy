package abuse

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newTestManager(t *testing.T, mod func(*Config)) (*Manager, *clock) {
	t.Helper()
	m := New(t.TempDir())
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	m.SetClock(clk.Now)
	c := DefaultConfig()
	c.Enabled = true
	d := c.Detectors[KindNotFound]
	d.Enabled, d.Threshold, d.WindowSec = true, 3, 10
	c.Detectors[KindNotFound] = d
	c.BanSeconds = 60
	if mod != nil {
		mod(&c)
	}
	if err := m.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	return m, clk
}

func TestDisabledByDefault(t *testing.T) {
	m := New("")
	for i := 0; i < 1000; i++ {
		if m.Report("198.51.100.1", "", KindNotFound, "e") != nil {
			t.Fatal("disabled engine banned")
		}
	}
	if _, b := m.IsBanned("198.51.100.1", ""); b {
		t.Fatal("banned while disabled")
	}
	if m.Active() {
		t.Fatal("must be inactive by default")
	}
}

func TestThresholdWindowAndExpiry(t *testing.T) {
	m, clk := newTestManager(t, nil)
	ip := "198.51.100.7"
	m.Report(ip, "", KindNotFound, "e")
	m.Report(ip, "", KindNotFound, "e")
	clk.Add(11 * time.Second) //first two fall out of the window
	if m.Report(ip, "", KindNotFound, "e") != nil {
		t.Fatal("events outside the window must not count")
	}
	m.Report(ip, "", KindNotFound, "e")
	if b := m.Report(ip, "", KindNotFound, "e"); b == nil {
		t.Fatal("3 events in the window must ban")
	}
	if _, ok := m.IsBanned(ip, ""); !ok {
		t.Fatal("not banned")
	}
	clk.Add(59 * time.Second)
	if _, ok := m.IsBanned(ip, ""); !ok {
		t.Fatal("ban expired early")
	}
	clk.Add(2 * time.Second)
	if _, ok := m.IsBanned(ip, ""); ok {
		t.Fatal("ban did not expire")
	}
	if len(m.List()) != 0 {
		t.Fatal("expired ban listed")
	}
}

func TestEscalationAndCap(t *testing.T) {
	m, clk := newTestManager(t, func(c *Config) { c.BanSeconds = 60; c.EscalationFactor = 2; c.MaxBanSeconds = 200 })
	ip := "198.51.100.8"
	want := []int64{60, 120, 200, 200}
	for i, w := range want {
		var b *Ban
		for j := 0; j < 3; j++ {
			b = m.Report(ip, "", KindNotFound, "e")
		}
		if b == nil {
			t.Fatalf("round %d: no ban", i)
		}
		if got := b.Expires - b.Created; got != w {
			t.Fatalf("round %d: duration %d want %d", i, got, w)
		}
		clk.Add(time.Duration(w+1) * time.Second)
	}
}

func TestProtectedAddressesNeverBanned(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) { c.AllowList = []string{"203.0.113.0/24", "2001:db8:aaaa::/48"} })
	m.Protect = func(a netip.Addr) bool { return a == netip.MustParseAddr("198.51.100.99") } //server's own address
	for _, ip := range []string{"127.0.0.1", "::1", "10.1.2.3", "192.168.0.5", "172.16.9.9", "169.254.1.1", "fe80::1", "fd00::5",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "203.0.113.50", "::ffff:203.0.113.50", "2001:db8:aaaa:1::7", "198.51.100.99", "0.0.0.0"} {
		for i := 0; i < 20; i++ {
			if m.Report(ip, "", KindNotFound, "e") != nil {
				t.Fatalf("%s must never be auto banned", ip)
			}
		}
		if _, err := m.ManualBan(ip, "", "x", "manual", 60); err == nil {
			t.Fatalf("%s must not be manually bannable", ip)
		}
	}
	// explicit opt-in
	c := m.Config()
	c.BanPrivate = true
	c.AllowList = nil
	m.Protect = nil
	m.SetConfig(c)
	var b *Ban
	for i := 0; i < 3; i++ {
		b = m.Report("10.9.9.9", "", KindNotFound, "e")
	}
	if b == nil {
		t.Fatal("BanPrivate must allow banning private ranges")
	}
}

func TestIPNormalisation(t *testing.T) {
	m, _ := newTestManager(t, nil)
	// the same client in different spellings counts as one
	for _, ip := range []string{"198.51.100.20", "::ffff:198.51.100.20", "[::ffff:198.51.100.20]:443"} {
		m.Report(ip, "", KindNotFound, "e")
	}
	if _, ok := m.IsBanned("198.51.100.20", ""); !ok {
		t.Fatal("IPv4-mapped IPv6 spellings must be the same client")
	}
	if _, ok := m.IsBanned("::ffff:198.51.100.20", ""); !ok {
		t.Fatal("lookup via mapped form must match")
	}
	// IPv6 collapses to /64: rotating the interface id does not evade
	for i := 0; i < 3; i++ {
		m.Report(fmt.Sprintf("2001:db8:1:2::%x", i+1), "", KindNotFound, "e")
	}
	if _, ok := m.IsBanned("2001:db8:1:2:dead:beef::1", ""); !ok {
		t.Fatal("/64 neighbour must share the ban")
	}
	if _, ok := m.IsBanned("2001:db8:1:3::1", ""); ok {
		t.Fatal("a different /64 must not be banned")
	}
	// zones and junk
	for _, junk := range []string{"", "unknown", "1.2.3", "1.2.3.4, 5.6.7.8", strings.Repeat("a", 100), "fe80::1%eth0\x00"} {
		if m.Report(junk, "", KindNotFound, "e") != nil {
			t.Fatalf("junk %q banned", junk)
		}
	}
}

func TestPerEndpointScopeAndExclusions(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) { c.PerEndpoint = true; c.ExcludeEndpoints = []string{"skip.example.com"} })
	ip := "198.51.100.30"
	for i := 0; i < 3; i++ {
		m.Report(ip, "a.example.com", KindNotFound, "a.example.com")
	}
	if _, ok := m.IsBanned(ip, "a.example.com"); !ok {
		t.Fatal("endpoint ban missing")
	}
	if _, ok := m.IsBanned(ip, "b.example.com"); ok {
		t.Fatal("per-endpoint ban leaked to another endpoint")
	}
	for i := 0; i < 10; i++ {
		m.Report("198.51.100.31", "skip.example.com", KindNotFound, "skip.example.com")
	}
	if _, ok := m.IsBanned("198.51.100.31", "skip.example.com"); ok {
		t.Fatal("excluded endpoint fed the detector")
	}
	// a global manual ban applies everywhere
	if _, err := m.ManualBan("198.51.100.32", "", "r", "manual", 0); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.IsBanned("198.51.100.32", "b.example.com"); !ok {
		t.Fatal("global ban must apply to all endpoints")
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	m.SetClock(clk.Now)
	c := DefaultConfig()
	c.Enabled = true
	m.SetConfig(c)
	m.ManualBan("198.51.100.40", "", "keep", "manual", 600)
	m.ManualBan("198.51.100.41", "", "perm", "manual", 0)
	m.ManualBan("198.51.100.42", "", "short", "manual", 5)
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	clk.Add(10 * time.Second)
	m2 := New(dir)
	m2.SetClock(clk.Now)
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if !m2.Active() {
		t.Fatal("config not restored")
	}
	if _, ok := m2.IsBanned("198.51.100.40", ""); !ok {
		t.Fatal("ban lost on restart")
	}
	if _, ok := m2.IsBanned("198.51.100.41", ""); !ok {
		t.Fatal("permanent ban lost on restart")
	}
	if _, ok := m2.IsBanned("198.51.100.42", ""); ok {
		t.Fatal("expired ban resurrected")
	}
}

func TestBoundedMemory(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) { c.MaxTracked = 100; c.MaxBans = 50; c.Detectors[KindNotFound] = Detector{true, 2, 10} })
	for i := 0; i < 5000; i++ {
		m.Report(fmt.Sprintf("198.51.%d.%d", i/250, i%250+1), "", KindNotFound, "e")
	}
	m.cmu.Lock()
	n := len(m.counters)
	m.cmu.Unlock()
	if n > 100 {
		t.Fatalf("counter table unbounded: %d", n)
	}
	for i := 0; i < 500; i++ {
		ip := fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)
		m.Report(ip, "", KindNotFound, "e")
		m.Report(ip, "", KindNotFound, "e")
	}
	if got := len(m.List()); got > 50 {
		t.Fatalf("ban table unbounded: %d", got)
	}
}

func TestConcurrency(t *testing.T) {
	m, _ := newTestManager(t, nil)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := fmt.Sprintf("198.51.100.%d", (g*7+i)%200+1)
				m.Report(ip, "", KindNotFound, "e")
				m.IsBanned(ip, "")
				if i%50 == 0 {
					m.List()
					m.Sweep()
					m.Flush()
					m.Unban(ip, "")
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestConfigValidation(t *testing.T) {
	bad := []func(*Config){
		func(c *Config) { c.Detectors["nonsense"] = Detector{true, 1, 1} },
		func(c *Config) { c.Detectors[KindNotFound] = Detector{true, 0, 10} },
		func(c *Config) { c.Detectors[KindNotFound] = Detector{true, 5, 0} },
		func(c *Config) { c.Detectors[KindNotFound] = Detector{true, 5, 999999999} },
		func(c *Config) { c.AllowList = []string{"not-an-ip"} },
		func(c *Config) { c.IPv6Prefix = 8 },
	}
	for i, f := range bad {
		c := DefaultConfig()
		f(&c)
		if _, err := c.Normalise(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	c := DefaultConfig()
	c.MaxTracked = 1 << 40
	n, _ := c.Normalise()
	if n.MaxTracked > hardMaxTracked {
		t.Error("MaxTracked not clamped")
	}
}

func post(h http.HandlerFunc, path string, tok string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestRemoteAPIToken(t *testing.T) {
	m, _ := newTestManager(t, nil)
	ban := m.HandleRemote("ban")
	// disabled until a token exists; empty token never matches an empty hash
	if w := post(ban, "/x", "", url.Values{"ip": {"198.51.100.50"}}); w.Code != 401 {
		t.Fatalf("remote API open without token: %d", w.Code)
	}
	w := post(m.HandleToken, "/t", "", url.Values{"action": {"generate"}})
	tok := strings.Split(strings.Split(w.Body.String(), `"token":"`)[1], `"`)[0]
	if len(tok) != 64 {
		t.Fatalf("token %q", tok)
	}
	if strings.Contains(fmt.Sprint(m.Config().RemoteTokenHash), tok) {
		t.Fatal("token stored in clear")
	}
	for _, bad := range []string{"", "x", tok[:63], tok + "0", strings.ToUpper(tok)} {
		if w := post(ban, "/x", bad, url.Values{"ip": {"198.51.100.50"}}); w.Code != 401 {
			t.Fatalf("bad token %q accepted", bad)
		}
	}
	if w := post(ban, "/x", tok, url.Values{"ip": {"198.51.100.50"}, "seconds": {"60"}}); w.Code != 200 || strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("valid token rejected: %d %s", w.Code, w.Body.String())
	}
	if _, ok := m.IsBanned("198.51.100.50", ""); !ok {
		t.Fatal("remote ban not applied")
	}
	// protected address cannot be banned remotely either
	w = post(ban, "/x", tok, url.Values{"ip": {"127.0.0.1"}})
	if !strings.Contains(w.Body.String(), "protected") {
		t.Fatalf("loopback remote ban allowed: %s", w.Body.String())
	}
	// GET is refused for mutations
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	ww := httptest.NewRecorder()
	ban(ww, r)
	if ww.Code != 405 {
		t.Fatalf("GET ban: %d", ww.Code)
	}
	post(m.HandleRemote("unban"), "/x", tok, url.Values{"ip": {"198.51.100.50"}})
	if _, ok := m.IsBanned("198.51.100.50", ""); ok {
		t.Fatal("unban failed")
	}
	// revoke
	post(m.HandleToken, "/t", "", url.Values{"action": {"revoke"}})
	if w := post(ban, "/x", tok, url.Values{"ip": {"198.51.100.51"}}); w.Code != 401 {
		t.Fatal("revoked token still works")
	}
}

func TestSetConfigKeepsTokenHashAndNeverLeaksIt(t *testing.T) {
	m, _ := newTestManager(t, nil)
	post(m.HandleToken, "/t", "", url.Values{"action": {"generate"}})
	want := m.Config().RemoteTokenHash
	c := m.Config()
	c.RemoteTokenHash = "attacker-chosen"
	js := `{"Enabled":true,"RemoteTokenHash":"attacker-chosen"}`
	post(m.HandleSetConfig, "/c", "", url.Values{"config": {js}})
	if m.Config().RemoteTokenHash != want {
		t.Fatal("config endpoint must not change the token hash")
	}
	r := httptest.NewRequest(http.MethodGet, "/c", nil)
	w := httptest.NewRecorder()
	m.HandleGetConfig(w, r)
	if strings.Contains(w.Body.String(), want) {
		t.Fatal("token hash leaked by the config API")
	}
}
