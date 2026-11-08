package dnsresponder

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testNames() []string {
	return []string{"app.example.com", "*.wild.example.org", "Alias.Example.com", "*", "*.com", "10.0.0.1"}
}

func testConfig() Config {
	c := DefaultConfig()
	c.Enabled = true
	c.ListenAddr = "127.0.0.1:0"
	c.IPv4 = "192.168.1.10"
	c.IPv6 = "fd00::10"
	c.RateLimitQPS = 1000
	c.RateBurst = 1000
	return c
}

func startServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := newServer(cfg, func() []string { return testNames() }, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

func query(t *testing.T, netw, addr, name string, qt uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	c := &dns.Client{Net: netw, Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s %s: %v", netw, name, dns.TypeToString[qt], err)
	}
	return r
}

func TestHostedNames(t *testing.T) {
	s := startServer(t, testConfig())
	for _, netw := range []string{"udp", "tcp"} {
		r := query(t, netw, s.Addr(), "app.example.com", dns.TypeA)
		if r.Rcode != dns.RcodeSuccess || !r.Authoritative || r.RecursionAvailable || len(r.Answer) != 1 {
			t.Fatalf("%s: %v", netw, r)
		}
		if a := r.Answer[0].(*dns.A); a.A.String() != "192.168.1.10" || a.Hdr.Ttl != 60 {
			t.Fatalf("bad A %v", a)
		}
		r = query(t, netw, s.Addr(), "APP.Example.COM.", dns.TypeAAAA)
		if len(r.Answer) != 1 || r.Answer[0].(*dns.AAAA).AAAA.String() != "fd00::10" {
			t.Fatalf("bad AAAA %v", r)
		}
	}
	//alias with different case in the configuration
	if r := query(t, "udp", s.Addr(), "alias.example.com", dns.TypeA); len(r.Answer) != 1 {
		t.Fatal("alias not answered")
	}
	//SOA and NS
	r := query(t, "udp", s.Addr(), "app.example.com", dns.TypeSOA)
	if len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("soa: %v", r)
	}
	r = query(t, "udp", s.Addr(), "app.example.com", dns.TypeNS)
	if len(r.Answer) != 1 || len(r.Extra) != 2 {
		t.Fatalf("ns: %v", r)
	}
	//NODATA: hosted name, other type, SOA in authority
	r = query(t, "udp", s.Addr(), "app.example.com", dns.TypeTXT)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatalf("nodata: %v", r)
	}
}

func TestFallbackToListenAddress(t *testing.T) {
	c := testConfig()
	c.IPv4, c.IPv6 = "", ""
	s := startServer(t, c)
	r := query(t, "udp", s.Addr(), "app.example.com", dns.TypeA)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "127.0.0.1" {
		t.Fatalf("expected listen address fallback: %v", r)
	}
	r = query(t, "udp", s.Addr(), "app.example.com", dns.TypeAAAA)
	if len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatalf("no v6 configured should be NODATA: %v", r)
	}
}

func TestWildcard(t *testing.T) {
	s := startServer(t, testConfig())
	for _, n := range []string{"a.wild.example.org", "x.y.wild.example.org"} {
		if r := query(t, "udp", s.Addr(), n, dns.TypeA); len(r.Answer) != 1 {
			t.Errorf("%s should be hosted", n)
		}
	}
	for _, n := range []string{"wild.example.org", "example.org", "evil.com", "foo.com", "anything.net", "wild.example.org.evil.com"} {
		if r := query(t, "udp", s.Addr(), n, dns.TypeA); r.Rcode != dns.RcodeRefused {
			t.Errorf("%s should be refused (catch-all wildcards must be ignored), got %d", n, r.Rcode)
		}
	}
	//IP-literal "hosts" are not DNS names
	if r := query(t, "udp", s.Addr(), "10.0.0.1", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Logf("ip literal rcode %d", r.Rcode)
	}
}

func TestRefusals(t *testing.T) {
	s := startServer(t, testConfig())
	r := query(t, "udp", s.Addr(), "google.com", dns.TypeA)
	if r.Rcode != dns.RcodeRefused || r.RecursionAvailable || len(r.Answer) != 0 {
		t.Fatalf("non-hosted must be refused: %v", r)
	}
	if r := query(t, "udp", s.Addr(), "app.example.com", dns.TypeANY); r.Rcode != dns.RcodeRefused {
		t.Fatal("ANY must be refused")
	}
	if r := query(t, "tcp", s.Addr(), "app.example.com", dns.TypeAXFR); r.Rcode != dns.RcodeRefused {
		t.Fatal("AXFR must be refused")
	}
	//CHAOS class (version.bind)
	m := new(dns.Msg)
	m.SetQuestion("version.bind.", dns.TypeTXT)
	m.Question[0].Qclass = dns.ClassCHAOS
	r, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, s.Addr())
	if err != nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("chaos: %v %v", r, err)
	}
	//Unsupported opcode
	m = new(dns.Msg)
	m.SetQuestion("app.example.com.", dns.TypeA)
	m.Opcode = dns.OpcodeNotify
	r, _, err = (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, s.Addr())
	if err != nil || r.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("notify: %v %v", r, err)
	}
	st := s.Stats()
	if st.Refused < 3 || st.Answered != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// fakeUpstream answers every A query with 9.9.9.9 and "big.*" TXT queries with a large answer
func fakeUpstream(t *testing.T) (string, func() int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan struct{}, 1000)
	ready := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		hits <- struct{}{}
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if strings.HasPrefix(q.Name, "big.") {
			for i := 0; i < 40; i++ {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{strings.Repeat("x", 50)}})
			}
		} else {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("9.9.9.9")})
		}
		if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
			m.Truncate(dns.MinMsgSize)
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	<-ready
	t.Cleanup(func() { srv.Shutdown() })
	//same handler over TCP on the same port
	if ln, err := net.Listen("tcp", pc.LocalAddr().String()); err == nil {
		tcp := &dns.Server{Listener: ln, Handler: srv.Handler}
		go tcp.ActivateAndServe()
		t.Cleanup(func() { tcp.Shutdown() })
	}
	return pc.LocalAddr().String(), func() int { return len(hits) }
}

func TestForwarding(t *testing.T) {
	up, hits := fakeUpstream(t)

	//Allowed client (127.0.0.1 inside 127.0.0.0/8)
	c := testConfig()
	c.ForwardEnabled = true
	c.Upstreams = []string{up}
	c.AllowedCIDRs = []string{"127.0.0.0/8"}
	s := startServer(t, c)
	r := query(t, "udp", s.Addr(), "forwarded.test", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "9.9.9.9" || !r.RecursionAvailable {
		t.Fatalf("forward allowed: %v", r)
	}
	//hosted names are still answered locally, never forwarded
	before := hits()
	if r := query(t, "udp", s.Addr(), "app.example.com", dns.TypeA); r.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatal("hosted name must not be forwarded")
	}
	if hits() != before {
		t.Fatal("upstream was contacted for a hosted name")
	}
	//RD not set: refused (no cache snooping)
	m := new(dns.Msg)
	m.SetQuestion("forwarded.test.", dns.TypeA)
	m.RecursionDesired = false
	r, _, _ = (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, s.Addr())
	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("RD=0 must be refused, got %d", r.Rcode)
	}
	if s.Stats().Forwarded != 1 {
		t.Fatalf("stats %+v", s.Stats())
	}

	//Client outside the allowed CIDRs
	c.AllowedCIDRs = []string{"10.0.0.0/8"}
	s2 := startServer(t, c)
	h := hits()
	if r := query(t, "udp", s2.Addr(), "forwarded.test", dns.TypeA); r.Rcode != dns.RcodeRefused || r.RecursionAvailable {
		t.Fatalf("forward denied by CIDR: %v", r)
	}
	if hits() != h {
		t.Fatal("denied client reached the upstream")
	}

	//Forwarding disabled although upstreams and CIDRs are set
	c.AllowedCIDRs = []string{"127.0.0.0/8"}
	c.ForwardEnabled = false
	s3 := startServer(t, c)
	if r := query(t, "tcp", s3.Addr(), "forwarded.test", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Fatal("forwarding off must refuse")
	}
}

func TestForwardUnreachableUpstreamIsServfail(t *testing.T) {
	c := testConfig()
	c.ForwardEnabled = true
	c.Upstreams = []string{"127.0.0.1:9"}
	c.AllowedCIDRs = []string{"127.0.0.0/8"}
	s, err := newServer(c, func() []string { return testNames() }, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	s.exchange = func(*dns.Msg, string) (*dns.Msg, error) { return nil, net.ErrClosed }
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	if r := query(t, "udp", s.Addr(), "x.test", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("got %d", r.Rcode)
	}
}

func TestUDPResponseSizeLimit(t *testing.T) {
	up, _ := fakeUpstream(t)
	c := testConfig()
	c.ForwardEnabled = true
	c.Upstreams = []string{up}
	c.AllowedCIDRs = []string{"127.0.0.0/8"}
	c.MaxUDPSize = 512
	s := startServer(t, c)
	m := new(dns.Msg)
	m.SetQuestion("big.test.", dns.TypeTXT)
	m.SetEdns0(4096, false) //client offers a large buffer, the server cap still wins
	wire, _ := m.Pack()
	conn, err := net.Dial("udp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(wire)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || n > 512 {
		t.Fatalf("expected truncated <=512 bytes, tc=%v wire=%d", r.Truncated, n)
	}
	//over TCP the full answer is returned
	r = query(t, "tcp", s.Addr(), "big.test", dns.TypeTXT)
	if r.Truncated || len(r.Answer) != 40 {
		t.Fatalf("tcp: tc=%v answers=%d", r.Truncated, len(r.Answer))
	}
}

func TestRateLimitPerClient(t *testing.T) {
	c := testConfig()
	c.RateLimitQPS = 0.5
	c.RateBurst = 3
	s := startServer(t, c)
	ok, dropped := 0, 0
	for i := 0; i < 10; i++ {
		m := new(dns.Msg)
		m.SetQuestion("app.example.com.", dns.TypeA)
		_, _, err := (&dns.Client{Timeout: 150 * time.Millisecond}).Exchange(m, s.Addr())
		if err == nil {
			ok++
		} else {
			dropped++
		}
	}
	if ok < 3 || ok > 5 || dropped < 5 {
		t.Fatalf("ok=%d dropped=%d", ok, dropped)
	}
	if s.Stats().RateLimited < 5 {
		t.Fatalf("stats %+v", s.Stats())
	}
}

func TestLimiterRefillAndIPv6Grouping(t *testing.T) {
	l := newLimiter(1, 2)
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	ip := netip.MustParseAddr("192.0.2.1")
	if !l.Allow(ip) || !l.Allow(ip) || l.Allow(ip) {
		t.Fatal("burst of 2 expected")
	}
	if l.Allow(netip.MustParseAddr("192.0.2.2")) != true {
		t.Fatal("other client has its own bucket")
	}
	now = now.Add(1500 * time.Millisecond)
	if !l.Allow(ip) || l.Allow(ip) {
		t.Fatal("expected one refilled token")
	}
	a, b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::ffff")
	l.Allow(a)
	l.Allow(a)
	if l.Allow(b) {
		t.Fatal("same /64 must share a bucket")
	}
	if !l.Allow(netip.MustParseAddr("2001:db8:0:1::1")) {
		t.Fatal("different /64 must not")
	}
	//sweep frees idle buckets
	now = now.Add(time.Hour)
	l.sweep(now)
	if len(l.m) != 0 {
		t.Fatalf("sweep left %d buckets", len(l.m))
	}
}

func TestMalformedPackets(t *testing.T) {
	s := startServer(t, testConfig())
	conn, err := net.Dial("udp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payloads := [][]byte{
		{},
		{0x00},
		{0x12, 0x34},
		make([]byte, 12), //empty header, zero questions
		{0x12, 0x34, 0x01, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, //claims 5 questions, truncated
		{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x3f, 'a'},  //label overruns
		[]byte(strings.Repeat("\xff", 600)),
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}, //a response packet
	}
	for _, p := range payloads {
		conn.Write(p)
	}
	time.Sleep(100 * time.Millisecond)
	//server still healthy
	if r := query(t, "udp", s.Addr(), "app.example.com", dns.TypeA); len(r.Answer) != 1 {
		t.Fatal("server unhealthy after malformed packets")
	}
	//garbage over TCP then a valid query on a new connection
	tc, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte{0xff, 0xff, 1, 2, 3})
	tc.Close()
	tc, _ = net.Dial("tcp", s.Addr())
	tc.Write([]byte{0x00, 0x05, 1, 2, 3, 4, 5})
	tc.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 512)
	tc.Read(buf)
	tc.Close()
	if r := query(t, "tcp", s.Addr(), "app.example.com", dns.TypeA); len(r.Answer) != 1 {
		t.Fatal("tcp unhealthy after malformed packets")
	}
	//multiple questions -> FORMERR
	m := new(dns.Msg)
	m.SetQuestion("app.example.com.", dns.TypeA)
	m.Question = append(m.Question, dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	r, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, s.Addr())
	if err != nil || r.Rcode != dns.RcodeFormatError {
		t.Fatalf("multi question: %v %v", r, err)
	}
}

func TestTCPConnectionCapAndIdleTimeout(t *testing.T) {
	c := testConfig()
	c.MaxTCPConns = 1
	c.TCPTimeoutSec = 1
	s := startServer(t, c)
	first, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	time.Sleep(100 * time.Millisecond)
	second, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("second connection should have been closed by the cap")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("second connection was kept open")
	}
	//the idle first connection is reaped by the timeout, freeing the slot
	first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected idle connection to be closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle connection was not closed by server timeout")
	}
	time.Sleep(100 * time.Millisecond)
	if r := query(t, "tcp", s.Addr(), "app.example.com", dns.TypeA); len(r.Answer) != 1 {
		t.Fatal("slot not released")
	}
}

func TestConfigValidation(t *testing.T) {
	ok := func() Config { c := DefaultConfig(); c.Enabled = true; c.ListenAddr = "127.0.0.1:5353"; return c }
	mod := func(f func(*Config)) Config { c := ok(); f(&c); c.Normalize(); return c }
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"default disabled", DefaultConfig(), true},
		{"basic", ok(), true},
		{"enabled without addr", mod(func(c *Config) { c.ListenAddr = "" }), false},
		{"host only gets default port", mod(func(c *Config) { c.ListenAddr = "192.168.1.2" }), true},
		{"v6 literal", mod(func(c *Config) { c.ListenAddr = "::1" }), true},
		{"hostname", mod(func(c *Config) { c.ListenAddr = "localhost:5353" }), false},
		{"empty host", mod(func(c *Config) { c.ListenAddr = ":5353" }), false},
		{"0.0.0.0 unconfirmed", mod(func(c *Config) { c.ListenAddr = "0.0.0.0:5353" }), false},
		{"0.0.0.0 confirmed", mod(func(c *Config) { c.ListenAddr = "0.0.0.0:5353"; c.AllowAllInterfaces = true }), true},
		{":: unconfirmed", mod(func(c *Config) { c.ListenAddr = "[::]:5353" }), false},
		{"empty host confirmed", mod(func(c *Config) { c.ListenAddr = ":5353"; c.AllowAllInterfaces = true }), true},
		{"port 0", mod(func(c *Config) { c.ListenAddr = "127.0.0.1:0" }), false},
		{"port too big", mod(func(c *Config) { c.ListenAddr = "127.0.0.1:70000" }), false},
		{"bad v4 answer", mod(func(c *Config) { c.IPv4 = "nope" }), false},
		{"v6 in v4 field", mod(func(c *Config) { c.IPv4 = "::1" }), false},
		{"v4 in v6 field", mod(func(c *Config) { c.IPv6 = "1.2.3.4" }), false},
		{"forward without upstream", mod(func(c *Config) { c.ForwardEnabled = true; c.AllowedCIDRs = []string{"10.0.0.0/8"} }), false},
		{"forward without cidr", mod(func(c *Config) { c.ForwardEnabled = true; c.Upstreams = []string{"1.1.1.1"} }), false},
		{"forward ok", mod(func(c *Config) {
			c.ForwardEnabled = true
			c.Upstreams = []string{"1.1.1.1", "[2606:4700:4700::1111]:53"}
			c.AllowedCIDRs = []string{"192.168.0.0/16", "fd00::/8"}
		}), true},
		{"forward cidr /0", mod(func(c *Config) {
			c.ForwardEnabled = true
			c.Upstreams = []string{"1.1.1.1"}
			c.AllowedCIDRs = []string{"0.0.0.0/0"}
		}), false},
		{"forward bad cidr", mod(func(c *Config) {
			c.ForwardEnabled = true
			c.Upstreams = []string{"1.1.1.1"}
			c.AllowedCIDRs = []string{"10.0.0.0"}
		}), false},
		{"hostname upstream", mod(func(c *Config) {
			c.ForwardEnabled = true
			c.Upstreams = []string{"dns.google"}
			c.AllowedCIDRs = []string{"10.0.0.0/8"}
		}), false},
		{"upstream is self", mod(func(c *Config) {
			c.ForwardEnabled = true
			c.Upstreams = []string{"127.0.0.1:5353"}
			c.AllowedCIDRs = []string{"10.0.0.0/8"}
		}), false},
		{"udp size small", mod(func(c *Config) { c.MaxUDPSize = 100 }), false},
		{"udp size big", mod(func(c *Config) { c.MaxUDPSize = 65000 }), false},
		{"negative rate", mod(func(c *Config) { c.RateLimitQPS = -1 }), false},
		{"tcp conns huge", mod(func(c *Config) { c.MaxTCPConns = 100000 }), false},
		{"ttl huge", mod(func(c *Config) { c.TTL = 999999 }), false},
	}
	for _, c := range cases {
		err := c.cfg.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v err=%v", c.name, c.ok, err)
		}
	}
	c := mod(func(c *Config) { c.ListenAddr = "192.168.1.2" })
	if c.ListenAddr != "192.168.1.2:5353" {
		t.Errorf("default port: %s", c.ListenAddr)
	}
	if DefaultConfig().Enabled {
		t.Error("must be disabled by default")
	}
}

func TestMatchName(t *testing.T) {
	cases := []struct {
		p, n string
		want bool
	}{
		{"app.example.com", "app.example.com", true},
		{"App.Example.com.", "app.example.com", true},
		{"app.example.com", "x.app.example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*", "anything.com", false},
		{"*.com", "a.com", false},
		{"*.*", "a.com", false},
		{"web-*.example.com", "web-1.example.com", true},
		{"", "", false},
		{"bad[pattern.example.com", "x", false},
		{"a b.example.com", "a b.example.com", false},
		{"a/b.example.com", "a/b.example.com", false},
	}
	for _, c := range cases {
		if got := matchName(c.p, c.n); got != c.want {
			t.Errorf("matchName(%q,%q)=%v", c.p, c.n, got)
		}
	}
}

func TestManagerApplyAndAPI(t *testing.T) {
	var saved Config
	m := NewManager(DefaultConfig(), func() []string { return testNames() }, func(c Config) error { saved = c; return nil }, nil)
	defer m.Stop()
	if m.Status().Running {
		t.Fatal("must be off by default")
	}

	//Apply via API; use a fixed free port
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ListenAddr = net.JoinHostPort("127.0.0.1", itoa(port))
	js, _ := json.Marshal(cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/tools/dnsresponder", strings.NewReader(url.Values{"config": {string(js)}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	m.HandleAPI(w, req)
	if strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	if !m.Status().Running || saved.ListenAddr != cfg.ListenAddr {
		t.Fatalf("not applied: %+v %+v", m.Status(), saved)
	}
	if r := query(t, "udp", cfg.ListenAddr, "app.example.com", dns.TypeA); len(r.Answer) != 1 {
		t.Fatal("manager server does not answer")
	}

	//GET
	w = httptest.NewRecorder()
	m.HandleAPI(w, httptest.NewRequest(http.MethodGet, "/api/tools/dnsresponder", nil))
	var got struct {
		Config Config
		Status Status
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !got.Status.Running || got.Config.ListenAddr != cfg.ListenAddr {
		t.Fatalf("%v %s", err, w.Body.String())
	}

	//invalid config is rejected and the running server is kept
	bad := cfg
	bad.ListenAddr = "0.0.0.0:5353"
	js, _ = json.Marshal(bad)
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(url.Values{"config": {string(js)}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	m.HandleAPI(w, req)
	if !strings.Contains(w.Body.String(), "error") || !m.Status().Running || m.Config().ListenAddr != cfg.ListenAddr {
		t.Fatalf("bad config must be rejected: %s", w.Body.String())
	}

	//a bind failure restores the previous server
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	bad.ListenAddr = busy.Addr().String()
	if err := m.Apply(bad); err == nil {
		t.Fatal("bind to a busy port must fail")
	}
	if !m.Status().Running {
		t.Fatal("previous server should be restored")
	}

	//disable
	cfg.Enabled = false
	if err := m.Apply(cfg); err != nil || m.Status().Running {
		t.Fatal("disable failed")
	}

	//garbage / wrong method
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("config=notjson"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	m.HandleAPI(w, req)
	if !strings.Contains(w.Body.String(), "error") {
		t.Fatal("expected error")
	}
	w = httptest.NewRecorder()
	m.HandleAPI(w, httptest.NewRequest(http.MethodDelete, "/x", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal(w.Code)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
