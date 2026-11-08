package dnsresponder

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// NameSource returns the hostname patterns that are hosted (exact names, or
// wildcard patterns such as "*.example.com"). Called on every query, keep it cheap.
type NameSource func() []string

// Stats are monotonic counters
type Stats struct {
	Queries     uint64 `json:"queries"`
	Answered    uint64 `json:"answered"`
	Refused     uint64 `json:"refused"`
	Forwarded   uint64 `json:"forwarded"`
	RateLimited uint64 `json:"rateLimited"`
}

// Server is one running UDP+TCP responder instance
type Server struct {
	cfg   Config
	names NameSource
	logf  func(msg string, err error)

	v4, v6    netip.Addr
	allowed   []netip.Prefix
	upstreams []string
	limiter   *limiter
	serial    uint32

	//exchange sends a query to an upstream (overridable in tests)
	exchange func(m *dns.Msg, upstream string) (*dns.Msg, error)

	ephemeral bool
	mu        sync.Mutex
	addr      string
	udpSrv    *dns.Server
	tcpSrv    *dns.Server
	running   bool

	queries, answered, refused, forwarded, rateLimited atomic.Uint64
}

// NewServer validates the configuration and prepares a (not yet started) server
func NewServer(cfg Config, names NameSource, logf func(string, error)) (*Server, error) {
	return newServer(cfg, names, logf, false)
}

func newServer(cfg Config, names NameSource, logf func(string, error), ephemeral bool) (*Server, error) {
	cfg.Normalize()
	if err := cfg.validate(ephemeral); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, error) {}
	}
	s := &Server{cfg: cfg, names: names, logf: logf, ephemeral: ephemeral,
		limiter: newLimiter(cfg.RateLimitQPS, cfg.RateBurst), serial: uint32(time.Now().Unix())}

	host, _, wildcard, _ := ParseListenAddr(cfg.ListenAddr)
	if a, err := netip.ParseAddr(cfg.IPv4); err == nil {
		s.v4 = a.Unmap()
	} else if la, err := netip.ParseAddr(host); err == nil && !wildcard && la.Unmap().Is4() {
		s.v4 = la.Unmap()
	}
	if a, err := netip.ParseAddr(cfg.IPv6); err == nil {
		s.v6 = a
	} else if la, err := netip.ParseAddr(host); err == nil && !wildcard && la.Is6() && !la.Is4In6() {
		s.v6 = la
	}
	for _, c := range cfg.AllowedCIDRs {
		p, _ := netip.ParsePrefix(c)
		s.allowed = append(s.allowed, p.Masked())
	}
	for _, u := range cfg.Upstreams {
		n, _ := normalizeUpstream(u)
		s.upstreams = append(s.upstreams, n)
	}
	s.exchange = defaultExchange
	return s, nil
}

func defaultExchange(m *dns.Msg, upstream string) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second, UDPSize: 4096}
	resp, _, err := c.Exchange(m, upstream)
	if err == nil && resp != nil && resp.Truncated {
		c = &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
		resp, _, err = c.Exchange(m, upstream)
	}
	return resp, err
}

// Addr returns the bound address (valid after Start)
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Stats returns a snapshot of the counters
func (s *Server) Stats() Stats {
	return Stats{s.queries.Load(), s.answered.Load(), s.refused.Load(), s.forwarded.Load(), s.rateLimited.Load()}
}

// Start binds UDP and TCP and begins serving
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("already running")
	}
	host, port, _, _ := ParseListenAddr(s.cfg.ListenAddr)
	var ln net.Listener
	var pc net.PacketConn
	var err error
	if port == 0 {
		//Ephemeral port (tests): the same number for TCP and UDP
		for i := 0; i < 20; i++ {
			ln, err = net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				break
			}
			p := ln.Addr().(*net.TCPAddr).Port
			pc, err = net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(p)))
			if err == nil {
				break
			}
			ln.Close()
			ln = nil
		}
	} else {
		ln, err = net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			pc, err = net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				ln.Close()
			}
		}
	}
	if err != nil || ln == nil || pc == nil {
		if err == nil {
			err = errors.New("unable to bind")
		}
		return fmt.Errorf("unable to bind %s: %w", s.cfg.ListenAddr, err)
	}

	to := time.Duration(s.cfg.TCPTimeoutSec) * time.Second
	limited := newLimitListener(ln, s.cfg.MaxTCPConns)
	udpReady, tcpReady := make(chan struct{}), make(chan struct{})
	s.udpSrv = &dns.Server{PacketConn: pc, Net: "udp", Handler: s, UDPSize: 1232 + 64,
		ReadTimeout: to, WriteTimeout: to, NotifyStartedFunc: func() { close(udpReady) }}
	s.tcpSrv = &dns.Server{Listener: limited, Net: "tcp", Handler: s,
		ReadTimeout: to, WriteTimeout: to, IdleTimeout: func() time.Duration { return to },
		MaxTCPQueries: 100, NotifyStartedFunc: func() { close(tcpReady) }}
	u, t := s.udpSrv, s.tcpSrv
	go func() {
		if e := u.ActivateAndServe(); e != nil {
			s.logf("DNS responder UDP server stopped", e)
		}
	}()
	go func() {
		if e := t.ActivateAndServe(); e != nil {
			s.logf("DNS responder TCP server stopped", e)
		}
	}()
	for _, c := range []chan struct{}{udpReady, tcpReady} {
		select {
		case <-c:
		case <-time.After(3 * time.Second):
			return errors.New("DNS responder did not start in time")
		}
	}
	s.addr = ln.Addr().String()
	s.running = true
	return nil
}

// Stop shuts both listeners down
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.running = false
	if s.udpSrv != nil {
		s.udpSrv.Shutdown()
	}
	if s.tcpSrv != nil {
		s.tcpSrv.Shutdown()
	}
	s.addr = ""
}

func clientIP(a net.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		return ip.Unmap(), ok
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		return ip.Unmap(), ok
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(h)
	return ip.Unmap(), err == nil
}

// ServeDNS implements dns.Handler
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			s.logf(fmt.Sprintf("DNS responder panic: %v", rec), nil)
		}
	}()
	s.queries.Add(1)
	ip, ok := clientIP(w.RemoteAddr())
	if !ok || !s.limiter.Allow(ip) {
		s.rateLimited.Add(1)
		return //drop silently, replying would help spoofed-source floods
	}
	resp := s.handle(ip, r)
	if resp == nil {
		return
	}
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		size := dns.MinMsgSize
		if o := r.IsEdns0(); o != nil && int(o.UDPSize()) > size {
			size = int(o.UDPSize())
		}
		if size > s.cfg.MaxUDPSize {
			size = s.cfg.MaxUDPSize
		}
		resp.Truncate(size)
	}
	w.WriteMsg(resp)
}

func (s *Server) reply(r *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = false
	if o := r.IsEdns0(); o != nil {
		m.SetEdns0(uint16(s.cfg.MaxUDPSize), false)
	}
	return m
}

func (s *Server) handle(ip netip.Addr, r *dns.Msg) *dns.Msg {
	if r.Response {
		return nil
	}
	if r.Opcode != dns.OpcodeQuery {
		return s.reply(r, dns.RcodeNotImplemented)
	}
	if len(r.Question) != 1 {
		return s.reply(r, dns.RcodeFormatError)
	}
	q := r.Question[0]
	switch q.Qtype {
	case dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR:
		s.refused.Add(1)
		return s.reply(r, dns.RcodeRefused)
	}
	if q.Qclass != dns.ClassINET {
		s.refused.Add(1)
		return s.reply(r, dns.RcodeRefused)
	}
	name := strings.ToLower(dns.Fqdn(q.Name))
	if !s.hosted(strings.TrimSuffix(name, ".")) {
		return s.nonHosted(ip, r)
	}

	m := s.reply(r, dns.RcodeSuccess)
	m.Authoritative = true
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: q.Name, Rrtype: t, Class: dns.ClassINET, Ttl: s.cfg.TTL}
	}
	addrRRs := func(owner string) []dns.RR {
		var out []dns.RR
		h := func(t uint16) dns.RR_Header {
			return dns.RR_Header{Name: owner, Rrtype: t, Class: dns.ClassINET, Ttl: s.cfg.TTL}
		}
		if s.v4.IsValid() {
			out = append(out, &dns.A{Hdr: h(dns.TypeA), A: net.IP(s.v4.AsSlice())})
		}
		if s.v6.IsValid() {
			out = append(out, &dns.AAAA{Hdr: h(dns.TypeAAAA), AAAA: net.IP(s.v6.AsSlice())})
		}
		return out
	}
	switch q.Qtype {
	case dns.TypeA:
		if s.v4.IsValid() {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr(dns.TypeA), A: net.IP(s.v4.AsSlice())})
		}
	case dns.TypeAAAA:
		if s.v6.IsValid() {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: net.IP(s.v6.AsSlice())})
		}
	case dns.TypeSOA:
		m.Answer = append(m.Answer, s.soa(q.Name))
	case dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(dns.TypeNS), Ns: q.Name})
		m.Extra = append(m.Extra, addrRRs(q.Name)...)
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, s.soa(q.Name)) //NODATA: name exists, no such record type
	}
	s.answered.Add(1)
	return m
}

func (s *Server) soa(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.cfg.TTL},
		Ns:     name,
		Mbox:   "hostmaster." + name,
		Serial: s.serial, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: s.cfg.TTL,
	}
}

func (s *Server) clientAllowed(ip netip.Addr) bool {
	for _, p := range s.allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// nonHosted refuses, or forwards when explicitly enabled for this client
func (s *Server) nonHosted(ip netip.Addr, r *dns.Msg) *dns.Msg {
	if !s.cfg.ForwardEnabled || len(s.upstreams) == 0 || !s.clientAllowed(ip) || !r.RecursionDesired {
		s.refused.Add(1) //RD unset also refused: no cache snooping
		return s.reply(r, dns.RcodeRefused)
	}
	fwd := r.Copy()
	for _, up := range s.upstreams {
		resp, err := s.exchange(fwd, up)
		if err != nil || resp == nil {
			continue
		}
		resp.Id = r.Id
		resp.RecursionAvailable = true
		s.forwarded.Add(1)
		return resp
	}
	m := s.reply(r, dns.RcodeServerFailure)
	m.RecursionAvailable = true
	return m
}

func (s *Server) hosted(name string) bool {
	if name == "" || s.names == nil {
		return false
	}
	for _, p := range s.names() {
		if matchName(p, name) {
			return true
		}
	}
	return false
}

// matchName matches a hosted pattern (exact or glob like "*.example.com") against a lowercase name
func matchName(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if pattern == "" || strings.ContainsAny(pattern, "/ ") {
		return false
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == name
	}
	//A wildcard must keep a literal parent domain of two labels (no "*" or "*.com" catch-alls)
	suffix := pattern[strings.LastIndexAny(pattern, "*?]")+1:]
	if !strings.Contains(strings.TrimPrefix(suffix, "."), ".") {
		return false
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
