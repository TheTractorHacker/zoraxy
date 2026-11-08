package netutils

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	diagnostics.go

	Admin-only network diagnostics: DNS lookup, TLS certificate inspector and HTTP request tester
	(redirect chain and timing). Routes: /api/tools/dns, /api/tools/tlsinspect, /api/tools/httptest.

	These tools make Zoraxy connect to a host the admin names, which is a server side request
	forgery primitive by design. They are behind the admin login, and in addition connections to cloud
	metadata services (169.254.0.0/16 link-local incl. 169.254.169.254 and 168.63.129.16 of Azure, the
	AWS IPv6 endpoint fd00:ec2::254, Alibaba 100.100.100.200) are refused by default. The check runs on the
	IP address that is actually connected to (dialer Control hook), so DNS rebinding and redirects to
	such addresses are caught as well. The request parameter allowmetadata=true switches the guard off for
	one call. Private LAN addresses stay reachable: testing internal upstreams is the point of the tool.
*/

var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),   //link-local, AWS / GCP / Azure / OpenStack IMDS
	netip.MustParsePrefix("168.63.129.16/32"), //Azure wire server
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("fd00:ec2::/32"), //AWS IMDS over IPv6
	netip.MustParsePrefix("fe80::/10"),     //IPv6 link-local
}

// IsMetadataAddress reports whether ip is in a cloud metadata / link-local range
func IsMetadataAddress(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	for _, p := range metadataPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var errMetadataBlocked = errors.New("target is a cloud metadata / link-local address, blocked by default (set allowmetadata=true to override)")

// guardedDialer refuses to connect to metadata addresses unless allowed
func guardedDialer(allowMetadata bool) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !allowMetadata {
		d.Control = func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if IsMetadataAddress(ip) {
				return errMetadataBlocked
			}
			return nil
		}
	}
	return d
}

func checkDiagHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\@?#\t\r\n") {
		return "", errors.New("invalid host name")
	}
	return strings.TrimSuffix(host, "."), nil
}

/* DNS lookup */

type DNSResult struct {
	Host    string
	Type    string
	Records []string
	Error   string `json:",omitempty"`
}

// DNSLookup resolves the record types (A, AAAA, CNAME, MX, TXT, NS) of host. server is an optional "ip[:port]" DNS server.
func DNSLookup(ctx context.Context, host string, types []string, server string) ([]DNSResult, error) {
	host, err := checkDiagHost(host)
	if err != nil {
		return nil, err
	}
	resolver := net.DefaultResolver
	if server = strings.TrimSpace(server); server != "" {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		h, _, _ := net.SplitHostPort(server)
		if _, err := netip.ParseAddr(h); err != nil {
			return nil, errors.New("DNS server must be an IP address")
		}
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, server)
		}}
	}
	if len(types) == 0 {
		types = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var out []DNSResult
	for _, t := range types {
		t = strings.ToUpper(strings.TrimSpace(t))
		res := DNSResult{Host: host, Type: t, Records: []string{}}
		switch t {
		case "A", "AAAA":
			network := "ip4"
			if t == "AAAA" {
				network = "ip6"
			}
			ips, err := resolver.LookupIP(ctx, network, host)
			for _, ip := range ips {
				res.Records = append(res.Records, ip.String())
			}
			if err != nil {
				res.Error = dnsErrString(err)
			}
		case "CNAME":
			cname, err := resolver.LookupCNAME(ctx, host)
			if err != nil {
				res.Error = dnsErrString(err)
			} else if strings.TrimSuffix(cname, ".") != host {
				res.Records = append(res.Records, cname)
			}
		case "MX":
			mx, err := resolver.LookupMX(ctx, host)
			for _, m := range mx {
				res.Records = append(res.Records, fmt.Sprintf("%d %s", m.Pref, m.Host))
			}
			if err != nil {
				res.Error = dnsErrString(err)
			}
		case "TXT":
			txt, err := resolver.LookupTXT(ctx, host)
			res.Records = append(res.Records, txt...)
			if err != nil {
				res.Error = dnsErrString(err)
			}
		case "NS":
			ns, err := resolver.LookupNS(ctx, host)
			for _, n := range ns {
				res.Records = append(res.Records, n.Host)
			}
			if err != nil {
				res.Error = dnsErrString(err)
			}
		default:
			return nil, errors.New("unsupported record type " + t)
		}
		if len(res.Records) > 0 {
			res.Error = "" //a partial answer is not an error worth showing
		}
		out = append(out, res)
	}
	return out, nil
}

func dnsErrString(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsNotFound {
			return "no records"
		}
		if de.IsTimeout {
			return "timeout"
		}
		return de.Err
	}
	return err.Error()
}

/* TLS certificate inspector */

type CertInfo struct {
	Subject      string
	Issuer       string
	NotBefore    string
	NotAfter     string
	DaysLeft     int
	DNSNames     []string
	IPAddresses  []string
	SerialHex    string
	SHA256       string
	SigAlgorithm string
	IsCA         bool
	SelfSigned   bool
	KeyAlgorithm string
}

type TLSInspectResult struct {
	Target      string
	ServerName  string
	Address     string
	Version     string
	CipherSuite string
	ALPN        string
	Verified    bool
	VerifyError string `json:",omitempty"`
	HostnameOK  bool
	Chain       []CertInfo
	HandshakeMS int64
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func certInfo(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.Raw)
	info := CertInfo{
		Subject:      c.Subject.String(),
		Issuer:       c.Issuer.String(),
		NotBefore:    c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:     c.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:     int(time.Until(c.NotAfter).Hours() / 24),
		DNSNames:     c.DNSNames,
		SerialHex:    strings.ToLower(c.SerialNumber.Text(16)),
		SHA256:       hex.EncodeToString(sum[:]),
		SigAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:         c.IsCA,
		SelfSigned:   c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil,
		KeyAlgorithm: c.PublicKeyAlgorithm.String(),
	}
	for _, ip := range c.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	return info
}

// InspectTLS connects to host:port, completes a handshake without trusting the peer, and reports the
// certificate chain plus whether it verifies against the system roots for serverName (default: host).
func InspectTLS(ctx context.Context, host string, port int, serverName string, allowMetadata bool) (*TLSInspectResult, error) {
	host, err := checkDiagHost(host)
	if err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	if serverName = strings.TrimSpace(serverName); serverName == "" {
		serverName = host
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	raw, err := guardedDialer(allowMetadata).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))

	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, NextProtos: []string{"h2", "http/1.1"}}
	if net.ParseIP(serverName) != nil {
		cfg.ServerName = ""
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	res := &TLSInspectResult{
		Target:      addr,
		ServerName:  serverName,
		Address:     raw.RemoteAddr().String(),
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
		HandshakeMS: time.Since(start).Milliseconds(),
	}
	for _, c := range state.PeerCertificates {
		res.Chain = append(res.Chain, certInfo(c))
	}
	if len(state.PeerCertificates) > 0 {
		inter := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		leaf := state.PeerCertificates[0]
		_, verr := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Intermediates: inter})
		res.Verified = verr == nil
		if verr != nil {
			res.VerifyError = verr.Error()
		}
		res.HostnameOK = leaf.VerifyHostname(serverName) == nil
	}
	return res, nil
}

/* HTTP request tester */

type HTTPHop struct {
	URL        string
	Status     int
	Proto      string
	Location   string `json:",omitempty"`
	Server     string `json:",omitempty"`
	RemoteAddr string
	Headers    map[string][]string
	DNSMS      int64
	ConnectMS  int64
	TLSMS      int64
	TTFBMS     int64
	TotalMS    int64
	TLSVersion string `json:",omitempty"`
	Error      string `json:",omitempty"`
}

type HTTPTestResult struct {
	Hops    []HTTPHop
	Final   int
	TotalMS int64
}

// HTTPTest requests rawURL and follows up to maxRedirects redirects manually so every hop is reported with its timing.
func HTTPTest(ctx context.Context, rawURL, method string, followRedirects bool, skipTLSVerify bool, allowMetadata bool) (*HTTPTestResult, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("URL must start with http:// or https://")
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case "":
		method = http.MethodGet
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return nil, errors.New("only GET, HEAD and OPTIONS are allowed")
	}
	const maxRedirects = 10
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	transport := &http.Transport{
		DialContext:         guardedDialer(allowMetadata).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: skipTLSVerify},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		Proxy:               nil,
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()

	res := &HTTPTestResult{}
	started := time.Now()
	for hop := 0; hop <= maxRedirects; hop++ {
		h := HTTPHop{URL: u.String()}
		var dnsStart, connStart, tlsStart, begin time.Time
		begin = time.Now()
		trace := &httptrace.ClientTrace{
			DNSStart:     func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
			DNSDone:      func(httptrace.DNSDoneInfo) { h.DNSMS = time.Since(dnsStart).Milliseconds() },
			ConnectStart: func(string, string) { connStart = time.Now() },
			ConnectDone: func(_, addr string, err error) {
				h.ConnectMS = time.Since(connStart).Milliseconds()
				h.RemoteAddr = addr
			},
			TLSHandshakeStart: func() { tlsStart = time.Now() },
			TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
				h.TLSMS = time.Since(tlsStart).Milliseconds()
				if err == nil {
					h.TLSVersion = tlsVersionName(cs.Version)
				}
			},
			GotFirstResponseByte: func() { h.TTFBMS = time.Since(begin).Milliseconds() },
		}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Zoraxy-HTTPTest")
		resp, err := client.Do(req)
		if err != nil {
			h.Error = err.Error()
			h.TotalMS = time.Since(begin).Milliseconds()
			res.Hops = append(res.Hops, h)
			break
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		h.Status = resp.StatusCode
		h.Proto = resp.Proto
		h.Server = resp.Header.Get("Server")
		h.Headers = resp.Header
		h.TotalMS = time.Since(begin).Milliseconds()
		res.Final = resp.StatusCode
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			h.Location = loc
		}
		res.Hops = append(res.Hops, h)
		if h.Location == "" || !followRedirects {
			break
		}
		next, err := u.Parse(h.Location)
		if err != nil || (next.Scheme != "http" && next.Scheme != "https") {
			res.Hops[len(res.Hops)-1].Error = "redirect to unsupported location"
			break
		}
		u = next
		if hop == maxRedirects {
			res.Hops[len(res.Hops)-1].Error = "too many redirects"
		}
	}
	res.TotalMS = time.Since(started).Milliseconds()
	return res, nil
}

/* HTTP handlers */

func diagParam(r *http.Request, key string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	if r.Method == http.MethodPost {
		v, _ := utils.PostPara(r, key)
		return v
	}
	return ""
}

func diagBool(r *http.Request, key string) bool {
	v := strings.ToLower(diagParam(r, key))
	return v == "true" || v == "1" || v == "on"
}

func sendJSON(w http.ResponseWriter, v interface{}) {
	js, _ := json.Marshal(v)
	utils.SendJSONResponse(w, string(js))
}

// HandleDNSLookup GET host, types (comma separated, optional), server (optional DNS server IP)
func HandleDNSLookup(w http.ResponseWriter, r *http.Request) {
	var types []string
	if t := diagParam(r, "types"); t != "" {
		types = strings.Split(t, ",")
	}
	res, err := DNSLookup(r.Context(), diagParam(r, "host"), types, diagParam(r, "server"))
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	sendJSON(w, res)
}

// HandleTLSInspect GET host, port (default 443), sni (optional), allowmetadata
func HandleTLSInspect(w http.ResponseWriter, r *http.Request) {
	port := 443
	if p := diagParam(r, "port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			utils.SendErrorResponse(w, "invalid port")
			return
		}
		port = n
	}
	res, err := InspectTLS(r.Context(), diagParam(r, "host"), port, diagParam(r, "sni"), diagBool(r, "allowmetadata"))
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	sendJSON(w, res)
}

// HandleHTTPTest GET url, method, follow (bool), skipverify (bool), allowmetadata (bool)
func HandleHTTPTest(w http.ResponseWriter, r *http.Request) {
	res, err := HTTPTest(r.Context(), diagParam(r, "url"), diagParam(r, "method"), diagBool(r, "follow"), diagBool(r, "skipverify"), diagBool(r, "allowmetadata"))
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	sendJSON(w, res)
}
