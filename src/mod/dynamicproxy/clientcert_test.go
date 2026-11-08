package dynamicproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

/* Tiny PKI used by the mTLS tests */

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

var testSerial int64 = 100

func nextSerial() *big.Int {
	testSerial++
	return big.NewInt(testSerial)
}

func newTestCA(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	signer, signerKey := tpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

type issueOpt struct {
	cn        string
	dns       []string
	notBefore time.Time
	notAfter  time.Time
	serial    *big.Int
	server    bool
}

func (ca *testCA) issue(t *testing.T, o issueOpt) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(time.Hour)
	}
	if o.serial == nil {
		o.serial = nextSerial()
	}
	eku := x509.ExtKeyUsageClientAuth
	if o.server {
		eku = x509.ExtKeyUsageServerAuth
	}
	tpl := &x509.Certificate{
		SerialNumber: o.serial,
		Subject:      pkix.Name{CommonName: o.cn, Organization: []string{"Zoraxy Test"}},
		DNSNames:     o.dns,
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
}

func leafOf(c tls.Certificate) *x509.Certificate {
	l, _ := x509.ParseCertificate(c.Certificate[0])
	return l
}

/* In-process TLS server driving the real shared chain */

type mtlsHarness struct {
	router  *Router
	addr    string
	rootCAs *x509.CertPool
	mu      sync.Mutex
	seen    http.Header
}

func (h *mtlsHarness) lastHeaders() http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.seen
}

func newMTLSHarness(t *testing.T, endpoints ...*ProxyEndpoint) *mtlsHarness {
	t.Helper()
	router, _, _ := newNonTLSTestRouter(t)
	h := &mtlsHarness{router: router}
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
		h.mu.Lock()
		h.seen = r.Header.Clone()
		h.mu.Unlock()
		w.WriteHeader(299)
		return true
	}
	for _, ep := range endpoints {
		ep.parent = router
		if ep.AuthenticationProvider == nil {
			ep.AuthenticationProvider = &AuthenticationProvider{}
		}
		ep.initNetworkOptions()
		router.ProxyEndpoints.Store(strings.ToLower(ep.RootOrMatchingDomain), ep)
	}

	serverCA := newTestCA(t, "server root", nil)
	serverCert := serverCA.issue(t, issueOpt{cn: "zoraxy test", dns: []string{"open.test", "mtls.test", "mtls-b.test", "plain.test", "*.test"}, server: true})
	h.rootCAs = x509.NewCertPool()
	h.rootCAs.AddCert(serverCA.cert)

	base := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
	}
	base.GetConfigForClient = router.clientCertGetConfig(base)

	srv := &http.Server{
		TLSConfig: base,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domainOnly := r.Host
			if strings.Contains(domainOnly, ":") {
				domainOnly = strings.Split(domainOnly, ":")[0]
			}
			sep := router.GetProxyEndpointFromHostname(domainOnly)
			if sep == nil {
				w.WriteHeader(404)
				return
			}
			router.handleNonTLSRequest(w, r, sep)
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	h.addr = ln.Addr().String()
	return h
}

// request performs a GET. sni is the TLS server name, host the HTTP Host header ("" = sni)
func (h *mtlsHarness) request(t *testing.T, sni, host string, cert *tls.Certificate, hdr map[string]string) (int, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: h.rootCAs, ServerName: sni, MinVersion: tls.VersionTLS12}
	if cert != nil {
		c := *cert
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil } //always offer it, even if the CA hint does not match
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DisableKeepAlives: true,
			Dial: func(network, _ string) (net.Conn, error) {
				return net.Dial(network, h.addr)
			},
		},
	}
	if host == "" {
		host = sni
	}
	req, _ := http.NewRequest("GET", "https://"+sni+"/", nil)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func fingerprintOf(c tls.Certificate) string { return certFingerprint(leafOf(c)) }

func TestClientCert_Handshake(t *testing.T) {
	ca := newTestCA(t, "client root", nil)
	otherCA := newTestCA(t, "other root", nil)
	inter := newTestCA(t, "client intermediate", ca)

	good := ca.issue(t, issueOpt{cn: "alice", dns: []string{"alice.example.org"}})
	good2 := ca.issue(t, issueOpt{cn: "bob"})
	expired := ca.issue(t, issueOpt{cn: "old", notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-24 * time.Hour)})
	wrongCA := otherCA.issue(t, issueOpt{cn: "alice"})
	viaInter := inter.issue(t, issueOpt{cn: "carol"})
	//intermediate chain: leaf, intermediate (root is in the server pool only)
	viaInter.Certificate = [][]byte{viaInter.Certificate[0], inter.cert.Raw}
	revokedSerial := big.NewInt(424242)
	revoked := ca.issue(t, issueOpt{cn: "mallory", serial: revokedSerial})

	h := newMTLSHarness(t,
		&ProxyEndpoint{RootOrMatchingDomain: "open.test"},
		&ProxyEndpoint{RootOrMatchingDomain: "mtls.test", ClientCert: &ClientCertConfig{
			Mode: ClientCertModeRequireAndVerify, CAPEM: ca.pem,
			BlockList: []string{"serial:" + revokedSerial.Text(16)},
		}},
		&ProxyEndpoint{RootOrMatchingDomain: "mtls-b.test", ClientCert: &ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: otherCA.pem}},
		&ProxyEndpoint{RootOrMatchingDomain: "plain.test", ClientCert: &ClientCertConfig{Mode: ClientCertModeRequest, CAPEM: ca.pem}},
	)

	type tc struct {
		name     string
		sni      string
		host     string
		cert     *tls.Certificate
		wantErr  bool
		wantCode int
	}
	cases := []tc{
		{"no mTLS endpoint needs no certificate", "open.test", "", nil, false, 299},
		{"no mTLS endpoint ignores a certificate", "open.test", "", &good, false, 299},
		{"required, none presented", "mtls.test", "", nil, true, 0},
		{"required, valid", "mtls.test", "", &good, false, 299},
		{"required, valid via intermediate", "mtls.test", "", &viaInter, false, 299},
		{"required, expired", "mtls.test", "", &expired, true, 0},
		{"required, wrong CA", "mtls.test", "", &wrongCA, true, 0},
		{"required, blocked serial (manual revocation)", "mtls.test", "", &revoked, false, 403},
		{"SNI of open site, Host of mTLS site (fronting)", "open.test", "mtls.test", nil, false, 403},
		{"SNI of open site, Host with port of mTLS site", "open.test", "mtls.test:443", nil, false, 403},
		{"SNI of mTLS site A, Host of mTLS site B (cert from CA A)", "mtls.test", "mtls-b.test", &good, false, 403},
		{"request mode, none presented", "plain.test", "", nil, false, 299},
		{"request mode, valid", "plain.test", "", &good, false, 299},
		{"request mode, wrong CA", "plain.test", "", &wrongCA, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, err := h.request(t, c.sni, c.host, c.cert, nil)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected a TLS failure, got status %d", code)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != c.wantCode {
				t.Fatalf("status = %d, want %d", code, c.wantCode)
			}
		})
	}

	t.Run("identity headers are set from the verified certificate", func(t *testing.T) {
		code, err := h.request(t, "mtls.test", "", &good, map[string]string{
			"X-Client-Cert-Subject": "CN=admin", "X-Client-Cert-Fingerprint": "00", "x-client-cert-serial": "1", "X-Client-Cert-Verified": "no",
		})
		if err != nil || code != 299 {
			t.Fatalf("code=%d err=%v", code, err)
		}
		hd := h.lastHeaders()
		if !strings.Contains(hd.Get(HeaderClientCertSubject), "CN=alice") || strings.Contains(hd.Get(HeaderClientCertSubject), "admin") {
			t.Errorf("subject header = %q", hd.Get(HeaderClientCertSubject))
		}
		if hd.Get(HeaderClientCertFingerprint) != fingerprintOf(good) {
			t.Errorf("fingerprint header = %q", hd.Get(HeaderClientCertFingerprint))
		}
		if hd.Get(HeaderClientCertSerial) != certSerialHex(leafOf(good)) {
			t.Errorf("serial header = %q", hd.Get(HeaderClientCertSerial))
		}
		if hd.Get(HeaderClientCertVerified) != "true" {
			t.Errorf("verified header = %q", hd.Get(HeaderClientCertVerified))
		}
	})

	t.Run("spoofed identity headers are stripped when no certificate is presented", func(t *testing.T) {
		code, err := h.request(t, "plain.test", "", nil, map[string]string{"X-Client-Cert-Subject": "CN=admin", "X-Client-Cert-Verified": "true"})
		if err != nil || code != 299 {
			t.Fatalf("code=%d err=%v", code, err)
		}
		hd := h.lastHeaders()
		if hd.Get(HeaderClientCertSubject) != "" || hd.Get(HeaderClientCertVerified) != "" {
			t.Errorf("client supplied identity headers reached the upstream: %v", hd)
		}
	})
	_ = good2
}

func TestClientCert_AllowListAndRequireMode(t *testing.T) {
	ca := newTestCA(t, "client root", nil)
	alice := ca.issue(t, issueOpt{cn: "alice", dns: []string{"alice.example.org"}})
	bob := ca.issue(t, issueOpt{cn: "bob"})

	selfKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	selfTpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "pinned"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	selfDER, _ := x509.CreateCertificate(rand.Reader, selfTpl, selfTpl, &selfKey.PublicKey, selfKey)
	pinned := tls.Certificate{Certificate: [][]byte{selfDER}, PrivateKey: selfKey}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.CreateCertificate(rand.Reader, selfTpl, selfTpl, &otherKey.PublicKey, otherKey)
	notPinned := tls.Certificate{Certificate: [][]byte{otherDER}, PrivateKey: otherKey}

	h := newMTLSHarness(t,
		&ProxyEndpoint{RootOrMatchingDomain: "cn.test", ClientCert: &ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: ca.pem, AllowList: []string{"cn:alice"}}},
		&ProxyEndpoint{RootOrMatchingDomain: "san.test", ClientCert: &ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: ca.pem, AllowList: []string{"san:ALICE.example.org"}}},
		&ProxyEndpoint{RootOrMatchingDomain: "fp.test", ClientCert: &ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: ca.pem, AllowList: []string{strings.ToUpper(fingerprintOf(alice))}}},
		&ProxyEndpoint{RootOrMatchingDomain: "pin.test", ClientCert: &ClientCertConfig{Mode: ClientCertModeRequire, AllowList: []string{"sha256:" + fingerprintOf(pinned)}}},
	)
	for _, c := range []struct {
		host string
		cert tls.Certificate
		want int
	}{
		{"cn.test", alice, 299}, {"cn.test", bob, 403},
		{"san.test", alice, 299}, {"san.test", bob, 403},
		{"fp.test", alice, 299}, {"fp.test", bob, 403},
		{"pin.test", pinned, 299}, {"pin.test", notPinned, 403},
	} {
		cert := c.cert
		code, err := h.request(t, c.host, "", &cert, nil)
		if err != nil || code != c.want {
			t.Errorf("%s %s: code=%d err=%v want %d", c.host, leafOf(c.cert).Subject.CommonName, code, err, c.want)
		}
	}
	if _, err := h.request(t, "pin.test", "", nil, nil); err == nil {
		t.Error("require mode accepted a client without certificate")
	}
}

func TestClientCert_PlainHTTPRefusedWhenRequired(t *testing.T) {
	ca := newTestCA(t, "client root", nil)
	router, sep, _ := newNonTLSTestRouter(t)
	sep.ClientCert = &ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: ca.pem}
	sep.initNetworkOptions()
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.1:1000"); w.Code != 403 {
		t.Fatalf("plain HTTP request to an endpoint that requires a client certificate got %d, want 403", w.Code)
	}
	//request mode stays reachable without TLS
	sep.ClientCert = &ClientCertConfig{Mode: ClientCertModeRequest, CAPEM: ca.pem}
	sep.initNetworkOptions()
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.1:1000"); w.Code != 299 {
		t.Fatalf("request mode got %d, want 299", w.Code)
	}
}

func TestClientCert_ValidationAndFailClosed(t *testing.T) {
	ca := newTestCA(t, "client root", nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	bad := []struct {
		name string
		cfg  ClientCertConfig
	}{
		{"unknown mode", ClientCertConfig{Mode: "sometimes"}},
		{"verify without CA", ClientCertConfig{Mode: ClientCertModeRequireAndVerify}},
		{"garbage CA", ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: "not a pem"}},
		{"private key in CA bundle", ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: ca.pem + keyPEM}},
		{"truncated certificate", ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}},
		{"bad allow entry", ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: ca.pem, AllowList: []string{"serial:zz"}}},
		{"allow list in request mode", ClientCertConfig{Mode: ClientCertModeRequest, CAPEM: ca.pem, AllowList: []string{"cn:a"}}},
		{"require without pin", ClientCertConfig{Mode: ClientCertModeRequire}},
		{"huge CA", ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: strings.Repeat("A", maxClientCertCABytes+1)}},
	}
	for _, b := range bad {
		cfg := b.cfg
		if _, err := ValidateClientCertConfig(&cfg); err == nil {
			t.Errorf("%s: expected a validation error", b.name)
		}
	}
	if n, err := ValidateClientCertConfig(&ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: ca.pem}); err != nil || n != 1 {
		t.Errorf("valid config: n=%d err=%v", n, err)
	}
	if _, err := ValidateClientCertConfig(nil); err != nil {
		t.Errorf("nil config must be valid (off): %v", err)
	}

	//A broken config that reached the runtime (hand edited file) fails closed
	router, sep, _ := newNonTLSTestRouter(t)
	sep.ClientCert = &ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: "garbage"}
	sep.initNetworkOptions()
	if w := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.1:1000"); w.Code != 503 {
		t.Fatalf("invalid client cert policy got %d, want 503 (fail closed)", w.Code)
	}
}

func TestClientCert_OffByDefault(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.initNetworkOptions()
	r := serveNonTLS(router, sep, "http://app.example.com/", "198.51.100.1:1000")
	if r.Code != 299 {
		t.Fatalf("endpoint without networking options changed behaviour: %d", r.Code)
	}
}
