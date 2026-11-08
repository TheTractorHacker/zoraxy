package dynamicproxy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

/*
	clientcert.go

	Per proxy endpoint client certificate authentication (mTLS), upstream issue #442.

	How it works
	  - ProxyEndpoint.ClientCert holds the admin supplied configuration. It is compiled
	    by PrepareProxyRoute into ProxyEndpoint.clientCert (CA pool, allow / block list).
	  - The TLS listeners get a tls.Config.GetConfigForClient callback that looks at the
	    SNI host name. Only endpoints with client certificates enabled ask the client for one,
	    everybody else keeps the normal handshake (no certificate prompt in the browser).
	  - The handshake is NOT the security boundary, because the SNI name and the HTTP
	    Host header are chosen independently by the client (domain fronting style
	    mismatch, connection reuse, TLS session resumption). runEndpointChain therefore calls
	    enforceClientCert for the endpoint selected by the Host header, which re-verifies the
	    presented certificate against that endpoint's own CA pool and allow / block list.
	  - Verified identity is passed to the upstream as X-Client-Cert-* headers. The headers are
	    always stripped from the incoming request first so a client can never forge them.

	Revocation is NOT supported: there is no CRL / OCSP checking. Use the block list
	(fingerprint, serial) or replace the CA to cut off a certificate.
*/

const (
	ClientCertModeOff              = ""
	ClientCertModeRequest          = "request"            //Ask for a certificate, optional. A presented certificate must verify when a CA bundle is configured
	ClientCertModeRequire          = "require"            //A certificate must be presented, but is not chain verified (pin it with the allow list)
	ClientCertModeRequireAndVerify = "require_and_verify" //A certificate must be presented and chain to the CA bundle

	HeaderClientCertSubject     = "X-Client-Cert-Subject"
	HeaderClientCertFingerprint = "X-Client-Cert-Fingerprint"
	HeaderClientCertSerial      = "X-Client-Cert-Serial"
	HeaderClientCertVerified    = "X-Client-Cert-Verified"

	maxClientCertCABytes   = 512 * 1024
	maxClientCertListItems = 1000
)

// ClientCertConfig is the per endpoint inbound client certificate (mTLS) setting. Zero value = off.
type ClientCertConfig struct {
	Mode                   string   //"" (off), "request", "require" or "require_and_verify"
	CAPEM                  string   //PEM bundle of the accepted client CA certificates
	AllowList              []string //Optional. Only these certificates may pass. Entries: sha256 fingerprint (hex), "serial:<hex>", "cn:<name>", "san:<dns|email|uri|ip>" or a bare CN / SAN
	BlockList              []string //Optional. Certificates that are refused even if valid (manual revocation). Same entry format
	DisableIdentityHeaders bool     //Do not pass X-Client-Cert-* headers to the upstream
}

// clientCertRuntime is the compiled form of ClientCertConfig
type clientCertRuntime struct {
	cfg      ClientCertConfig
	pool     *x509.CertPool
	authType tls.ClientAuthType
	allow    []certMatcher
	block    []certMatcher
}

type certMatcher struct {
	kind  string // "fp", "serial", "cn", "san", "name"
	value string // lower case
}

// Enabled reports whether the config turns client certificate handling on
func (c *ClientCertConfig) Enabled() bool {
	return c != nil && c.Mode != ClientCertModeOff
}

func parseCAPEM(caPEM string) (*x509.CertPool, int, error) {
	if len(caPEM) > maxClientCertCABytes {
		return nil, 0, errors.New("CA bundle is too large")
	}
	pool := x509.NewCertPool()
	count := 0
	rest := []byte(caPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, 0, fmt.Errorf("unexpected PEM block %q in CA bundle, only CERTIFICATE blocks are allowed (never upload a private key here)", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid CA certificate: %w", err)
		}
		pool.AddCert(cert)
		count++
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, 0, errors.New("CA bundle contains data that is not PEM encoded")
	}
	return pool, count, nil
}

func normalizeFingerprint(s string) (string, bool) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if len(s) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", false
	}
	return s, true
}

func padHex(s string) string {
	if len(s)%2 == 1 {
		return "0" + s
	}
	return s
}

func parseCertMatcher(entry string) (certMatcher, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return certMatcher{}, errors.New("empty entry")
	}
	lower := strings.ToLower(entry)
	switch {
	case strings.HasPrefix(lower, "serial:"):
		v := strings.TrimLeft(strings.TrimSpace(strings.ReplaceAll(lower[len("serial:"):], ":", "")), "0")
		if v == "" {
			return certMatcher{}, errors.New("empty or zero serial")
		}
		if _, err := hex.DecodeString(padHex(v)); err != nil {
			return certMatcher{}, fmt.Errorf("serial %q is not hexadecimal", entry)
		}
		return certMatcher{"serial", v}, nil
	case strings.HasPrefix(lower, "cn:"):
		v := strings.TrimSpace(lower[3:])
		if v == "" {
			return certMatcher{}, errors.New("empty common name")
		}
		return certMatcher{"cn", v}, nil
	case strings.HasPrefix(lower, "san:"):
		v := strings.TrimSpace(lower[4:])
		if v == "" {
			return certMatcher{}, errors.New("empty SAN")
		}
		return certMatcher{"san", v}, nil
	case strings.HasPrefix(lower, "sha256:"):
		fp, ok := normalizeFingerprint(lower[7:])
		if !ok {
			return certMatcher{}, fmt.Errorf("%q is not a SHA-256 fingerprint", entry)
		}
		return certMatcher{"fp", fp}, nil
	}
	if fp, ok := normalizeFingerprint(lower); ok {
		return certMatcher{"fp", fp}, nil
	}
	//bare value: matches the common name or any SAN
	return certMatcher{"name", lower}, nil
}

func compileCertMatchers(entries []string) ([]certMatcher, error) {
	if len(entries) > maxClientCertListItems {
		return nil, errors.New("too many list entries")
	}
	out := make([]certMatcher, 0, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		m, err := parseCertMatcher(e)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func certSerialHex(cert *x509.Certificate) string {
	return strings.ToLower(cert.SerialNumber.Text(16))
}

func (m certMatcher) matches(cert *x509.Certificate) bool {
	switch m.kind {
	case "fp":
		return certFingerprint(cert) == m.value
	case "serial":
		return certSerialHex(cert) == m.value
	case "cn":
		return strings.EqualFold(cert.Subject.CommonName, m.value)
	}
	//"san" and "name"
	if m.kind == "name" && strings.EqualFold(cert.Subject.CommonName, m.value) {
		return true
	}
	for _, d := range cert.DNSNames {
		if strings.EqualFold(d, m.value) {
			return true
		}
	}
	for _, e := range cert.EmailAddresses {
		if strings.EqualFold(e, m.value) {
			return true
		}
	}
	for _, u := range cert.URIs {
		if strings.EqualFold(u.String(), m.value) {
			return true
		}
	}
	for _, ip := range cert.IPAddresses {
		if ip.String() == m.value {
			return true
		}
	}
	return false
}

func anyMatcher(ms []certMatcher, cert *x509.Certificate) bool {
	for _, m := range ms {
		if m.matches(cert) {
			return true
		}
	}
	return false
}

func compactStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// ValidateClientCertConfig checks a config before it is stored and returns the number of CA certificates found
func ValidateClientCertConfig(cfg *ClientCertConfig) (int, error) {
	if !cfg.Enabled() {
		return 0, nil
	}
	switch cfg.Mode {
	case ClientCertModeRequest, ClientCertModeRequire, ClientCertModeRequireAndVerify:
	default:
		return 0, fmt.Errorf("unknown client certificate mode %q", cfg.Mode)
	}
	_, n, err := parseCAPEM(cfg.CAPEM)
	if err != nil {
		return 0, err
	}
	if cfg.Mode == ClientCertModeRequireAndVerify && n == 0 {
		return 0, errors.New("mode require_and_verify needs at least one CA certificate")
	}
	if _, err := compileCertMatchers(cfg.AllowList); err != nil {
		return 0, fmt.Errorf("allow list: %w", err)
	}
	if _, err := compileCertMatchers(cfg.BlockList); err != nil {
		return 0, fmt.Errorf("block list: %w", err)
	}
	hasAllow := len(compactStrings(cfg.AllowList)) > 0
	if cfg.Mode == ClientCertModeRequest && hasAllow {
		return 0, errors.New("an allow list needs mode require or require_and_verify (in request mode the certificate is optional, so the list could not restrict anything)")
	}
	if cfg.Mode == ClientCertModeRequire && !hasAllow {
		return 0, errors.New("mode require does not verify the certificate chain and would accept any self-made certificate; add an allow list (fingerprint) or use require_and_verify")
	}
	return n, nil
}

func compileClientCert(cfg *ClientCertConfig) (*clientCertRuntime, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	if _, err := ValidateClientCertConfig(cfg); err != nil {
		return nil, err
	}
	pool, n, _ := parseCAPEM(cfg.CAPEM)
	rt := &clientCertRuntime{cfg: *cfg}
	if n > 0 {
		rt.pool = pool
	}
	rt.allow, _ = compileCertMatchers(cfg.AllowList)
	rt.block, _ = compileCertMatchers(cfg.BlockList)
	switch cfg.Mode {
	case ClientCertModeRequest:
		if rt.pool != nil {
			rt.authType = tls.VerifyClientCertIfGiven
		} else {
			rt.authType = tls.RequestClientCert
		}
	case ClientCertModeRequire:
		rt.authType = tls.RequireAnyClientCert
	case ClientCertModeRequireAndVerify:
		rt.authType = tls.RequireAndVerifyClientCert
	}
	return rt, nil
}

// initClientCert compiles the client certificate policy of an endpoint. A compile error does
// not fail the endpoint load: it is remembered and the endpoint then answers 503 to every
// request, i.e. it fails closed instead of silently dropping the protection.
func (pe *ProxyEndpoint) initClientCert() {
	pe.clientCert = nil
	pe.clientCertErr = nil
	rt, err := compileClientCert(pe.ClientCert)
	if err != nil {
		pe.clientCertErr = err
		return
	}
	pe.clientCert = rt
}

// verifyChain verifies the presented chain against the endpoint CA pool for client auth use
func (rt *clientCertRuntime) verifyChain(certs []*x509.Certificate, now time.Time) bool {
	if rt.pool == nil || len(certs) == 0 {
		return false
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         rt.pool,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

// tlsConfigFor returns the TLS config used for handshakes of this endpoint, derived from the listener config
func (rt *clientCertRuntime) tlsConfigFor(base *tls.Config, hello *tls.ClientHelloInfo) *tls.Config {
	cfg := base.Clone()
	cfg.GetConfigForClient = nil
	cfg.ClientAuth = rt.authType
	cfg.ClientCAs = rt.pool
	//ALPN: h2 / http/1.1 are only added to the HTTP server's private copy of the listener config
	for _, p := range hello.SupportedProtos {
		if p == "h3" {
			cfg.NextProtos = []string{"h3"}
			return cfg
		}
	}
	cfg.NextProtos = nil
	for _, want := range []string{"h2", "http/1.1"} {
		for _, p := range hello.SupportedProtos {
			if p == want {
				cfg.NextProtos = append(cfg.NextProtos, p)
			}
		}
	}
	return cfg
}

// clientCertGetConfig builds the GetConfigForClient callback that applies the client
// certificate policy of the endpoint matching the SNI host name
func (router *Router) clientCertGetConfig(base *tls.Config) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
		if name == "" {
			return nil, nil
		}
		sep := router.GetProxyEndpointFromHostname(name)
		if sep == nil || sep.Disabled || sep.clientCert == nil {
			return nil, nil
		}
		return sep.clientCert.tlsConfigFor(base, hello), nil
	}
}

var clientCertHeaders = []string{HeaderClientCertSubject, HeaderClientCertFingerprint, HeaderClientCertSerial, HeaderClientCertVerified}

// enforceClientCert applies the endpoint's client certificate policy to a request. It returns
// true when the request was rejected (response already written).
func (h *ProxyHandler) enforceClientCert(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if sep.clientCertErr != nil {
		h.Parent.Option.Logger.PrintAndLog("proxy-clientcert", "Client certificate configuration of "+sep.RootOrMatchingDomain+" is invalid, refusing requests", sep.clientCertErr)
		http.Error(w, "503 - Client certificate policy misconfigured", http.StatusServiceUnavailable)
		return true
	}
	rt := sep.clientCert
	if rt == nil {
		return false
	}
	//Never trust identity headers from the client
	for _, hn := range clientCertHeaders {
		r.Header.Del(hn)
	}

	var leaf *x509.Certificate
	verified := false
	now := time.Now()
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf = r.TLS.PeerCertificates[0]
		verified = rt.verifyChain(r.TLS.PeerCertificates, now)
	}

	deny := func(reason string) bool {
		h.Parent.logRequest(r, false, 403, "client-cert-"+reason, r.Host, "", sep)
		http.Error(w, "403 - Client certificate required or not accepted", http.StatusForbidden)
		return true
	}

	switch rt.cfg.Mode {
	case ClientCertModeRequire:
		if leaf == nil {
			return deny("missing")
		}
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return deny("expired")
		}
	case ClientCertModeRequireAndVerify:
		if leaf == nil {
			return deny("missing")
		}
		if !verified {
			return deny("invalid")
		}
	case ClientCertModeRequest:
		if leaf != nil && rt.pool != nil && !verified {
			return deny("invalid")
		}
	}
	if leaf != nil {
		if anyMatcher(rt.block, leaf) {
			return deny("blocked")
		}
		if len(rt.allow) > 0 && !anyMatcher(rt.allow, leaf) {
			return deny("not-allowed")
		}
		if !rt.cfg.DisableIdentityHeaders {
			r.Header.Set(HeaderClientCertSubject, sanitizeHeaderValue(leaf.Subject.String()))
			r.Header.Set(HeaderClientCertFingerprint, certFingerprint(leaf))
			r.Header.Set(HeaderClientCertSerial, certSerialHex(leaf))
			if verified {
				r.Header.Set(HeaderClientCertVerified, "true")
			} else {
				r.Header.Set(HeaderClientCertVerified, "false")
			}
		}
	}
	return false
}

// sanitizeHeaderValue removes control characters so a subject can never inject a header line
func sanitizeHeaderValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
