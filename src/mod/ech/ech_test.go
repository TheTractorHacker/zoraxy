package ech

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	pubName   = "ech.example.test"
	innerName = "secret.example.test"
)

func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func newMgr(t *testing.T, enable bool) *Manager {
	t.Helper()
	m, err := Open(filepath.Join(t.TempDir(), "ech"))
	if err != nil {
		t.Fatal(err)
	}
	if enable {
		if err := m.SetSettings(Settings{Enabled: true, PublicName: pubName}); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

type serverResult struct {
	sni      string
	accepted bool
	err      error
}

// startServer starts a TLS server using the same wiring as the proxy (Apply on the listener config, then a
// GetConfigForClient clone like the mTLS code does) and reports what each handshake looked like on the server side.
func startServer(t *testing.T, m *Manager, cert tls.Certificate, clone bool) (string, chan serverResult) {
	t.Helper()
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
	}
	m.Apply(cfg)
	if clone {
		base := cfg
		cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			c := base.Clone()
			c.GetConfigForClient = nil
			return c, nil
		}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	res := make(chan serverResult, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				err := tc.Handshake()
				st := tc.ConnectionState()
				res <- serverResult{st.ServerName, st.ECHAccepted, err}
				if err == nil {
					tc.Write([]byte("ok"))
				}
			}()
		}
	}()
	return ln.Addr().String(), res
}

func dial(addr, sni string, list []byte, pool *x509.CertPool) (*tls.ConnectionState, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName: sni, RootCAs: pool, MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	st := conn.ConnectionState()
	return &st, nil
}

func listOf(t *testing.T, m *Manager) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(m.ConfigListBase64())
	if err != nil || len(b) == 0 {
		t.Fatalf("no config list: %v", err)
	}
	return b
}

func TestDisabledByDefault(t *testing.T) {
	m, err := Open(filepath.Join(t.TempDir(), "ech"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Settings().Enabled || len(m.TLSKeys()) != 0 || m.ConfigListBase64() != "" || len(m.Keys()) != 0 {
		t.Fatal("ECH must be off and keyless by default")
	}
	if m.TLSKeys() == nil {
		t.Fatal("crypto/tls requires a non-nil slice")
	}
}

func TestHandshakeHidesInnerSNI(t *testing.T) {
	for _, clone := range []bool{false, true} {
		m := newMgr(t, true)
		cert, pool := testCert(t, pubName, innerName)
		addr, res := startServer(t, m, cert, clone)
		st, err := dial(addr, innerName, listOf(t, m), pool)
		if err != nil {
			t.Fatalf("clone=%v: %v", clone, err)
		}
		if !st.ECHAccepted {
			t.Fatalf("clone=%v: client says ECH not accepted", clone)
		}
		r := <-res
		if r.err != nil || !r.accepted || r.sni != innerName {
			t.Fatalf("clone=%v: server saw %+v, want accepted with inner SNI", clone, r)
		}
	}
}

func TestSNIPaddingAndConfigShape(t *testing.T) {
	m := newMgr(t, true)
	k := m.Keys()[0]
	if k.PublicName != pubName || k.MaxNameLength != DefaultMaxNameLength || !k.Advertised || k.State != StateActive {
		t.Fatalf("unexpected key %+v", k)
	}
	list := listOf(t, m)
	if int(list[0])<<8|int(list[1]) != len(list)-2 {
		t.Fatal("ECHConfigList length prefix wrong")
	}
	if list[2] != 0xfe || list[3] != 0x0d {
		t.Fatal("not an ECH config")
	}
}

func TestWrongKeyGetsRetryConfigs(t *testing.T) {
	server := newMgr(t, true)
	other := newMgr(t, true) //client has the config list of a different deployment
	cert, pool := testCert(t, pubName, innerName)
	addr, res := startServer(t, server, cert, false)
	_, err := dial(addr, innerName, listOf(t, other), pool)
	var rej *tls.ECHRejectionError
	if !errors.As(err, &rej) {
		t.Fatalf("expected ECHRejectionError, got %v", err)
	}
	if string(rej.RetryConfigList) != string(listOf(t, server)) {
		t.Fatal("retry configs must be the server's current advertised list")
	}
	r := <-res
	if r.accepted || r.sni == innerName {
		t.Fatalf("server must not see the inner name when decryption failed: %+v", r)
	}
	//Retrying with the supplied list works
	st, err := dial(addr, innerName, rej.RetryConfigList, pool)
	if err != nil || !st.ECHAccepted {
		t.Fatalf("retry failed: %v", err)
	}
}

func TestRotationKeepsOldKeyDecrypting(t *testing.T) {
	m := newMgr(t, true)
	cert, pool := testCert(t, pubName, innerName)
	addr, _ := startServer(t, m, cert, true)
	oldList := listOf(t, m)
	oldKey := m.Keys()[0]
	if _, err := m.Rotate(); err != nil {
		t.Fatal(err)
	}
	newList := listOf(t, m)
	if string(oldList) == string(newList) {
		t.Fatal("rotation must change the advertised list")
	}
	st, err := dial(addr, innerName, oldList, pool)
	if err != nil || !st.ECHAccepted {
		t.Fatalf("client with the pre-rotation list must still work (old key is decrypt-only): %v", err)
	}
	st, err = dial(addr, innerName, newList, pool)
	if err != nil || !st.ECHAccepted {
		t.Fatalf("new key: %v", err)
	}
	keys := m.Keys()
	if len(keys) != 2 || keys[0].State != StateActive || keys[1].State != StateRetired || keys[1].ID != oldKey.ID {
		t.Fatalf("unexpected key states %+v", keys)
	}
	//Only the active key is advertised for retries
	retry := 0
	for _, k := range m.TLSKeys() {
		if k.SendAsRetry {
			retry++
		}
	}
	if retry != 1 {
		t.Fatalf("exactly one key may be sent as retry, got %d", retry)
	}
	//Once the old key is deleted, old clients are rejected and told the new list
	if err := m.Delete(oldKey.ID); err != nil {
		t.Fatal(err)
	}
	_, err = dial(addr, innerName, oldList, pool)
	var rej *tls.ECHRejectionError
	if !errors.As(err, &rej) || string(rej.RetryConfigList) != string(newList) {
		t.Fatalf("deleted key: want rejection with new list, got %v", err)
	}
}

func TestDisabledServerIgnoresECH(t *testing.T) {
	m := newMgr(t, true)
	list := listOf(t, m)
	cert, pool := testCert(t, pubName, innerName)
	addr, _ := startServer(t, m, cert, false)
	s := m.Settings()
	s.Enabled = false
	if err := m.SetSettings(s); err != nil {
		t.Fatal(err)
	}
	_, err := dial(addr, innerName, list, pool)
	var rej *tls.ECHRejectionError
	if !errors.As(err, &rej) || len(rej.RetryConfigList) != 0 {
		t.Fatalf("disabled server: want rejection without retry configs, got %v", err)
	}
	//Plain clients are unaffected
	if st, err := dial(addr, innerName, nil, pool); err != nil || st.ECHAccepted {
		t.Fatalf("plain TLS must keep working: %v", err)
	}
}

func TestPersistenceAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ech")
	m, _ := Open(dir)
	if err := m.SetSettings(Settings{Enabled: true, PublicName: pubName, RotateEveryHours: 24}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, "ech.json"))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("ech.json must be 0600: %v %v", st, err)
		}
		if d, _ := os.Stat(dir); d.Mode().Perm() != 0o700 {
			t.Fatalf("dir must be 0700, got %v", d.Mode().Perm())
		}
	}
	m2, err := Open(dir)
	if err != nil || m2.ConfigListBase64() != m.ConfigListBase64() || !m2.Settings().Enabled {
		t.Fatalf("state not restored: %v", err)
	}
}

func TestPrivateKeyNeverInKeyInfo(t *testing.T) {
	m := newMgr(t, true)
	raw, _ := os.ReadFile(filepath.Join(m.dir, "ech.json"))
	var priv string
	m.mu.RLock()
	priv = m.keys[0].PrivateKey
	m.mu.RUnlock()
	if priv == "" || !strings.Contains(string(raw), priv) {
		t.Fatal("test setup")
	}
	for _, ki := range m.Keys() {
		if strings.Contains(ki.Config+ki.ID, priv) {
			t.Fatal("KeyInfo leaks the private key")
		}
	}
}

func TestMaintainRotatesAndPurges(t *testing.T) {
	m := newMgr(t, true)
	now := time.Now()
	m.now = func() time.Time { return now }
	s := m.Settings()
	s.RotateEveryHours = 24
	s.RetainHours = 48
	if err := m.SetSettings(s); err != nil {
		t.Fatal(err)
	}
	first := m.Keys()
	n := len(first)
	now = now.Add(25 * time.Hour)
	m.Maintain()
	if len(m.Keys()) != n+1 {
		t.Fatalf("auto rotation did not happen (%d keys)", len(m.Keys()))
	}
	now = now.Add(49 * time.Hour)
	m.Maintain()
	//Everything older than the retain window is gone, a fresh active key remains
	for _, k := range m.Keys() {
		if k.State == StateRetired && now.Sub(k.RetiredAt) >= 48*time.Hour {
			t.Fatal("expired retired key kept")
		}
	}
	if m.ConfigListBase64() == "" {
		t.Fatal("an active key must remain advertised")
	}
}

func TestValidation(t *testing.T) {
	for _, bad := range []string{"", "1.2.3.4", "*.example.com", "Example.com", "localhost", "a b.example.com", "-x.example.com"} {
		if ValidatePublicName(bad) == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	m := newMgr(t, false)
	if err := m.SetSettings(Settings{Enabled: true}); err == nil {
		t.Error("enabling without public name must fail")
	}
	if err := m.SetSettings(Settings{Enabled: true, PublicName: pubName, MaxNameLength: 300}); err == nil {
		t.Error("max name length over 255 must fail")
	}
	if m.Settings().Enabled {
		t.Error("failed update must not change settings")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	a := newMgr(t, true)
	pemText, err := a.Export(a.Keys()[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pemText, "BEGIN PRIVATE KEY") || !strings.Contains(pemText, "BEGIN ECHCONFIG") {
		t.Fatal("PEM blocks missing")
	}
	b := newMgr(t, false)
	if _, err := b.Import(pemText); err != nil {
		t.Fatal(err)
	}
	s := b.Settings()
	s.Enabled = true
	s.PublicName = "other.example.test"
	_ = s
	//Imported keys are decrypt-only; they accept a client that has A's list
	if len(b.Keys()) != 1 || b.Keys()[0].State != StateRetired {
		t.Fatal("imported key should be decrypt-only")
	}
	if _, err := b.Import(pemText); err == nil {
		t.Fatal("duplicate config id must be refused")
	}
	if _, err := b.Import("garbage"); err == nil {
		t.Fatal("garbage must be refused")
	}
}

func TestDNSCheckAgainstFakeResolver(t *testing.T) {
	m := newMgr(t, true)
	expected := m.ConfigListBase64()
	raw, _ := base64.StdEncoding.DecodeString(expected)

	build := func(echb []byte) dns.Handler {
		return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(r)
			if r.Question[0].Qtype == dns.TypeHTTPS && r.Question[0].Name == "www.example.test." {
				rr := &dns.HTTPS{SVCB: dns.SVCB{
					Hdr:      dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
					Priority: 1, Target: ".",
					Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: echb}},
				}}
				resp.Answer = append(resp.Answer, rr)
			}
			_ = w.WriteMsg(resp)
		})
	}
	run := func(h dns.Handler) string {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &dns.Server{PacketConn: pc, Handler: h}
		go srv.ActivateAndServe()
		t.Cleanup(func() { srv.Shutdown() })
		time.Sleep(50 * time.Millisecond)
		return pc.LocalAddr().String()
	}
	ctx := context.Background()

	res, err := CheckDNS(ctx, "www.example.test", run(build(raw)), expected)
	if err != nil || !res.HasECH || !res.Match || res.Stale {
		t.Fatalf("matching record: %+v %v", res, err)
	}
	res, err = CheckDNS(ctx, "www.example.test", run(build([]byte{0, 2, 1, 2})), expected)
	if err != nil || !res.HasECH || res.Match || !res.Stale {
		t.Fatalf("stale record: %+v %v", res, err)
	}
	res, err = CheckDNS(ctx, "nothing.example.test", run(build(raw)), expected)
	if err != nil || res.HasHTTPS {
		t.Fatalf("missing record: %+v %v", res, err)
	}
	if _, err := CheckDNS(ctx, "bad host", "127.0.0.1:1", expected); err == nil {
		t.Fatal("invalid host accepted")
	}
	if _, err := CheckDNS(ctx, "www.example.test", "not-an-ip", expected); err == nil {
		t.Fatal("non-IP resolver accepted")
	}
}

func TestSVCBExample(t *testing.T) {
	s := SVCBExample("www.example.com", "AAAA", true)
	if !strings.Contains(s, `ech="AAAA"`) || !strings.Contains(s, "h3") || !strings.HasPrefix(s, "www.example.com. ") {
		t.Fatal(s)
	}
}

func TestSelfCheckAcceptedAndDisabled(t *testing.T) {
	m := newMgr(t, true)
	cert, _ := testCert(t, pubName, innerName)
	addr, _ := startServer(t, m, cert, false)
	res := SelfCheck(context.Background(), addr, innerName, m.ConfigListBase64())
	if !res.Attempted || !res.Accepted || res.TLSVersion != "TLS 1.3" {
		t.Fatalf("expected accepted ECH, got %+v", res)
	}
	// no key: nothing is attempted
	if r := SelfCheck(context.Background(), addr, innerName, ""); r.Attempted || r.Accepted || r.Advice == "" {
		t.Fatalf("empty list must not attempt a handshake: %+v", r)
	}
	// nobody listening: clear error, not accepted
	if r := SelfCheck(context.Background(), "127.0.0.1:1", innerName, m.ConfigListBase64()); !r.Attempted || r.Accepted || r.Error == "" {
		t.Fatalf("closed port: %+v", r)
	}
	// server without ECH keys: handshake works (TLS 1.3) but ECH is not accepted
	m2 := newMgr(t, false)
	addr2, _ := startServer(t, m2, cert, false)
	if r := SelfCheck(context.Background(), addr2, innerName, m.ConfigListBase64()); r.Accepted {
		t.Fatalf("server without ECH must not report acceptance: %+v", r)
	}
}

func TestRecordsFor(t *testing.T) {
	got := RecordsFor([]string{"B.example.com", "a.example.com.", "*.example.com", "localhost", "10.0.0.1", "a.example.com", "x/y.com", ""}, "AAAA", true)
	if len(got) != 2 || got[0].Host != "a.example.com" || got[1].Host != "b.example.com" {
		t.Fatalf("unexpected hosts: %+v", got)
	}
	if !strings.Contains(got[0].Record, `ech="AAAA"`) || !strings.Contains(got[0].Record, "h3,h2") {
		t.Fatalf("record: %s", got[0].Record)
	}
}
