package webuitls

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
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func writeTestPair(t *testing.T, dir string, names []string, ips []net.IP, nb, na time.Time, marker bool) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: nb, NotAfter: na, DNSNames: names, IPAddresses: ips,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(priv)
	os.WriteFile(filepath.Join(dir, CertFileName), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	os.WriteFile(filepath.Join(dir, KeyFileName), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0600)
	if marker {
		os.WriteFile(filepath.Join(dir, markerFileName), []byte("x"), 0644)
	}
}

func TestGenerate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "webui")
	info, err := EnsureCert(dir, ModeAuto)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Generated {
		t.Fatal("expected generated")
	}
	leaf := info.Certificate.Leaf
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatal("not ECDSA P-256")
	}
	d := leaf.NotAfter.Sub(leaf.NotBefore)
	if d < 3649*24*time.Hour || d > 3652*24*time.Hour {
		t.Fatalf("validity %v", d)
	}
	for _, n := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := leaf.VerifyHostname(n); err != nil {
			t.Errorf("SAN %s: %v", n, err)
		}
	}
	if h, _ := os.Hostname(); h != "" {
		if err := leaf.VerifyHostname(h); err != nil {
			t.Errorf("hostname SAN: %v", err)
		}
	}
	_, ips := LocalIdentities()
	for _, ip := range ips {
		if err := leaf.VerifyHostname(ip.String()); err != nil {
			t.Errorf("ip SAN %s: %v", ip, err)
		}
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("missing digital signature key usage")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("bad ext key usage")
	}
	if leaf.IsCA {
		t.Error("must not be CA")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(dir, KeyFileName))
		if st.Mode().Perm() != 0600 {
			t.Errorf("key mode %v", st.Mode().Perm())
		}
	}
	if len(info.Fingerprint) != 95 {
		t.Errorf("fingerprint %q", info.Fingerprint)
	}
}

func TestReuse(t *testing.T) {
	dir := t.TempDir()
	a, err := EnsureCert(dir, ModeAuto)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EnsureCert(dir, ModeAuto)
	if err != nil {
		t.Fatal(err)
	}
	if b.Generated || a.Fingerprint != b.Fingerprint {
		t.Fatal("expected reuse")
	}
}

func TestRegenerateOnSANChange(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeTestPair(t, dir, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, now.Add(-time.Hour), now.Add(CertValidity), true)
	info, err := EnsureCert(dir, ModeAuto)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Generated {
		t.Fatal("expected regeneration because SANs do not cover ::1/hostname")
	}
}

func TestRegenerateExpiring(t *testing.T) {
	names, ips := LocalIdentities()
	for name, na := range map[string]time.Time{"expired": time.Now().Add(-time.Hour), "near": time.Now().Add(10 * 24 * time.Hour)} {
		dir := t.TempDir()
		writeTestPair(t, dir, names, ips, time.Now().Add(-100*24*time.Hour), na, true)
		info, err := EnsureCert(dir, ModeAuto)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Generated {
			t.Errorf("%s: expected regeneration", name)
		}
	}
	// control: healthy marker cert is reused
	dir := t.TempDir()
	writeTestPair(t, dir, names, ips, time.Now().Add(-time.Hour), time.Now().Add(CertValidity), true)
	info, _ := EnsureCert(dir, ModeAuto)
	if info.Generated {
		t.Error("healthy cert should be reused")
	}
}

func TestUserSuppliedNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	// expired, no matching SANs, no marker -> user supplied
	writeTestPair(t, dir, []string{"example.org"}, nil, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), false)
	before, _ := os.ReadFile(filepath.Join(dir, CertFileName))
	for _, m := range []string{ModeAuto, ModeCustom} {
		info, err := EnsureCert(dir, m)
		if err != nil {
			t.Fatal(err)
		}
		if info.Generated || !info.UserSupplied {
			t.Fatalf("%s: should use user cert", m)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, CertFileName))
	if string(before) != string(after) {
		t.Fatal("user cert modified")
	}
}

func TestCustomMissing(t *testing.T) {
	if _, err := EnsureCert(t.TempDir(), ModeCustom); err == nil {
		t.Fatal("expected error")
	}
	if _, err := EnsureCert(t.TempDir(), "bogus"); err == nil {
		t.Fatal("expected error")
	}
}

func startSniff(t *testing.T, h http.Handler) (string, *CertInfo) {
	t.Helper()
	info, err := EnsureCert(t.TempDir(), ModeAuto)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sl := NewSniffListener(ln, ServerTLSConfig(info))
	srv := &http.Server{Handler: h}
	go srv.Serve(sl)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), info
}

func TestSniffListener(t *testing.T) {
	addr, info := startSniff(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	pool := x509.NewCertPool()
	pool.AddCert(info.Certificate.Leaf)
	tc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := tc.Get("https://" + addr + "/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "hello" {
		t.Fatalf("body %q", b)
	}

	pc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = pc.Get("http://" + addr + "/a/b?c=d")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 308 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://"+addr+"/a/b?c=d" {
		t.Fatalf("location %q", loc)
	}
}

// Integration style: handler with a Secure-over-TLS cookie on an ephemeral port.
func TestAdminHandlerOverTLS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Secure: r.TLS != nil})
		io.WriteString(w, "pong")
	})
	addr, info := startSniff(t, mux)
	pool := x509.NewCertPool()
	pool.AddCert(info.Certificate.Leaf)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	_, port, _ := net.SplitHostPort(addr)
	resp, err := c.Get("https://localhost:" + port + "/api/ping")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.Cookies()) != 1 || !resp.Cookies()[0].Secure {
		t.Fatal("expected TLS and Secure cookie")
	}
}
