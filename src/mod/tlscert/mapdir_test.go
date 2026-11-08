package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/acme"
)

// selfPair returns PEM encoded certificate and key for a name.
func selfPair(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func put(t *testing.T, path string, data []byte) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMapDirLayouts(t *testing.T) {
	root := t.TempDir()
	soon := time.Now().Add(48 * time.Hour)
	c1, k1 := selfPair(t, "a.example", soon)
	c2, k2 := selfPair(t, "b.example", soon)
	c3, k3 := selfPair(t, "c.example", soon)
	c4, k4 := selfPair(t, "d.example", soon)
	c5, k5 := selfPair(t, "e.example", soon)
	put(t, filepath.Join(root, "a.example", "fullchain.pem"), c1)
	put(t, filepath.Join(root, "a.example", "privkey.pem"), k1)
	put(t, filepath.Join(root, "b.example.crt"), c2)
	put(t, filepath.Join(root, "b.example.key"), k2)
	put(t, filepath.Join(root, "live", "c.example", "fullchain.pem"), c3)
	put(t, filepath.Join(root, "live", "c.example", "privkey.pem"), k3)
	put(t, filepath.Join(root, "d", "server.crt"), c4)
	put(t, filepath.Join(root, "d", "server.key"), k4)
	put(t, filepath.Join(root, "k8s", "tls.crt"), c5)
	put(t, filepath.Join(root, "k8s", "tls.key"), k5)
	put(t, filepath.Join(root, "orphan.crt"), c1) // no key: ignored

	got := map[string]bool{}
	for _, c := range Discover(root) {
		got[c.Name] = true
	}
	for _, want := range []string{"a.example", "b.example", "c.example", "d", "k8s"} {
		if !got[want] {
			t.Errorf("layout for %s not discovered; got %v", want, got)
		}
	}
	if got["orphan"] {
		t.Error("certificate without key must be ignored")
	}
}

func TestMapDirCertbotSymlinksImportUpdateAndSourceUntouched(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	m := newTestManager(t)
	root := t.TempDir()
	cert1, key1 := selfPair(t, "site.example", time.Now().Add(72*time.Hour))
	// certbot: archive/<name>/fullchain1.pem, live/<name>/fullchain.pem -> ../../archive/<name>/fullchain1.pem
	put(t, filepath.Join(root, "archive", "site.example", "fullchain1.pem"), cert1)
	put(t, filepath.Join(root, "archive", "site.example", "privkey1.pem"), key1)
	live := filepath.Join(root, "live", "site.example")
	os.MkdirAll(live, 0o755)
	os.Symlink("../../archive/site.example/fullchain1.pem", filepath.Join(live, "fullchain.pem"))
	os.Symlink("../../archive/site.example/privkey1.pem", filepath.Join(live, "privkey.pem"))

	w := &MapDirWatcher{Dir: root, Manager: m}
	if n := w.ScanOnce(); n != 1 {
		t.Fatalf("expected 1 import, got %d (%+v)", n, w.Status())
	}
	pemPath := filepath.Join(m.CertStore, "site.example.pem")
	if b, _ := os.ReadFile(pemPath); string(b) != string(cert1) {
		t.Fatal("certificate not copied")
	}
	info, err := acme.LoadCertInfoJSON(filepath.Join(m.CertStore, "site.example.json"))
	if err != nil || info.ManagedBy != "mapdir" || !info.IsExternallyManaged() || info.Source == "" {
		t.Fatalf("metadata: %+v %v", info, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(m.CertStore, "site.example.key")); st.Mode().Perm() != 0o600 {
			t.Fatal("imported key must be 0600")
		}
	}
	if names, _ := m.ListCertDomains(); len(names) != 1 {
		t.Fatalf("imported cert must show up in the store: %v", names)
	}
	if n := w.ScanOnce(); n != 0 {
		t.Fatalf("unchanged files must not be re-imported, got %d", n)
	}

	// renewal by the external tool: new archive file, symlinks repointed
	cert2, key2 := selfPair(t, "site.example", time.Now().Add(96*time.Hour))
	put(t, filepath.Join(root, "archive", "site.example", "fullchain2.pem"), cert2)
	put(t, filepath.Join(root, "archive", "site.example", "privkey2.pem"), key2)
	os.Remove(filepath.Join(live, "fullchain.pem"))
	os.Remove(filepath.Join(live, "privkey.pem"))
	os.Symlink("../../archive/site.example/fullchain2.pem", filepath.Join(live, "fullchain.pem"))
	os.Symlink("../../archive/site.example/privkey2.pem", filepath.Join(live, "privkey.pem"))
	if n := w.ScanOnce(); n != 1 {
		t.Fatalf("renewed certificate must be picked up, got %d (%+v)", n, w.Status())
	}
	if b, _ := os.ReadFile(pemPath); string(b) != string(cert2) {
		t.Fatal("store still has the old certificate")
	}

	// source untouched (never deleted / modified)
	if b, _ := os.ReadFile(filepath.Join(root, "archive", "site.example", "fullchain1.pem")); string(b) != string(cert1) {
		t.Fatal("source file modified")
	}
	// removing the source never removes the store copy
	os.RemoveAll(root)
	w.ScanOnce()
	if _, err := os.Stat(pemPath); err != nil {
		t.Fatal("store copy must stay when the source disappears")
	}
}

func TestMapDirRejectsMismatchExpiredAndNeverClobbers(t *testing.T) {
	m := newTestManager(t)
	root := t.TempDir()
	cA, _ := selfPair(t, "mismatch.example", time.Now().Add(time.Hour))
	_, kB := selfPair(t, "other.example", time.Now().Add(time.Hour))
	put(t, filepath.Join(root, "mismatch.example.crt"), cA)
	put(t, filepath.Join(root, "mismatch.example.key"), kB)
	cE, kE := selfPair(t, "expired.example", time.Now().Add(-time.Minute))
	put(t, filepath.Join(root, "expired.example.crt"), cE)
	put(t, filepath.Join(root, "expired.example.key"), kE)

	// an ACME/uploaded certificate of the same name already exists
	cX, kX := selfPair(t, "mine.example", time.Now().Add(time.Hour))
	put(t, filepath.Join(m.CertStore, "mine.example.pem"), cX)
	put(t, filepath.Join(m.CertStore, "mine.example.key"), kX)
	cN, kN := selfPair(t, "mine.example", time.Now().Add(100*time.Hour))
	put(t, filepath.Join(root, "mine.example.crt"), cN)
	put(t, filepath.Join(root, "mine.example.key"), kN)

	w := &MapDirWatcher{Dir: root, Manager: m}
	if n := w.ScanOnce(); n != 0 {
		t.Fatalf("nothing should import, got %d", n)
	}
	errs := map[string]string{}
	for _, s := range w.Status() {
		errs[s.Name] = s.Error
	}
	if !strings.Contains(errs["mismatch.example"], "do not match") {
		t.Errorf("mismatch not reported: %q", errs["mismatch.example"])
	}
	if !strings.Contains(errs["expired.example"], "expired") {
		t.Errorf("expired not reported: %q", errs["expired.example"])
	}
	if !strings.Contains(errs["mine.example"], "left alone") {
		t.Errorf("collision not reported: %q", errs["mine.example"])
	}
	if b, _ := os.ReadFile(filepath.Join(m.CertStore, "mine.example.pem")); string(b) != string(cX) {
		t.Fatal("an existing certificate was overwritten")
	}
	for _, n := range []string{"mismatch.example", "expired.example"} {
		if _, err := os.Stat(filepath.Join(m.CertStore, n+".pem")); err == nil {
			t.Errorf("%s must not be installed", n)
		}
	}
}
