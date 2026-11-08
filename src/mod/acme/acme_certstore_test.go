package acme

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
	"testing"
	"time"
)

// A handler with a custom CertStorePath (the -conf flag) must scan that folder,
// not ./conf/certs of the working directory.
func TestCheckCertificateUsesCertStorePath(t *testing.T) {
	cwd := t.TempDir()
	store := filepath.Join(t.TempDir(), "mydata", "certs")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(cwd, "conf", "certs"), 0o755)
	old, _ := os.Getwd()
	os.Chdir(cwd)
	defer os.Chdir(old)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "expired.example.com"},
		DNSNames:  []string{"expired.example.com"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	os.WriteFile(filepath.Join(store, "expired.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)

	h := newTestHandler(t)
	h.CertStorePath = store
	got := h.CheckCertificate()
	if len(got) != 1 || got[0] != "expired.example.com" {
		t.Fatalf("expected the expired cert in the custom store to be reported, got %v", got)
	}
	if h.certPath("a.pem") != filepath.Join(store, "a.pem") {
		t.Fatalf("certPath ignores CertStorePath: %s", h.certPath("a.pem"))
	}
	if (&ACMEHandler{}).certPath("a.pem") != filepath.Join("conf", "certs", "a.pem") {
		t.Fatal("default must stay ./conf/certs")
	}
}
