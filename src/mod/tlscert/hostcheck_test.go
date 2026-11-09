package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
)

// mkCert returns a certificate; with a ca it is a leaf issued by that CA, otherwise it is self-signed.
func mkCert(t *testing.T, names []string, notBefore, notAfter time.Time, ca *tls.Certificate) (*tls.Certificate, []byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	parent, signer := tpl, any(key)
	if ca != nil {
		parent, _ = x509.ParseCertificate(ca.Certificate[0])
		signer = ca.PrivateKey
	} else {
		tpl.IsCA = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{der}
	if ca != nil {
		chain = append(chain, ca.Certificate[0])
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	var pemChain []byte
	for _, c := range chain {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key}, pemChain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func TestEvaluateCertificate(t *testing.T) {
	now := time.Now()
	ca, _, _ := mkCert(t, []string{"Test CA"}, now.Add(-time.Hour), now.Add(24*time.Hour), nil)
	good, _, _ := mkCert(t, []string{"ech.example.com"}, now.Add(-time.Hour), now.Add(time.Hour), ca)
	wild, _, _ := mkCert(t, []string{"*.example.com"}, now.Add(-time.Hour), now.Add(time.Hour), ca)
	expired, _, _ := mkCert(t, []string{"ech.example.com"}, now.Add(-48*time.Hour), now.Add(-time.Hour), ca)
	selfs, _, _ := mkCert(t, []string{"ech.example.com"}, now.Add(-time.Hour), now.Add(time.Hour), nil)
	other, _, _ := mkCert(t, []string{"other.example.org"}, now.Add(-time.Hour), now.Add(time.Hour), ca)

	cases := []struct {
		name     string
		cert     *tls.Certificate
		fallback bool
		want     string
	}{
		{"no certificate", nil, false, CertMissing},
		{"built-in fallback", good, true, CertFallback},
		{"valid", good, false, CertOK},
		{"wildcard covers the name", wild, false, CertOK},
		{"expired", expired, false, CertExpired},
		{"self-signed but covering", selfs, false, CertSelfSigned},
		{"other name", other, false, CertMismatch},
	}
	for _, c := range cases {
		got := EvaluateCertificate(c.cert, "ech.example.com", c.fallback, now)
		if got.State != c.want || got.Reason == "" || got.Valid != (c.want == CertOK) {
			t.Errorf("%s: state %q valid=%v reason=%q, want %q", c.name, got.State, got.Valid, got.Reason, c.want)
		}
	}
}

func TestCheckHostCertificateUsesRealMatching(t *testing.T) {
	dir, tmp := t.TempDir(), t.TempDir()
	lg, _ := logger.NewFmtLogger()
	m, err := NewManagerWithTmp(dir, tmp, lg)
	if err != nil {
		t.Fatal(err)
	}
	// nothing stored: the built-in self-signed localhost certificate would be served
	if got := m.CheckHostCertificate("ech.example.com", time.Now()); got.State != CertFallback || got.Valid {
		t.Fatalf("no cert stored: %+v", got)
	}
	now := time.Now()
	ca, _, _ := mkCert(t, []string{"Test CA"}, now.Add(-time.Hour), now.Add(24*time.Hour), nil)
	_, pemChain, key := mkCert(t, []string{"*.example.com"}, now.Add(-time.Hour), now.Add(time.Hour), ca)
	os.WriteFile(filepath.Join(dir, "wild.pem"), pemChain, 0644)
	os.WriteFile(filepath.Join(dir, "wild.key"), key, 0600)
	if err := m.UpdateLoadedCertList(); err != nil {
		t.Fatal(err)
	}
	if got := m.CheckHostCertificate("ech.example.com", now); got.State != CertOK || !got.Valid {
		t.Fatalf("wildcard cert stored: %+v", got)
	}
}
