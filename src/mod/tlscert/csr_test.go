package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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
	"imuslab.com/zoraxy/mod/info/logger"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	lg, _ := logger.NewFmtLogger()
	return &Manager{CertStore: t.TempDir(), Logger: lg}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Internal CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, key}
}

// sign issues a certificate for a CSR PEM like an internal CA would
func (ca *testCA) sign(t *testing.T, csrPEM []byte, notAfter time.Time, dropSANs bool) []byte {
	b, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("bad CSR: %v", err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: csr.Subject, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if dropSANs {
		tpl.DNSNames = tpl.DNSNames[:1]
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
}

func TestCSRGenerateKeyTypesAndKeyStaysPrivate(t *testing.T) {
	m := newTestManager(t)
	for _, kt := range []string{"", "RSA2048", "EC256", "EC384"} {
		p, csrPEM, err := m.GenerateCSR(CSRRequest{CommonName: "svc.corp.example", SANs: []string{"svc.corp.example", "*.svc.corp.example", "10.1.2.3"}, KeyType: kt, Organization: "Corp"})
		if err != nil {
			t.Fatalf("%q: %v", kt, err)
		}
		b, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Fatalf("invalid CSR: %v", err)
		}
		if csr.Subject.CommonName != "svc.corp.example" || len(csr.DNSNames) != 2 || len(csr.IPAddresses) != 1 {
			t.Fatalf("subject/SAN wrong: %+v", csr)
		}
		switch kt {
		case "RSA2048", "":
			if k, ok := csr.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 2048 {
				t.Fatal("wrong key type")
			}
		case "EC384":
			if k, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P384() {
				t.Fatal("wrong key type")
			}
		}
		if runtime.GOOS != "windows" {
			st, err := os.Stat(m.pendingPath(p.ID, ".key"))
			if err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("pending key must be 0600: %v %v", err, st)
			}
		}
	}
	// the key is not in the live store and the pending folder is not mistaken for a certificate
	names, _ := m.ListCertDomains()
	if len(names) != 0 {
		t.Fatalf("pending requests must not appear as certificates: %v", names)
	}
	if len(m.ListPendingCSRs()) != 4 {
		t.Fatal("pending list wrong")
	}
	if _, _, err := m.GenerateCSR(CSRRequest{CommonName: "x", KeyType: "RSA1"}); err == nil {
		t.Fatal("bad key type must fail")
	}
	if _, _, err := m.GenerateCSR(CSRRequest{CommonName: ""}); err == nil {
		t.Fatal("empty common name must fail")
	}
	if _, _, err := m.GenerateCSR(CSRRequest{CommonName: "a.example", Name: "../evil"}); err == nil {
		t.Fatal("path traversal in name must fail")
	}
}

func TestCSRCompleteFlow(t *testing.T) {
	m := newTestManager(t)
	ca := newTestCA(t)
	p, csrPEM, err := m.GenerateCSR(CSRRequest{CommonName: "app.corp.example", SANs: []string{"app.corp.example", "api.corp.example"}, KeyType: "EC256"})
	if err != nil {
		t.Fatal(err)
	}

	// certificate for ANOTHER key must be refused
	other := newTestManager(t)
	_, otherCSR, _ := other.GenerateCSR(CSRRequest{CommonName: "app.corp.example", SANs: []string{"app.corp.example", "api.corp.example"}})
	wrong := ca.sign(t, otherCSR, time.Now().Add(time.Hour), false)
	if _, err := m.CompleteCSR(p.ID, wrong, false, false); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("key mismatch must be refused, got %v", err)
	}

	// expired
	if _, err := m.CompleteCSR(p.ID, ca.sign(t, csrPEM, time.Now().Add(-time.Second), false), false, false); err == nil {
		t.Fatal("expired certificate must be refused")
	}
	// missing SAN refused unless forced
	partial := ca.sign(t, csrPEM, time.Now().Add(time.Hour), true)
	if _, err := m.CompleteCSR(p.ID, partial, false, false); err == nil || !strings.Contains(err.Error(), "api.corp.example") {
		t.Fatalf("missing SAN must be reported, got %v", err)
	}
	// nothing installed so far
	if _, err := os.Stat(filepath.Join(m.CertStore, p.Name+".pem")); err == nil {
		t.Fatal("failed attempts must not install anything")
	}

	good := ca.sign(t, csrPEM, time.Now().Add(time.Hour), false)
	name, err := m.CompleteCSR(p.ID, good, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(m.CertStore, name+".pem"), filepath.Join(m.CertStore, name+".key")); err != nil {
		t.Fatalf("installed pair must load: %v", err)
	}
	info, err := acme.LoadCertInfoJSON(filepath.Join(m.CertStore, name+".json"))
	if err != nil || info.ManagedBy != "csr" || !info.IsExternallyManaged() || info.KeyType != "EC256" {
		t.Fatalf("metadata wrong: %+v %v", info, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(filepath.Join(m.CertStore, name+".key")); st.Mode().Perm() != 0o600 {
			t.Fatal("installed key must be 0600")
		}
	}
	if len(m.ListPendingCSRs()) != 0 {
		t.Fatal("pending request must be consumed")
	}
	if _, err := m.CompleteCSR(p.ID, good, false, false); err == nil {
		t.Fatal("a consumed request cannot be completed twice")
	}
}

func TestCSRNoOverwriteWithoutFlag(t *testing.T) {
	m := newTestManager(t)
	ca := newTestCA(t)
	os.WriteFile(filepath.Join(m.CertStore, "app.corp.example.pem"), []byte("existing"), 0o644)
	p, csrPEM, _ := m.GenerateCSR(CSRRequest{CommonName: "app.corp.example"})
	crt := ca.sign(t, csrPEM, time.Now().Add(time.Hour), false)
	if _, err := m.CompleteCSR(p.ID, crt, false, false); err == nil {
		t.Fatal("existing certificate must not be replaced silently")
	}
	if _, err := m.CompleteCSR(p.ID, crt, false, true); err != nil {
		t.Fatalf("overwrite=true must work: %v", err)
	}
}

func TestCSRIDValidation(t *testing.T) {
	m := newTestManager(t)
	for _, id := range []string{"../x", "", "zz", "0123456789abcdef/../.."} {
		if _, err := m.ReadCSR(id); err == nil {
			t.Errorf("id %q accepted", id)
		}
		if err := m.RemovePendingCSR(id); err == nil {
			t.Errorf("id %q accepted for delete", id)
		}
	}
}

// An invalid common name is reported as the common name (not as an alternative name) and a long value is shortened.
func TestCSRInvalidCommonNameMessage(t *testing.T) {
	m := newTestManager(t)
	long := "not a domain!! " + strings.Repeat("x", 200)
	_, _, err := m.GenerateCSR(CSRRequest{CommonName: long})
	if err == nil || !strings.Contains(err.Error(), "common name") || strings.Contains(err.Error(), "alternative") || len(err.Error()) > 120 {
		t.Fatalf("unexpected error for an invalid common name: %v", err)
	}
	_, _, err = m.GenerateCSR(CSRRequest{CommonName: "ok.example", SANs: []string{"bad san"}})
	if err == nil || !strings.Contains(err.Error(), "alternative name") {
		t.Fatalf("unexpected error for an invalid SAN: %v", err)
	}
}

func TestValidateUploadedPEM(t *testing.T) {
	m := newTestManager(t)
	p, csrPEM, err := m.GenerateCSR(CSRRequest{CommonName: "up.example"})
	if err != nil || p == nil {
		t.Fatal(err)
	}
	ca := newTestCA(t)
	leaf := ca.sign(t, csrPEM, time.Now().Add(time.Hour), false)
	if validateUploadedPEM("pub", leaf) != nil {
		t.Fatal("a PEM certificate must be accepted")
	}
	for _, bad := range []string{"garbage", "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----", ""} {
		if validateUploadedPEM("pub", []byte(bad)) == nil {
			t.Fatalf("%q accepted as a certificate", bad)
		}
		if validateUploadedPEM("pri", []byte(bad)) == nil {
			t.Fatalf("%q accepted as a private key", bad)
		}
	}
	key := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	if validateUploadedPEM("pri", []byte(key)) != nil {
		t.Fatal("a PEM private key must be accepted")
	}
}
