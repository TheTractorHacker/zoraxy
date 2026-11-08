package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/offline"
)

func writeCert(t *testing.T, dir, name string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name + ".example.com"},
		DNSNames: []string{name + ".example.com"}, NotBefore: time.Now().Add(-72 * time.Hour), NotAfter: notAfter}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	os.WriteFile(filepath.Join(dir, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func newRenewer(t *testing.T) (*AutoRenewer, *int32) {
	h := newDBTestHandler(t)
	var issued int32
	h.beforeIssue = func() error { atomic.AddInt32(&issued, 1); return errors.New("stop here, test") }
	r := &AutoRenewer{CertFolder: h.CertStorePath, AcmeHandler: h, EarlyRenewDays: 30, Logger: h.Logger,
		RenewerConfig: &AutoRenewConfig{Enabled: true, Email: "a@example.org", RenewAll: true}}
	writeCert(t, h.CertStorePath, "old", time.Now().Add(-time.Hour))
	return r, &issued
}

func TestBackgroundRenewSkippedOffline(t *testing.T) {
	r, issued := newRenewer(t)

	offline.Set(true)
	defer offline.Set(false)
	r.backgroundCheck()
	if atomic.LoadInt32(issued) != 0 {
		t.Fatal("offline mode must not start unattended issuance")
	}

	// explicit "renew now" still reaches the issuer
	r.CheckAndRenewCertificates()
	if atomic.LoadInt32(issued) != 1 {
		t.Fatal("explicit renewal must keep working in offline mode")
	}

	offline.Set(false)
	r.backgroundCheck()
	if atomic.LoadInt32(issued) != 2 {
		t.Fatal("online background run must renew")
	}
}

func TestExternallyManagedCertIsNotRenewed(t *testing.T) {
	r, issued := newRenewer(t)
	info := CertificateInfoJSON{ManagedBy: "mapdir", Source: "/etc/ssl/x"}
	if err := writeInfo(r.CertFolder, "old", info); err != nil {
		t.Fatal(err)
	}
	r.CheckAndRenewCertificates()
	if atomic.LoadInt32(issued) != 0 {
		t.Fatal("externally managed certificate must not be renewed")
	}
	if _, err := r.RenewOne("old"); !errors.Is(err, errExternallyManaged) {
		t.Fatalf("RenewOne must refuse externally managed certs, got %v", err)
	}
}

func writeInfo(dir, name string, info CertificateInfoJSON) error {
	return SaveCertInfoJSON(filepath.Join(dir, name+".json"), &info, 0o644)
}
