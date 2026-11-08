package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func testCertPEM(t *testing.T, cn string) (certPEM []byte, pubPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// Upstream #459: a PEM bundle whose first block is not a certificate (e.g. a
// PUBLIC KEY block in front of the chain) showed "Unknown" for the expiry.
func TestFirstCertificateSkipsLeadingNonCertBlocks(t *testing.T) {
	certPEM, pubPEM := testCertPEM(t, "example.com")
	bundle := append(append([]byte{}, pubPEM...), certPEM...)

	cert := firstCertificate(bundle)
	if cert == nil {
		t.Fatal("expected the certificate behind the PUBLIC KEY block to be found")
	}
	if cert.Subject.CommonName != "example.com" {
		t.Fatalf("unexpected CN %q", cert.Subject.CommonName)
	}
	if firstCertificate(certPEM) == nil {
		t.Fatal("plain certificate must still parse")
	}
	if firstCertificate(pubPEM) != nil || firstCertificate([]byte("garbage")) != nil {
		t.Fatal("no certificate present, expected nil")
	}
}
