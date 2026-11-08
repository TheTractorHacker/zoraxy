package tlscert

import (
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"
)

// Upstream #403 (Uptime Kuma: "unable to verify the first certificate"): the intermediate certificates stored
// in the PEM file must be sent to the client, not only the leaf.
func TestServedCertificateIncludesChain(t *testing.T) {
	m := newTestManager(t)
	m.SetHostSpecificTlsBehavior(defaultHostSpecificTlsBehavior)
	leaf, key := selfPair(t, "kuma.example.com", time.Now().Add(48*time.Hour))
	inter, _ := selfPair(t, "Intermediate CA", time.Now().Add(48*time.Hour))
	put(t, filepath.Join(m.CertStore, "kuma.example.com.pem"), append(append([]byte{}, leaf...), inter...))
	put(t, filepath.Join(m.CertStore, "kuma.example.com.key"), key)
	if err := m.UpdateLoadedCertList(); err != nil {
		t.Fatal(err)
	}
	c, err := m.GetCert(&tls.ClientHelloInfo{ServerName: "kuma.example.com"})
	if err != nil || c == nil {
		t.Fatalf("GetCert: %v", err)
	}
	if len(c.Certificate) != 2 {
		t.Fatalf("served %d certificates, want leaf + intermediate", len(c.Certificate))
	}
}
