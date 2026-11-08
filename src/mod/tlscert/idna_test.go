package tlscert

import (
	"path/filepath"
	"testing"
	"time"
)

// Upstream #458: browsers send the punycode form in SNI. A certificate issued for the IDN (SAN in xn-- form)
// and one stored under the Unicode spelling the user typed must both be found.
func TestGetCertificateByHostnameIDN(t *testing.T) {
	m := newTestManager(t)
	m.SetHostSpecificTlsBehavior(defaultHostSpecificTlsBehavior)

	c, k := selfPair(t, "xn--bcher-kva.example", time.Now().Add(48*time.Hour))
	put(t, filepath.Join(m.CertStore, "shop.pem"), c)
	put(t, filepath.Join(m.CertStore, "shop.key"), k)
	if err := m.UpdateLoadedCertList(); err != nil {
		t.Fatal(err)
	}
	for _, sni := range []string{"xn--bcher-kva.example", "XN--BCHER-KVA.EXAMPLE", "bücher.example"} {
		pub, _, err := m.GetCertificateByHostname(sni)
		if err != nil || filepath.Base(pub) != "shop.pem" {
			t.Errorf("SNI %q resolved to %q (%v), want shop.pem", sni, pub, err)
		}
	}

	// A certificate file named after the Unicode spelling (legacy filename matching) is found for the punycode SNI.
	m2 := newTestManager(t)
	m2.SetHostSpecificTlsBehavior(defaultHostSpecificTlsBehavior)
	c2, k2 := selfPair(t, "other.example", time.Now().Add(48*time.Hour))
	put(t, filepath.Join(m2.CertStore, "münchen.example.pem"), c2)
	put(t, filepath.Join(m2.CertStore, "münchen.example.key"), k2)
	pub, _, _ := m2.GetCertificateByHostname("xn--mnchen-3ya.example")
	if filepath.Base(pub) != "münchen.example.pem" {
		t.Errorf("legacy unicode filename not matched for punycode SNI: %q", pub)
	}
}
