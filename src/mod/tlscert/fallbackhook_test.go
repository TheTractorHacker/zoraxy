package tlscert

import (
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
)

// OnFallbackServed is diagnostics: it fires for names that got the localhost or configured fallback certificate
// and does not change which certificate is served.
func TestOnFallbackServed(t *testing.T) {
	lg, _ := logger.NewFmtLogger()
	m, err := NewManagerWithTmp(t.TempDir(), t.TempDir(), lg)
	if err != nil {
		t.Fatal(err)
	}
	m.SetHostSpecificTlsBehavior(defaultHostSpecificTlsBehavior)
	c, k := selfPair(t, "app.example.com", time.Now().Add(48*time.Hour))
	put(t, filepath.Join(m.CertStore, "app.example.com.pem"), c)
	put(t, filepath.Join(m.CertStore, "app.example.com.key"), k)
	if err := m.UpdateLoadedCertList(); err != nil {
		t.Fatal(err)
	}
	var got []string
	m.OnFallbackServed = func(n string) { got = append(got, n) }

	serve := func(name string) []byte {
		cert, err := m.GetCert(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || cert == nil {
			t.Fatalf("GetCert(%q): %v", name, err)
		}
		return cert.Certificate[0]
	}
	hit := serve("app.example.com")
	if len(got) != 0 {
		t.Fatalf("a name with its own certificate must not be reported: %v", got)
	}
	a := serve("cloudflare-ech.com")
	b := serve("")
	if len(got) != 2 || got[0] != "cloudflare-ech.com" || got[1] != "" {
		t.Fatalf("fallback names = %q", got)
	}
	if string(a) != string(b) || string(a) == string(hit) {
		t.Fatalf("the served certificates must be the localhost fallback for both unknown names")
	}
	// the hook must not alter the choice: same answer with the hook removed
	m.OnFallbackServed = nil
	if string(serve("cloudflare-ech.com")) != string(a) {
		t.Fatalf("served certificate changed")
	}

	// a configured fallback certificate counts as the fallback as well
	fc, fk := selfPair(t, "fallback.example", time.Now().Add(48*time.Hour))
	put(t, filepath.Join(m.CertStore, "fallback.example.pem"), fc)
	put(t, filepath.Join(m.CertStore, "fallback.example.key"), fk)
	m.FallbackCert = "fallback.example"
	got = nil
	m.OnFallbackServed = func(n string) { got = append(got, n) }
	serve("unknown.test")
	serve("fallback.example") // valid for its own name: not a fallback miss
	if len(got) != 1 || got[0] != "unknown.test" {
		t.Fatalf("configured fallback: %q", got)
	}
}
