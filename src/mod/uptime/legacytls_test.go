package uptime

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Upstream #971: an IPMI/BMC web UI usually has a self-signed certificate AND only offers legacy RSA key
// exchange cipher suites (Go's client does not offer those by default), which shows up as
// "remote error: tls: handshake failure". With "skip verification" on, the monitor has to be able to talk
// to such a device, the same way a browser does.
func TestGetWebsiteStatusLegacyCipherUpstreamWithSkipVerify(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}
	server.StartTLS()
	defer server.Close()

	m := &Monitor{Config: &Config{}}
	code, err := m.getWebsiteStatus(server.URL, true, 3*time.Second)
	if err != nil || code != http.StatusOK {
		t.Fatalf("legacy cipher upstream with skip verification: code=%d err=%v", code, err)
	}
	// Without the option, the monitor stays strict.
	if code, err := m.getWebsiteStatus(server.URL, false, 3*time.Second); err == nil && code == http.StatusOK {
		t.Fatal("strict mode must not accept the self-signed legacy upstream")
	}
}
