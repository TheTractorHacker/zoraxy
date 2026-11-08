package uptime

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Upstream #971: an upstream with a self-signed certificate must be reported online
// when "skip verification" is set, and offline when it is not.
func TestGetWebsiteStatusSelfSignedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := &Monitor{Config: &Config{}}

	code, err := m.getWebsiteStatus(server.URL, true, 3*time.Second)
	if err != nil || code != http.StatusOK {
		t.Fatalf("skip verification: got code=%d err=%v, want 200", code, err)
	}

	if code, err := m.getWebsiteStatus(server.URL, false, 3*time.Second); err == nil && code == http.StatusOK {
		t.Fatal("without skip verification a self-signed certificate must not be reported healthy")
	}
}
