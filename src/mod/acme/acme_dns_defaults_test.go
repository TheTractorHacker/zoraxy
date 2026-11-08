package acme_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/acme"
)

// The certificate UI sends every field of the selected DNS provider, empty ones as "". An empty value
// used to override the provider's default (PowerDNS ServerName "localhost" became "", so the API path
// /servers//zones was requested), which made providers with optional fields unusable unless every
// field was filled in (upstream #681).
func TestDNSProviderEmptyFieldsKeepProviderDefaults(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	creds := `{"APIKey":"k","Host":"` + srv.URL + `","ServerName":"","APIVersion":null,"PropagationTimeout":"","PollingInterval":""}`
	p, err := acme.GetDnsChallengeProviderByName("pdns", creds, 120)
	if err != nil || p == nil {
		t.Fatalf("provider creation failed: %v", err)
	}
	type presenter interface {
		Present(ctx context.Context, domain, token, keyAuth string) error
	}
	pr, ok := p.(presenter)
	if !ok {
		t.Fatalf("provider %T has no Present(ctx, ...)", p)
	}
	_ = pr.Present(context.Background(), "example.com", "tok", "auth")

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, path := range paths {
		if strings.Contains(path, "/servers//") {
			t.Fatalf("empty ServerName reached the PowerDNS API: %v", paths)
		}
		if strings.Contains(path, "/servers/localhost/") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected requests below /servers/localhost/, got %v", paths)
	}
}
