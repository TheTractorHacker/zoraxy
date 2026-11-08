package acme_test

import (
	"testing"

	"imuslab.com/zoraxy/mod/acme"
)

// Upstream #1156: lego's Plesk provider keeps baseURL in an unexported field, so
// the credentials sent by the UI were silently dropped ("plesk: missing server base URL").
func TestDNSProviderPleskBaseURL(t *testing.T) {
	creds := `{"baseURL":"https://plesk.example.com:8443","Username":"admin","Password":"pw"}`
	p, err := acme.GetDnsChallengeProviderByName("plesk", creds, 120)
	if err != nil {
		t.Fatalf("plesk provider with a baseURL must be accepted: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
}
