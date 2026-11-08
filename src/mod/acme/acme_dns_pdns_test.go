package acme_test

import (
	"testing"

	"imuslab.com/zoraxy/mod/acme"
)

// Upstream #766 / #917: PowerDNS "Host" is a *url.URL in lego and used to fail
// with "cannot unmarshal string into Go struct field Config.Host of type url.URL".
func TestDNSProviderPowerDNSHostURL(t *testing.T) {
	creds := `{"APIKey":"secret","Host":"http://127.0.0.1:1"}`
	p, err := acme.GetDnsChallengeProviderByName("pdns", creds, 120)
	if err != nil {
		t.Fatalf("pdns provider with a string Host URL must be accepted: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
}
