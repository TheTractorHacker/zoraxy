package acme_test

import (
	"testing"

	"imuslab.com/zoraxy/mod/acme"
)

// Upstream #922: the INWX DNS challenge failed with "[id] expected type int, got unconvertible type string"
// because INWX changed its API to string record IDs. The fix lives in lego/goinwx (record IDs are strings in
// the vendored version); this test pins that the provider can be built from the UI credentials.
func TestDNSProviderINWX(t *testing.T) {
	p, err := acme.GetDnsChallengeProviderByName("inwx", `{"Username":"user","Password":"pw","Sandbox":false,"TTL":300}`, 120)
	if err != nil || p == nil {
		t.Fatalf("inwx provider: %v", err)
	}
}
