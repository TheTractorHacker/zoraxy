package acme

import (
	"strings"
	"testing"
)

// Upstream #1193 (b): rotating the DNS API token must not require re-issuing the certificate. A DNS credential
// profile is edited in place; certificates reference the profile by ID so the next renewal uses the new secret.
func TestDNSProfileCredentialRotation(t *testing.T) {
	a := newDBTestHandler(t)
	id, err := a.SaveDNSProfile(DNSProfile{Name: "cf", Provider: "cloudflare", Credentials: `{"CloudflareApiToken":"old-token","PropagationTimeout":"120"}`})
	if err != nil {
		t.Fatal(err)
	}
	// Rotate only the secret; the unchanged field comes back masked from the UI and keeps its value.
	p, _ := a.GetDNSProfile(id)
	masked := p.Masked().Credentials
	rotated := strings.Replace(masked, SecretMask, "new-token", 1)
	if rotated == masked {
		t.Fatalf("masked credentials %q do not contain the mask", masked)
	}
	if _, err := a.SaveDNSProfile(DNSProfile{ID: id, Name: "cf", Provider: "cloudflare", Credentials: rotated}); err != nil {
		t.Fatal(err)
	}
	p, _ = a.GetDNSProfile(id)
	if !strings.Contains(p.Credentials, "new-token") || strings.Contains(p.Credentials, "old-token") {
		t.Fatalf("token not rotated: %s", p.Credentials)
	}
	if !strings.Contains(p.Credentials, "120") {
		t.Fatalf("unrelated field lost during rotation: %s", p.Credentials)
	}
}
