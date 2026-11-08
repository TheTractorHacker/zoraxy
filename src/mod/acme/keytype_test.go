package acme

import (
	"testing"

	"github.com/go-acme/lego/v5/certcrypto"
)

func TestParseKeyType(t *testing.T) {
	want := map[string]certcrypto.KeyType{
		"": certcrypto.RSA2048, "RSA2048": certcrypto.RSA2048, "rsa3072": certcrypto.RSA3072,
		"RSA4096": certcrypto.RSA4096, "EC256": certcrypto.EC256, " ec384 ": certcrypto.EC384,
	}
	for in, w := range want {
		got, err := ParseKeyType(in)
		if err != nil || got != w {
			t.Errorf("ParseKeyType(%q) = %v, %v; want %v", in, got, err, w)
		}
	}
	for _, bad := range []string{"RSA1024", "ed25519", "EC521", "dsa"} {
		if _, err := ParseKeyType(bad); err == nil {
			t.Errorf("ParseKeyType(%q) must fail", bad)
		}
	}
	for _, n := range KeyTypeNames {
		if _, err := ParseKeyType(n); err != nil {
			t.Errorf("advertised key type %s does not parse", n)
		}
	}
}

func TestResolveKeyTypePrecedence(t *testing.T) {
	a := newTestHandler(t)
	// request > stored cert info > preference > default
	if got := a.resolveKeyType("EC384", "RSA4096"); got != "EC384" {
		t.Errorf("request must win, got %s", got)
	}
	if got := a.resolveKeyType("", "RSA4096"); got != "RSA4096" {
		t.Errorf("stored must win over default, got %s", got)
	}
	if got := a.resolveKeyType("", ""); got != DefaultKeyType {
		t.Errorf("default must stay %s, got %s", DefaultKeyType, got)
	}
}

func TestKeyTypePreferenceRoundTrip(t *testing.T) {
	a := newDBTestHandler(t)
	if got := a.resolveKeyType("", ""); got != DefaultKeyType {
		t.Fatalf("got %s", got)
	}
	if err := a.SetDefaultKeyType("EC256"); err != nil {
		t.Fatal(err)
	}
	if got := a.resolveKeyType("", ""); got != "EC256" {
		t.Fatalf("preference not used, got %s", got)
	}
	if err := a.SetDefaultKeyType("bogus"); err == nil {
		t.Fatal("invalid default must be rejected")
	}
}
