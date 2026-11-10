package aiassist

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCheckIPEmbeddedIPv4Forms(t *testing.T) {
	// transition forms carrying a metadata, link-local or reserved IPv4 are refused in every mode
	always := []string{
		"64:ff9b::a9fe:a9fe", "64:ff9b::169.254.169.254", "64:ff9b::a9fe:1",
		"2002:a9fe:a9fe::", "2002:a9fe:a9fe:1::5", "2002:6464:64c8::", // 100.100.100.200
		"::a9fe:a9fe", "::169.254.169.254", "::0.0.0.5", "::f000:1",
		"::ffff:a9fe:a9fe",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
		"64:ff9b:1::1", "64:ff9b:1:ffff::a9fe:a9fe",
	}
	for _, a := range always {
		for _, allow := range []bool{false, true} {
			if checkIP(netip.MustParseAddr(a), allow) == nil {
				t.Errorf("%s must be refused (allowLocal=%v)", a, allow)
			}
		}
	}
	// embedded loopback / private: only with the local option
	local := []string{"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::", "2002:c0a8:101::", "::7f00:1", "::a00:1", "64:ff9b::6440:1"}
	for _, a := range local {
		if checkIP(netip.MustParseAddr(a), false) == nil {
			t.Errorf("%s must be refused without the local option", a)
		}
		if err := checkIP(netip.MustParseAddr(a), true); err != nil {
			t.Errorf("%s with local option: %v", a, err)
		}
	}
	// embedded public IPv4 and the plain ::1 / :: keep their old behaviour
	for _, a := range []string{"64:ff9b::808:808", "2002:808:808::"} {
		if err := checkIP(netip.MustParseAddr(a), false); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	if checkIP(netip.MustParseAddr("::"), true) == nil || checkIP(netip.MustParseAddr("::1"), false) == nil || checkIP(netip.MustParseAddr("::1"), true) != nil {
		t.Error("::/::1 behaviour changed")
	}
}

func TestEndpointAndDialRefuseEmbeddedForms(t *testing.T) {
	if checkLiteralHost("64:ff9b::a9fe:a9fe", false) == nil || checkLiteralHost("2002:a9fe:a9fe::", true) == nil {
		t.Fatal("literal hosts of embedded form accepted at settings time")
	}
	old := lookupIP
	defer func() { lookupIP = old }()
	for _, a := range []string{"64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "::a9fe:a9fe", "2001:0:4136:e378:8000:63bf:3fff:fdd2"} {
		lookupIP = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(a)}, nil
		}
		for _, allow := range []bool{false, true} {
			err := get(t, newGuardedClient(allow, 3*time.Second), "http://dns.example.com:9")
			if err == nil || !strings.Contains(err.Error(), "refused") {
				t.Errorf("DNS answer %s (allow=%v) was not refused by the guard: %v", a, allow, err)
			}
		}
	}
}
