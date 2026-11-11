package tlscert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
)

func servedCN(t *testing.T, m *Manager, host string) string {
	t.Helper()
	pub, _, err := m.GetCertificateByHostname(host)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c.Subject.CommonName
}

func newPrefManager(t *testing.T, behavior *HostSpecificTlsBehavior) *Manager {
	t.Helper()
	dir := t.TempDir()
	lg, _ := logger.NewFmtLogger()
	m, err := NewManagerWithTmp(filepath.Join(dir, "certs"), filepath.Join(dir, "tmp"), lg)
	if err != nil {
		t.Fatal(err)
	}
	//only a covers test.local, so the automatic choice is a (the scan order of several matches is not defined)
	//and only the preference can make b the served certificate
	for n, sans := range map[string][]string{"a": {"test.local"}, "b": {"b.other.local", "*.wild.local"}} {
		if err := m.GenerateSelfSignedCertificate(n+".test.local", sans, n+".pem", n+".key"); err != nil {
			t.Fatal(err)
		}
	}
	m.UpdateLoadedCertList()
	m.SetHostSpecificTlsBehavior(func(string) (*HostSpecificTlsBehavior, error) { return behavior, nil })
	return m
}

// PreferredCertificate is honoured only when SNI matching is disabled for the rule (documented in the form).
func TestPreferredCertificateOnlyHonouredWithoutSNI(t *testing.T) {
	prefs := map[string]string{"test.local": "b"}
	m := newPrefManager(t, &HostSpecificTlsBehavior{DisableSNI: false, PreferredCertificate: prefs})
	if got := servedCN(t, m, "test.local"); got != "a.test.local" {
		t.Fatalf("with SNI enabled the preference must be ignored (today's behaviour), served %s", got)
	}
	m = newPrefManager(t, &HostSpecificTlsBehavior{DisableSNI: true, PreferredCertificate: prefs})
	if got := servedCN(t, m, "test.local"); got != "b.test.local" {
		t.Fatalf("with SNI disabled the preferred certificate must be served, got %s", got)
	}
}

func TestPreferredCertificateWildcardAndIDNKeys(t *testing.T) {
	prefs := map[string]string{"*.wild.local": "b", "bücher.de": "a"}
	m := newPrefManager(t, &HostSpecificTlsBehavior{DisableSNI: true, PreferredCertificate: prefs})
	if got := servedCN(t, m, "x.wild.local"); got != "b.test.local" {
		t.Errorf("a wildcard key must apply to names it matches, got %s", got)
	}
	if got := preferredCertificateFor(prefs, "xn--bcher-kva.de"); got != "a" {
		t.Errorf("a Unicode key must apply to the punycode name, got %q", got)
	}
	//the router matches a wildcard rule with filepath.Match, so the key follows the same rule
	if got := preferredCertificateFor(prefs, "other.local"); got != "" {
		t.Errorf("a name no key matches has no preference, got %q", got)
	}
}

// A stored certificate whose name contains two dots in a row is a plain file name and can be chosen.
func TestCertExistsAllowsDoubleDotInsideName(t *testing.T) {
	m := newPrefManager(t, GetDefaultHostSpecificTlsBehavior())
	for _, ext := range []string{".pem", ".key"} {
		b, err := os.ReadFile(filepath.Join(m.CertStore, "a"+ext))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m.CertStore, "foo..bar"+ext), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.CertExists("foo..bar"); err != nil {
		t.Errorf("foo..bar must be accepted: %v", err)
	}
	for _, bad := range []string{".", "..", "../foo..bar"} {
		if err := m.CertExists(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestCertExists(t *testing.T) {
	m := newPrefManager(t, GetDefaultHostSpecificTlsBehavior())
	if err := m.CertExists("a"); err != nil {
		t.Errorf("a stored certificate must exist: %v", err)
	}
	for _, bad := range []string{"", "nope", "../a", "a/../a", "a\\b", ".."} {
		if err := m.CertExists(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}
