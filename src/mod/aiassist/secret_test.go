package aiassist

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeKey = "sk-ant-FAKEKEY-0123456789abcdefWXYZ"

func TestVaultSealRoundTripAndPerms(t *testing.T) {
	dir := t.TempDir()
	v := NewVault(dir)
	if err := v.Set(fakeKey); err != nil {
		t.Fatal(err)
	}
	got, ok, err := v.Get()
	if err != nil || !ok || got != fakeKey {
		t.Fatalf("round trip: %q %v %v", got, ok, err)
	}
	for _, f := range []string{keyFileName, sealedFileName} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if strings.Contains(string(b), fakeKey) || strings.Contains(string(b), "FAKEKEY") {
			t.Errorf("%s holds the plain key", f)
		}
	}
	set, last4, err := v.Hint()
	if err != nil || !set || last4 != "WXYZ" {
		t.Fatalf("hint %v %q %v", set, last4, err)
	}
}

func TestVaultTamperDetection(t *testing.T) {
	dir := t.TempDir()
	v := NewVault(dir)
	if err := v.Set(fakeKey); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, sealedFileName)
	b, _ := os.ReadFile(p)
	for _, mod := range []func([]byte) []byte{
		func(b []byte) []byte { c := append([]byte{}, b...); c[len(c)/2] ^= 1; return c },
		func(b []byte) []byte { return b[:len(b)-6] },
		func(b []byte) []byte { return []byte("not base64 !!") },
	} {
		os.WriteFile(p, mod(b), 0o600)
		if _, _, err := v.Get(); err != ErrTampered {
			t.Fatalf("expected ErrTampered, got %v", err)
		}
	}
	// a different install key must not open the blob
	os.WriteFile(p, b, 0o600)
	os.Remove(filepath.Join(dir, keyFileName))
	if _, _, err := v.Get(); err != ErrTampered {
		t.Fatalf("missing key file: %v", err)
	}
}

func TestPseudonymStableAndPerInstall(t *testing.T) {
	a, b := NewVault(t.TempDir()), NewVault(t.TempDir())
	if a.Pseudonym("ip", "203.0.113.9") != a.Pseudonym("ip", "203.0.113.9") {
		t.Fatal("not stable")
	}
	if a.Pseudonym("ip", "203.0.113.9") == b.Pseudonym("ip", "203.0.113.9") {
		t.Fatal("same label on two installs")
	}
	if !strings.HasPrefix(a.Pseudonym("ip", "1.2.3.4"), "ip-") {
		t.Fatal("format")
	}
}

func TestKeyNeverInViewExportsErrorsOrAudit(t *testing.T) {
	var audit []string
	s := newTestService(t, nil, func(e, d string) { audit = append(audit, e+" "+d) })
	st := localSettings("http://127.0.0.1:1")
	if _, err := s.Save(SettingsUpdate{Settings: st, APIKey: fakeKey}); err != nil {
		t.Fatal(err)
	}
	v, _ := json.Marshal(s.View())
	if strings.Contains(string(v), fakeKey) || strings.Contains(string(v), "FAKEKEY") {
		t.Fatalf("view leaks the key: %s", v)
	}
	if !strings.Contains(string(v), `"key_set":true`) || !strings.Contains(string(v), "WXYZ") {
		t.Fatalf("view: %s", v)
	}
	// a failing call (connection refused) must not put the key into the error or the audit log
	s.Ack(FeatureExplain)
	_, err := s.Test(context.Background())
	if err == nil {
		t.Fatal("expected failure")
	}
	all := err.Error() + strings.Join(audit, "\n")
	if strings.Contains(all, fakeKey) {
		t.Fatalf("key leaked: %s", all)
	}
	// the key file is excluded from backups
	if !IsSecretFile("aiassist/ai.key") || !IsSecretFile("aiassist/apikey.sealed") || IsSecretFile("aiassist/settings.json") {
		t.Fatal("IsSecretFile")
	}
	// settings.json holds no key material
	b, _ := os.ReadFile(filepath.Join(s.store.Dir(), "settings.json"))
	if strings.Contains(string(b), "FAKEKEY") || strings.Contains(string(b), "api_key") {
		t.Fatalf("settings.json: %s", b)
	}
}
