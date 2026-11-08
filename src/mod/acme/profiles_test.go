package acme

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCAProfileCRUDAndSecrets(t *testing.T) {
	a := newDBTestHandler(t)
	id, err := a.SaveCAProfile(CAProfile{Name: "ZeroSSL", DirectoryURL: "https://acme.zerossl.com/v2/DV90", EABKid: "kid1", EABHmac: "s3cret"})
	if err != nil || id == "" {
		t.Fatalf("save: %v", err)
	}
	if _, err := a.SaveCAProfile(CAProfile{Name: "zerossl", DirectoryURL: "https://x.example/dir"}); err == nil {
		t.Error("duplicate name must be rejected")
	}
	if _, err := a.SaveCAProfile(CAProfile{Name: "bad", DirectoryURL: "ftp://x"}); err == nil {
		t.Error("bad URL must be rejected")
	}
	if _, err := a.SaveCAProfile(CAProfile{Name: "half", DirectoryURL: "https://x.example", EABKid: "k"}); err == nil {
		t.Error("EAB kid without HMAC must be rejected")
	}
	masked := a.ListCAProfiles()[0].Masked()
	js, _ := json.Marshal(masked)
	if strings.Contains(string(js), "s3cret") || masked.EABHmac != SecretMask {
		t.Fatalf("secret leaked in masked profile: %s", js)
	}
	// edit keeping the masked secret
	if _, err := a.SaveCAProfile(CAProfile{ID: id, Name: "ZeroSSL 2", DirectoryURL: "https://acme.zerossl.com/v2/DV90", EABKid: "kid1", EABHmac: SecretMask}); err != nil {
		t.Fatal(err)
	}
	p, _ := a.GetCAProfile(id)
	if p.EABHmac != "s3cret" || p.Name != "ZeroSSL 2" {
		t.Fatalf("masked save must keep the secret: %+v", p)
	}
	if err := a.DeleteCAProfile(id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetCAProfile(id); err == nil {
		t.Fatal("deleted profile still found")
	}
}

func TestDNSProfilesDefaultAndMasking(t *testing.T) {
	a := newDBTestHandler(t)
	id, err := a.SaveDNSProfile(DNSProfile{Name: "cf", Provider: "cloudflare", Credentials: `{"CloudflareApiToken":"tok-123","PropagationTimeout":"120"}`})
	if err != nil {
		t.Fatal(err)
	}
	if a.DefaultDNSProfileID() != "" {
		t.Fatal("no default expected")
	}
	if err := a.SetDefaultDNSProfile("nope"); err == nil {
		t.Fatal("unknown default must fail")
	}
	if err := a.SetDefaultDNSProfile(id); err != nil || a.DefaultDNSProfileID() != id {
		t.Fatalf("default not set: %v", err)
	}
	p, _ := a.GetDNSProfile(id)
	m := p.Masked()
	if strings.Contains(m.Credentials, "tok-123") || !strings.Contains(m.Credentials, SecretMask) || !strings.Contains(m.Credentials, "120") {
		t.Fatalf("bad masking: %s", m.Credentials)
	}
	// resubmitting the masked credentials keeps the token
	if _, err := a.SaveDNSProfile(DNSProfile{ID: id, Name: "cf", Provider: "cloudflare", Credentials: m.Credentials}); err != nil {
		t.Fatal(err)
	}
	p, _ = a.GetDNSProfile(id)
	if !strings.Contains(p.Credentials, "tok-123") {
		t.Fatalf("secret lost on masked save: %s", p.Credentials)
	}
	if err := a.DeleteDNSProfile(id); err != nil || a.DefaultDNSProfileID() != "" {
		t.Fatalf("delete must clear the default: %v", err)
	}
}

// A fake ACME directory that always fails lets us test the plumbing (options, events, log capture)
// without any CA. No real network is used.
func fakeBrokenCA(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fake CA says no", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestObtainOptionsErrorsAndFailureEvent(t *testing.T) {
	a := newDBTestHandler(t)
	var mu sync.Mutex
	var events []CertEvent
	a.OnEvent = func(e CertEvent) { mu.Lock(); events = append(events, e); mu.Unlock() }

	if _, err := a.ObtainCertWithOptions([]string{"a.example"}, "a", "x@example.com", "", "", false, false, 60, "", false, false, ObtainOptions{KeyType: "RSA1"}); err == nil || !strings.Contains(err.Error(), "key type") {
		t.Fatalf("bad key type must fail early, got %v", err)
	}
	if _, err := a.ObtainCertWithOptions([]string{"a.example"}, "a", "x@example.com", "", "", false, false, 60, "", false, false, ObtainOptions{CAProfileID: "missing"}); err == nil {
		t.Fatal("unknown CA profile must fail")
	}

	srv := fakeBrokenCA(t)
	id, _ := a.SaveCAProfile(CAProfile{Name: "fake", DirectoryURL: srv.URL + "/dir", SkipTLS: true})
	ok, lines, err := a.ObtainCertCapture([]string{"a.example"}, "a", "x@example.com", "", "", false, false, 60, "", false, false, ObtainOptions{CAProfileID: id, KeyType: "EC256"})
	if ok || err == nil {
		t.Fatal("expected failure against the fake CA")
	}
	if len(lines) == 0 {
		t.Error("operation log must be captured")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("every failed attempt must emit an event, got %+v", events)
	}
	last := events[len(events)-1]
	if last.Type != EventCertFailed || last.CertName != "a" || last.Error == "" {
		t.Fatalf("bad failure event: %+v", last)
	}
}

func TestRenewKeepsStoredSettingsAndSkipsExternal(t *testing.T) {
	a := newDBTestHandler(t)
	info := CertificateInfoJSON{AcmeName: "custom", KeyType: "EC384", CAProfileID: "p1", ManagedBy: "mapdir"}
	if !info.IsExternallyManaged() {
		t.Fatal("mapdir must count as external")
	}
	if (&CertificateInfoJSON{ManagedBy: "acme"}).IsExternallyManaged() || (&CertificateInfoJSON{}).IsExternallyManaged() {
		t.Fatal("acme / legacy metadata must stay renewable")
	}
	// old metadata files (no new fields) still parse and resolve to the default key type
	old := filepath.Join(a.CertStorePath, "old.json")
	os.WriteFile(old, []byte(`{"acme_name":"Let's Encrypt","dns":false}`), 0o644)
	got, err := LoadCertInfoJSON(old)
	if err != nil || a.resolveKeyType("", got.KeyType) != DefaultKeyType {
		t.Fatalf("legacy metadata broke: %v", err)
	}
}

func TestStagingCAIsBuiltin(t *testing.T) {
	url, err := loadCAApiServerFromName("Let's Encrypt (Staging)", false)
	if err != nil || !strings.Contains(url, "acme-staging-v02") {
		t.Fatalf("staging CA missing: %v %s", err, url)
	}
	if !IsSupportedCA("Let's Encrypt (Staging)", true) {
		t.Fatal("staging CA must also be supported in -acmetestmode")
	}
}
