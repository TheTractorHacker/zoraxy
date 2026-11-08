package tlscert

import (
	"os"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
)

// Upstream #1193: deleting a certificate must also drop its ACME metadata file and
// notify other modules, otherwise a stale <name>.json overrides the challenge type
// of the next certificate issued under the same name.
func TestRemoveCertDeletesAcmeMetadata(t *testing.T) {
	dir := t.TempDir()
	for _, ext := range []string{".pem", ".key", ".json"} {
		if err := os.WriteFile(filepath.Join(dir, "_.example.com"+ext), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(dir, "keep.example.com.json")
	os.WriteFile(other, []byte("x"), 0600)

	lg, _ := logger.NewFmtLogger()
	m := &Manager{CertStore: dir, Logger: lg}
	removed := ""
	m.OnCertRemoved = func(name string) { removed = name }

	if err := m.RemoveCert("_.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".pem", ".key", ".json"} {
		if _, err := os.Stat(filepath.Join(dir, "_.example.com"+ext)); err == nil {
			t.Errorf("_.example.com%s was not removed", ext)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("metadata of another certificate must be kept: %v", err)
	}
	if removed != "_.example.com" {
		t.Errorf("OnCertRemoved called with %q", removed)
	}
}
