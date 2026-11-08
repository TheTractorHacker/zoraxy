package tlscert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewManagerWithTmpUsesConfiguredFolder(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	tmp := filepath.Join(cwd, "mytmp")
	m, err := NewManagerWithTmp(filepath.Join(cwd, "certs"), tmp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "localhost.pem")); err != nil {
		t.Fatalf("localhost cert not in -tmp: %v", err)
	}
	if _, err := os.Stat("tmp"); err == nil {
		t.Fatal("stray ./tmp created")
	}
	pub, _, _ := m.GetCertificateByHostname("unknown.example")
	if pub != filepath.Join(tmp, "localhost.pem") {
		t.Fatalf("fallback cert path = %q", pub)
	}
}
