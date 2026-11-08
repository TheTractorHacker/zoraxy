package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationsUseConfiguredConfDir(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	conf := filepath.Join(cwd, "custom-conf")
	os.MkdirAll(filepath.Join(conf, "proxy"), 0o775)
	os.MkdirAll(filepath.Join(conf, "certs"), 0o775)
	os.WriteFile(filepath.Join(conf, "proxy", "a.config"), []byte(`{}`), 0o664)
	os.WriteFile(filepath.Join(conf, "version"), []byte("307"), 0o664)
	os.WriteFile(filepath.Join(conf, "certs", "example.com.json"), []byte(`{"recursive_ns":true}`), 0o664)

	RunConfigUpdateInDir(conf, 0, 335)

	if _, err := os.Stat("conf"); err == nil {
		t.Fatal("migration created a stray ./conf")
	}
	v, _ := os.ReadFile(filepath.Join(conf, "version"))
	if strings.TrimSpace(string(v)) != "335" {
		t.Fatalf("version file = %q, want 335", v)
	}
	for _, d := range []string{"proxy.old", "proxy-314.old", "proxy-321.old"} {
		if st, err := os.Stat(filepath.Join(conf, d)); err != nil || !st.IsDir() {
			t.Errorf("expected backup folder %s in the configured conf dir", d)
		}
	}
	js, _ := os.ReadFile(filepath.Join(conf, "certs", "example.com.json"))
	if strings.Contains(string(js), `"recursive_ns"`) {
		t.Errorf("cert json was not migrated: %s", js)
	}
}

func TestFirstTimeInitWritesVersionInConfDir(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	conf := filepath.Join(cwd, "elsewhere")
	RunConfigUpdateInDir(conf, 0, 335)
	if v, err := os.ReadFile(filepath.Join(conf, "version")); err != nil || string(v) != "335" {
		t.Fatalf("version file: %q %v", v, err)
	}
	if _, err := os.Stat("conf"); err == nil {
		t.Fatal("stray ./conf created")
	}
}

func TestFindStrayDefaultPaths(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	os.MkdirAll("conf", 0o775)
	os.MkdirAll("tmp", 0o775)
	got := FindStrayDefaultPaths(map[string][2]string{
		"conf": {"./conf", "/data/conf"},
		"tmp":  {"./tmp", "./tmp"},     //same path: not stray
		"log":  {"./log", "/data/log"}, //default does not exist
	})
	if len(got) != 1 || got[0].Flag != "conf" {
		t.Fatalf("got %+v", got)
	}
	if len(FindStrayDefaultPaths(map[string][2]string{"conf": {"./conf", "conf"}})) != 0 {
		t.Fatal("equivalent path reported as stray")
	}
}
