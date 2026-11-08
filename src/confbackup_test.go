package main

import (
	"archive/zip"
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
)

func setupBackupTest(t *testing.T) (confDir string, dbFile string) {
	t.Helper()
	oldConf, oldDB, oldLog := CONF_FOLDER, *path_database, SystemWideLogger
	t.Cleanup(func() { CONF_FOLDER, *path_database, SystemWideLogger = oldConf, oldDB, oldLog })
	SystemWideLogger, _ = logger.NewFmtLogger()
	root := t.TempDir()
	// deliberately NOT ./conf: installs started with -conf must back up and restore too
	confDir = filepath.Join(root, "custom-config")
	dbFile = filepath.Join(root, "my.db")
	CONF_FOLDER = confDir
	*path_database = dbFile
	os.MkdirAll(filepath.Join(confDir, "proxy"), 0o775)
	os.WriteFile(filepath.Join(confDir, "proxy", "a.config"), []byte("rule-a"), 0o644)
	os.WriteFile(filepath.Join(confDir, "version"), []byte("335"), 0o644)
	return
}

func uploadZip(t *testing.T, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "backup.zip")
	fw.Write(data)
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/conf/import", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	ImportConfigFromZip(w, r)
	return w
}

func TestConfigExportImportRoundTripWithCustomConfFolder(t *testing.T) {
	confDir, _ := setupBackupTest(t)

	w := httptest.NewRecorder()
	ExportConfigAsZip(w, httptest.NewRequest(http.MethodGet, "/api/conf/export", nil))
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("export is not a valid zip: %v", err)
	}
	names := []string{}
	for _, f := range zr.File {
		names = append(names, f.Name)
		if !strings.HasPrefix(f.Name, "conf/") {
			t.Fatalf("entry %q must be stored under conf/", f.Name)
		}
	}

	os.RemoveAll(confDir)
	res := uploadZip(t, w.Body.Bytes())
	if res.Code != http.StatusOK {
		t.Fatalf("import failed: %d %s (entries %v)", res.Code, res.Body.String(), names)
	}
	got, err := os.ReadFile(filepath.Join(confDir, "proxy", "a.config"))
	if err != nil || string(got) != "rule-a" {
		t.Fatalf("config not restored into the -conf folder: %v %q", err, got)
	}
}

func TestInvalidConfigZipKeepsExistingConfig(t *testing.T) {
	confDir, _ := setupBackupTest(t)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("not-a-backup/readme.txt")
	f.Write([]byte("x"))
	zw.Close()

	res := uploadZip(t, buf.Bytes())
	if res.Code == http.StatusOK {
		t.Fatal("an invalid archive must be rejected")
	}
	got, err := os.ReadFile(filepath.Join(confDir, "proxy", "a.config"))
	if err != nil || string(got) != "rule-a" {
		t.Fatalf("existing config was destroyed by a rejected import: %v %q", err, got)
	}
}

func TestConfigZipRejectsTraversal(t *testing.T) {
	confDir, _ := setupBackupTest(t)
	for _, name := range []string{"conf/../../evil.txt", "conf/../evil.txt", "/etc/passwd", "conf/"} {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create(name)
		f.Write([]byte("x"))
		zw.Close()
		if res := uploadZip(t, buf.Bytes()); res.Code == http.StatusOK && name != "conf/" {
			t.Errorf("%q accepted", name)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(confDir), "evil.txt")); err == nil {
		t.Fatal("zip slip wrote outside of the config folder")
	}
	if _, err := os.Stat(filepath.Join(confDir, "proxy", "a.config")); err != nil {
		t.Fatalf("config removed by rejected archives: %v", err)
	}
}
