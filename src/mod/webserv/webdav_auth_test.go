package webserv

import (
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

func newTestWebDAV(t *testing.T) (*WebServer, *WebDAVServer, *database.Database) {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sys"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := db.NewTable("webserv"); err != nil {
		t.Fatal(err)
	}
	lg, _ := logger.NewFmtLogger()
	opts := &WebServerOptions{Sysdb: db, Logger: lg, UseCustomCredentials: true}
	return &WebServer{option: opts}, &WebDAVServer{options: opts}, db
}

func storedHash(t *testing.T, db *database.Database) string {
	t.Helper()
	var h string
	if err := db.Read("webserv", "webdavCustomPasswordHash", &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// New credentials are stored as salted argon2id and verify (fork #165).
func TestWebDAVCustomCredentialsSalted(t *testing.T) {
	ws, wd, db := newTestWebDAV(t)
	if err := ws.SetCustomCredentials("dav", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if h := storedHash(t, db); !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("password not stored as argon2id: %q", h)
	}
	if !wd.validateCustomCredentials("dav", "s3cret") {
		t.Fatal("correct credentials rejected")
	}
	if wd.validateCustomCredentials("dav", "wrong") || wd.validateCustomCredentials("other", "s3cret") {
		t.Fatal("bad credentials accepted")
	}
}

// A hash stored by an older version (unsalted) keeps working and is migrated.
func TestWebDAVLegacyHashMigrates(t *testing.T) {
	_, wd, db := newTestWebDAV(t)
	db.Write("webserv", "webdavCustomUsername", "dav")
	db.Write("webserv", "webdavCustomPasswordHash", auth.Hash("s3cret"))

	if wd.validateCustomCredentials("dav", "wrong") {
		t.Fatal("wrong password accepted")
	}
	if !auth.IsLegacyPasswordHash(storedHash(t, db)) {
		t.Fatal("failed login must not rewrite the hash")
	}
	if !wd.validateCustomCredentials("dav", "s3cret") {
		t.Fatal("legacy credential rejected")
	}
	if h := storedHash(t, db); !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("legacy hash not migrated: %q", h)
	}
	if !wd.validateCustomCredentials("dav", "s3cret") {
		t.Fatal("migrated credential rejected")
	}
}
