package acme

import (
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

// newDBTestHandler returns a handler backed by a real temporary database and cert store.
func newDBTestHandler(t *testing.T) *ACMEHandler {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "test.db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	l, _ := logger.NewFmtLogger()
	h := NewACME("45678", db, l, true, 0o600, 0o644)
	h.CertStorePath = t.TempDir()
	return h
}
