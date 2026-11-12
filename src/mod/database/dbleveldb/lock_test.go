package dbleveldb_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/database/dbleveldb"
)

// LevelDB takes a non-blocking lock: a second open fails at once (it never hangs) and
// reports the same LockedError as BoltDB, with the same hints.
func TestSecondOpenReportsLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leveldbdir")
	first, err := dbleveldb.NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	start := time.Now()
	_, err = dbleveldb.NewDB(path)
	var locked *dbinc.LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("want *dbinc.LockedError, got %T: %v", err, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("a locked LevelDB must fail at once")
	}
	if !strings.Contains(err.Error(), "sudo lsof "+path) || !strings.Contains(err.Error(), "grep [z]oraxy") {
		t.Fatalf("message lacks the hints:\n%v", err)
	}
	//the first handle still works
	if err := first.Write("t", "k", "v"); err != nil {
		t.Fatal(err)
	}
}
