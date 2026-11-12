//go:build linux

package instance

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// a /proc file that never answers (simulated with a FIFO nobody writes to) must time out, not hang the doctor
func TestReadProcTimesOut(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "locks"), 0o600); err != nil {
		t.Skip("mkfifo unavailable")
	}
	old := readTimeout
	readTimeout = 200 * time.Millisecond
	defer func() { readTimeout = old }()
	start := time.Now()
	if _, err := readProc(dir, "locks"); err != errReadTimeout {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("took too long")
	}
	// and the lock lookup degrades to an error instead of hanging
	db := filepath.Join(dir, "sys.db")
	if err := os.WriteFile(db, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := findLockHolders(dir, db); err == nil || err == ErrNoHolder {
		t.Fatalf("got %v", err)
	}
}
