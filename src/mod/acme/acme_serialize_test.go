package acme

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
)

func newTestHandler(t *testing.T) *ACMEHandler {
	t.Helper()
	l, _ := logger.NewFmtLogger()
	return NewACME("45678", nil, l, true, 0o600, 0o644)
}

// Upstream #1117: concurrent obtain / renew requests shared one HTTP-01 listener port and
// failed with "address already in use". Issuance must run one at a time.
func TestObtainCertIsSerialised(t *testing.T) {
	a := newTestHandler(t)
	var running, maxRunning int32
	a.beforeIssue = func() error {
		n := atomic.AddInt32(&running, 1)
		for {
			m := atomic.LoadInt32(&maxRunning)
			if n <= m || atomic.CompareAndSwapInt32(&maxRunning, m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&running, -1)
		return errors.New("stop here")
	}

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.ObtainCert([]string{"example.com"}, "example.com", "a@example.com", "", "", false, false, 0, "", false, false)
		}()
	}
	wg.Wait()
	if maxRunning != 1 {
		t.Fatalf("%d issuances ran at the same time, want 1", maxRunning)
	}
}

// The challenge port is re-checked before use: a port taken since start-up is replaced.
func TestEnsureFreeChallengePort(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer l.Close()
	busy := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)

	a := newTestHandler(t)
	a.Port = busy
	a.ensureFreeChallengePort()
	if a.Getport() == busy {
		t.Fatalf("busy port %s was kept", busy)
	}
	p, _ := strconv.Atoi(a.Getport())
	if IsPortInUse(p) {
		t.Fatalf("replacement port %d is not free", p)
	}

	// a free port stays as it is
	free := a.Getport()
	a.ensureFreeChallengePort()
	if a.Getport() != free {
		t.Fatalf("free port changed from %s to %s", free, a.Getport())
	}
}
