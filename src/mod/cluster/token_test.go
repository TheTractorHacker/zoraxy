package cluster

import (
	"strings"
	"testing"
	"time"
)

func TestTokenValidAndBoundToRequest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := NewTokenVerifier()
	tok := MakeToken(testSecret, "GET", SnapshotPath, "node-1", now)
	node, err := v.Verify(testSecret, "GET", SnapshotPath, tok, now.Add(2*time.Second))
	if err != nil || node != "node-1" {
		t.Fatalf("valid token rejected: %v", err)
	}
	// bound to method and path
	tok2 := MakeToken(testSecret, "GET", SnapshotPath, "node-1", now)
	if _, err := v.Verify(testSecret, "POST", SnapshotPath, tok2, now); err != ErrTokenInvalid {
		t.Fatalf("method confusion: %v", err)
	}
	if _, err := v.Verify(testSecret, "GET", HeartbeatPath, tok2, now); err != ErrTokenInvalid {
		t.Fatalf("path confusion: %v", err)
	}
	// wrong secret
	if _, err := v.Verify(testSecret+"x", "GET", SnapshotPath, tok2, now); err != ErrTokenInvalid {
		t.Fatalf("wrong secret: %v", err)
	}
	// node id swap
	forged := strings.Replace(tok2, ":node-1:", ":node-2:", 1)
	if _, err := v.Verify(testSecret, "GET", SnapshotPath, forged, now); err != ErrTokenInvalid {
		t.Fatalf("node swap: %v", err)
	}
}

func TestTokenExpiryWindowAndReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := NewTokenVerifier()
	tok := MakeToken(testSecret, "GET", SnapshotPath, "n", now)

	if _, err := v.Verify(testSecret, "GET", SnapshotPath, tok, now.Add(TokenWindow+time.Second)); err != ErrTokenExpired {
		t.Fatalf("old token: want expired got %v", err)
	}
	if _, err := v.Verify(testSecret, "GET", SnapshotPath, tok, now.Add(-TokenWindow-time.Second)); err != ErrTokenExpired {
		t.Fatalf("future token: want expired got %v", err)
	}
	if _, err := v.Verify(testSecret, "GET", SnapshotPath, tok, now.Add(TokenWindow-time.Second)); err != nil {
		t.Fatalf("token inside the window rejected: %v", err)
	}
	if _, err := v.Verify(testSecret, "GET", SnapshotPath, tok, now.Add(TokenWindow-time.Second)); err != ErrTokenReplayed {
		t.Fatalf("replay: want ErrTokenReplayed got %v", err)
	}
}

func TestTokenMalformed(t *testing.T) {
	v := NewTokenVerifier()
	now := time.Now()
	for _, tok := range []string{"", "x", "zxc1:1:n", "zxc1:abc:n:00", "zxc1:1:bad node:00", "zxc1:1:n:zz", "other:1:n:00", "zxc1:1:n:00:00:extra", "zxc1:1:n:00:00"} {
		if _, err := v.Verify(testSecret, "GET", SnapshotPath, tok, now); err != ErrTokenMalformed {
			t.Errorf("%q: want malformed got %v", tok, err)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	rl := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.Allow("1.1.1.1", now) {
			t.Fatalf("hit %d denied", i)
		}
	}
	if rl.Allow("1.1.1.1", now) {
		t.Fatal("limit not enforced")
	}
	if !rl.Allow("2.2.2.2", now) {
		t.Fatal("limit must be per key")
	}
	if !rl.Allow("1.1.1.1", now.Add(time.Minute)) {
		t.Fatal("window did not reset")
	}
}
