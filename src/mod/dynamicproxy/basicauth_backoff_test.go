package dynamicproxy

import (
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/auth"
)

func countVerifies(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	orig := basicAuthVerifyPassword
	basicAuthVerifyPassword = func(raw, stored string, p auth.PasswordProfile) (bool, bool) {
		n.Add(1)
		return orig(raw, stored, p)
	}
	t.Cleanup(func() { basicAuthVerifyPassword = orig })
	return &n
}

func baAttempt(pe *ProxyEndpoint, ip, user, pass string) error {
	r := httptest.NewRequest("GET", "http://ba.example.com/", nil)
	r.RemoteAddr = ip + ":4000"
	r.SetBasicAuth(user, pass)
	return handleBasicAuth(httptest.NewRecorder(), r, pe)
}

// Repeated bad credentials from one client must not each pay the argon2 cost
// (fork #166), while a correct credential from the same client still works
// once the backoff has elapsed, and other clients are never affected.
func TestBasicAuth_FailureBackoffSkipsArgon2(t *testing.T) {
	var persisted atomic.Int32
	pe := basicAuthEndpoint(auth.HashPasswordWithProfile("goodpw", auth.ProfileBasicAuth), &persisted)
	pe.RootOrMatchingDomain = "backoff.example.com"
	n := countVerifies(t)

	now := time.Now()
	basicAuthNow = func() time.Time { return now }
	t.Cleanup(func() { basicAuthNow = time.Now })

	for i := 0; i < 50; i++ {
		if baAttempt(pe, "198.51.100.7", "alice", "bad"+strconv.Itoa(i)) == nil {
			t.Fatal("bad credential accepted")
		}
	}
	if got := n.Load(); got > 8 {
		t.Fatalf("50 bad attempts ran argon2 %d times; backoff is not applied", got)
	}

	//Another client is unaffected and a correct credential works immediately
	if err := baAttempt(pe, "198.51.100.8", "alice", "goodpw"); err != nil {
		t.Fatalf("other client blocked: %v", err)
	}
	//Same client: correct credential works again after the backoff expires
	now = now.Add(2 * time.Minute)
	if err := baAttempt(pe, "198.51.100.7", "alice", "goodpw"); err != nil {
		t.Fatalf("correct credential rejected after backoff: %v", err)
	}
	//and success clears the failure state
	before := n.Load()
	for i := 0; i < 3; i++ {
		_ = baAttempt(pe, "198.51.100.7", "alice", "bad")
	}
	if n.Load()-before != 3 {
		t.Fatalf("failure state not reset by success")
	}
}

// A previously verified (cached) credential keeps working while its client is
// in backoff, so a user with a good session is not locked out by noise.
func TestBasicAuth_CachedSuccessBypassesBackoff(t *testing.T) {
	var persisted atomic.Int32
	pe := basicAuthEndpoint(auth.HashPasswordWithProfile("goodpw", auth.ProfileBasicAuth), &persisted)
	pe.RootOrMatchingDomain = "backoff2.example.com"
	if err := baAttempt(pe, "198.51.100.20", "alice", "goodpw"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		_ = baAttempt(pe, "198.51.100.20", "alice", "bad"+strconv.Itoa(i))
	}
	if err := baAttempt(pe, "198.51.100.20", "alice", "goodpw"); err != nil {
		t.Fatalf("cached credential blocked by backoff: %v", err)
	}
}

func TestBasicAuth_FailureTableBounded(t *testing.T) {
	for i := 0; i < basicAuthFailMax*2; i++ {
		basicAuthRecordFailure("k" + strconv.Itoa(i))
	}
	basicAuthFailMu.Lock()
	defer basicAuthFailMu.Unlock()
	if len(basicAuthFailData) > basicAuthFailMax {
		t.Fatalf("failure table grew to %d", len(basicAuthFailData))
	}
}
