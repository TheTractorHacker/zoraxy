package dynamicproxy

import (
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/auth"
)

func basicAuthEndpoint(hash string, persisted *atomic.Int32) *ProxyEndpoint {
	pe := &ProxyEndpoint{
		RootOrMatchingDomain: "ba.example.com",
		AuthenticationProvider: &AuthenticationProvider{
			AuthMethod:           AuthMethodBasic,
			BasicAuthCredentials: []*BasicAuthCredentials{{Username: "alice", PasswordHash: hash}},
		},
	}
	pe.parent = &Router{Option: &RouterOption{PersistProxyEndpoint: func(*ProxyEndpoint) error {
		persisted.Add(1)
		return nil
	}}}
	return pe
}

func TestBasicAuth_LegacyHashVerifiesAndUpgrades(t *testing.T) {
	var persisted atomic.Int32
	pe := basicAuthEndpoint(auth.Hash("s3cret"), &persisted)

	r := httptest.NewRequest("GET", "http://ba.example.com/", nil)
	r.SetBasicAuth("alice", "wrong")
	if err := handleBasicAuth(httptest.NewRecorder(), r, pe); err == nil {
		t.Fatal("wrong password accepted")
	}
	if !auth.IsLegacyPasswordHash(pe.AuthenticationProvider.BasicAuthCredentials[0].PasswordHash) {
		t.Fatal("failed attempt must not change the hash")
	}

	r = httptest.NewRequest("GET", "http://ba.example.com/", nil)
	r.SetBasicAuth("alice", "s3cret")
	if err := handleBasicAuth(httptest.NewRecorder(), r, pe); err != nil {
		t.Fatalf("legacy credential must keep working: %v", err)
	}
	if r.Header.Get("X-Remote-User") != "alice" {
		t.Error("X-Remote-User not set")
	}
	basicAuthCredMu.RLock()
	h := pe.AuthenticationProvider.BasicAuthCredentials[0].PasswordHash
	basicAuthCredMu.RUnlock()
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("hash not upgraded: %s", h)
	}
	//persist runs in a goroutine, wait briefly
	for i := 0; i < 100 && persisted.Load() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if persisted.Load() != 1 {
		t.Errorf("upgraded config should be persisted once, got %d", persisted.Load())
	}

	//Still works with the new hash, wrong password still rejected
	r = httptest.NewRequest("GET", "http://ba.example.com/", nil)
	r.SetBasicAuth("alice", "s3cret")
	if err := handleBasicAuth(httptest.NewRecorder(), r, pe); err != nil {
		t.Fatalf("upgraded credential rejected: %v", err)
	}
	r = httptest.NewRequest("GET", "http://ba.example.com/", nil)
	r.SetBasicAuth("alice", "wrong")
	if err := handleBasicAuth(httptest.NewRecorder(), r, pe); err == nil {
		t.Fatal("wrong password accepted after upgrade")
	}
}

// The verified-credential cache must skip argon2 on repeat requests, and a
// password change (new stored hash) must invalidate it immediately.
func TestBasicAuth_CacheAvoidsRehashAndInvalidatesOnChange(t *testing.T) {
	var persisted atomic.Int32
	pe := basicAuthEndpoint(auth.HashPasswordWithProfile("pw1", auth.ProfileBasicAuth), &persisted)

	do := func(pass string) error {
		r := httptest.NewRequest("GET", "http://ba.example.com/", nil)
		r.SetBasicAuth("alice", pass)
		return handleBasicAuth(httptest.NewRecorder(), r, pe)
	}

	if err := do("pw1"); err != nil {
		t.Fatal(err)
	}
	basicAuthCacheMu.Lock()
	cached := len(basicAuthCacheData)
	basicAuthCacheMu.Unlock()
	if cached == 0 {
		t.Fatal("successful verification was not cached")
	}
	//Replace the stored hash (password change): the cached entry must NOT be honoured
	basicAuthCredMu.Lock()
	pe.AuthenticationProvider.BasicAuthCredentials[0].PasswordHash = auth.HashPasswordWithProfile("pw2", auth.ProfileBasicAuth)
	basicAuthCredMu.Unlock()
	if err := do("pw1"); err == nil {
		t.Fatal("old password accepted after credential change (stale cache)")
	}
	if err := do("pw2"); err != nil {
		t.Fatal(err)
	}
	if err := do("pw2"); err != nil {
		t.Fatalf("cached repeat failed: %v", err)
	}
}

func TestBasicAuth_NoRawPasswordInCacheKeys(t *testing.T) {
	var persisted atomic.Int32
	pe := basicAuthEndpoint(auth.HashPasswordWithProfile("topsecretpw", auth.ProfileBasicAuth), &persisted)
	r := httptest.NewRequest("GET", "http://ba.example.com/", nil)
	r.SetBasicAuth("alice", "topsecretpw")
	if err := handleBasicAuth(httptest.NewRecorder(), r, pe); err != nil {
		t.Fatal(err)
	}
	basicAuthCacheMu.Lock()
	defer basicAuthCacheMu.Unlock()
	for k, exp := range basicAuthCacheData {
		if strings.Contains(k, "topsecretpw") || strings.Contains(k, "Basic") {
			t.Fatal("cache key leaks credential material")
		}
		if d := time.Until(exp); d > 60*time.Second {
			t.Fatalf("cache TTL too long: %v", d)
		}
	}
}
