package dynamicproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/auth"
)

/*
	Basic auth credential verification

	Credentials are stored as salted argon2id hashes. Legacy unsalted SHA-512
	hashes are still accepted and are upgraded in place on the first successful
	request, then persisted through RouterOption.PersistProxyEndpoint.

	Why a verified-credential cache: HTTP basic auth sends the password with
	EVERY request, so running argon2 (~20 ms, 19 MiB) per request would let a
	single page load with 50 assets burn a second of CPU and would make the
	proxy trivially CPU/memory DoS-able by any authenticated client. After a
	successful verification we remember, for at most basicAuthCacheTTL, that
	this exact Authorization header was valid for this endpoint and stored
	hash. The map key is HMAC-SHA256(per-process random key, endpoint | header
	| stored hash), so the password is never kept in memory by the cache, a
	leaked key list is useless, and changing the stored hash (password change)
	invalidates every cached entry. Only successes are cached; failures always
	pay the full argon2 cost (bounded by auth's concurrency limiter).
*/

const (
	basicAuthCacheTTL = 30 * time.Second // must stay <= 60 s
	basicAuthCacheMax = 4096
)

var (
	// basicAuthCredMu guards BasicAuthCredentials.PasswordHash against the
	// in-place upgrade racing with request-time reads
	basicAuthCredMu sync.RWMutex

	basicAuthCacheKey  = newBasicAuthCacheKey()
	basicAuthCacheMu   sync.Mutex
	basicAuthCacheData = map[string]time.Time{}
)

func newBasicAuthCacheKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("dynamicproxy: unable to seed basic auth cache key: " + err.Error())
	}
	return k
}

func basicAuthCacheID(endpoint string, authHeader string, storedHash string) string {
	m := hmac.New(sha256.New, basicAuthCacheKey)
	m.Write([]byte(endpoint))
	m.Write([]byte{0})
	m.Write([]byte(authHeader))
	m.Write([]byte{0})
	m.Write([]byte(storedHash))
	return string(m.Sum(nil))
}

func basicAuthCacheHit(id string) bool {
	basicAuthCacheMu.Lock()
	defer basicAuthCacheMu.Unlock()
	exp, ok := basicAuthCacheData[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(basicAuthCacheData, id)
		return false
	}
	return true
}

func basicAuthCacheStore(id string) {
	basicAuthCacheMu.Lock()
	defer basicAuthCacheMu.Unlock()
	now := time.Now()
	if len(basicAuthCacheData) >= basicAuthCacheMax {
		for k, exp := range basicAuthCacheData {
			if now.After(exp) {
				delete(basicAuthCacheData, k)
			}
		}
		if len(basicAuthCacheData) >= basicAuthCacheMax {
			return //Full of live entries, just skip caching
		}
	}
	basicAuthCacheData[id] = now.Add(basicAuthCacheTTL)
}

// verifyBasicAuthCredentials checks username / password against the
// endpoint's credentials, upgrading legacy hashes on success
func verifyBasicAuthCredentials(pe *ProxyEndpoint, username string, password string, authHeader string) bool {
	endpoint := pe.RootOrMatchingDomain

	basicAuthCredMu.RLock()
	creds := append([]*BasicAuthCredentials(nil), pe.AuthenticationProvider.BasicAuthCredentials...)
	stored := make([]string, len(creds))
	for i, c := range creds {
		stored[i] = c.PasswordHash
	}
	basicAuthCredMu.RUnlock()

	for i, cred := range creds {
		if cred.Username != username {
			continue
		}

		cacheID := basicAuthCacheID(endpoint, authHeader, stored[i])
		if authHeader != "" && basicAuthCacheHit(cacheID) {
			return true
		}

		ok, needsRehash := auth.VerifyPassword(password, stored[i], auth.ProfileBasicAuth)
		if !ok {
			continue
		}

		if needsRehash {
			upgradeBasicAuthHash(pe, cred, stored[i], password)
			basicAuthCredMu.RLock()
			cacheID = basicAuthCacheID(endpoint, authHeader, cred.PasswordHash)
			basicAuthCredMu.RUnlock()
		}
		if authHeader != "" {
			basicAuthCacheStore(cacheID)
		}
		return true
	}
	return false
}

// upgradeBasicAuthHash replaces a legacy / weak hash by a fresh argon2id one
// and persists the endpoint config. Failure to persist is not fatal: the
// upgrade simply happens again after the next restart.
func upgradeBasicAuthHash(pe *ProxyEndpoint, cred *BasicAuthCredentials, oldHash string, password string) {
	newHash := auth.HashPasswordWithProfile(password, auth.ProfileBasicAuth)

	basicAuthCredMu.Lock()
	if cred.PasswordHash != oldHash {
		//Somebody else (password change or concurrent upgrade) got here first
		basicAuthCredMu.Unlock()
		return
	}
	cred.PasswordHash = newHash
	basicAuthCredMu.Unlock()

	if pe.parent != nil && pe.parent.Option != nil && pe.parent.Option.PersistProxyEndpoint != nil {
		persist := pe.parent.Option.PersistProxyEndpoint
		go func() {
			basicAuthCredMu.RLock()
			defer basicAuthCredMu.RUnlock()
			if err := persist(pe); err != nil && pe.parent.Option.Logger != nil {
				pe.parent.Option.Logger.PrintAndLog("basic-auth", "Unable to save upgraded credential hash for "+pe.RootOrMatchingDomain, err)
			}
		}()
	}
}
