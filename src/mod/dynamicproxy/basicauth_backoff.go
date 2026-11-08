package dynamicproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"sync"
	"time"
)

/*
	Basic auth failure backoff

	A wrong password normally costs a full argon2 computation (~20 ms, 19 MiB)
	and, unlike successes, can not be served from the verified-credential
	cache. Without a limit one client could burn the CPU with a stream of bad
	credentials. Failures are therefore counted per (endpoint, client IP,
	username): the first basicAuthFailFree failures are verified normally, after
	that further attempts from the same key are rejected WITHOUT running argon2
	until an exponentially growing block (1 s, 2 s, ... capped at 60 s) expires.
	A successful login clears the counter, and an already cached (verified)
	Authorization header keeps working while the client is blocked.

	The client IP is the TCP peer address (never a forwarded header, which an
	attacker could rotate to dodge the limit). Keys are HMACed, entries expire
	basicAuthFailWindow after the last failure and the table is capped at
	basicAuthFailMax entries so memory stays bounded.

	This is in addition to, not instead of, the per-endpoint rate limiter which
	runs earlier in the request path (Server.go).
*/

const (
	basicAuthFailFree   = 5
	basicAuthFailWindow = 5 * time.Minute
	basicAuthBackoffMin = time.Second
	basicAuthBackoffMax = 60 * time.Second
	basicAuthFailMax    = 4096
)

type basicAuthFailState struct {
	count        int
	last         time.Time
	blockedUntil time.Time
}

var (
	basicAuthNow      = time.Now //test seam
	basicAuthFailMu   sync.Mutex
	basicAuthFailData = map[string]*basicAuthFailState{}
)

func basicAuthFailKey(endpoint, ip, user string) string {
	m := hmac.New(sha256.New, basicAuthCacheKey)
	m.Write([]byte(endpoint))
	m.Write([]byte{0})
	m.Write([]byte(ip))
	m.Write([]byte{0})
	m.Write([]byte(user))
	return string(m.Sum(nil))
}

// basicAuthBlocked reports whether the key is currently in backoff.
func basicAuthBlocked(key string) bool {
	basicAuthFailMu.Lock()
	defer basicAuthFailMu.Unlock()
	st, ok := basicAuthFailData[key]
	if !ok {
		return false
	}
	now := basicAuthNow()
	if now.Sub(st.last) > basicAuthFailWindow {
		delete(basicAuthFailData, key)
		return false
	}
	return now.Before(st.blockedUntil)
}

// basicAuthRecordFailure counts a failed attempt (not called while blocked).
func basicAuthRecordFailure(key string) {
	basicAuthFailMu.Lock()
	defer basicAuthFailMu.Unlock()
	now := basicAuthNow()
	st, ok := basicAuthFailData[key]
	if ok && now.Sub(st.last) > basicAuthFailWindow {
		delete(basicAuthFailData, key)
		ok = false
	}
	if !ok {
		if len(basicAuthFailData) >= basicAuthFailMax {
			for k, v := range basicAuthFailData {
				if now.Sub(v.last) > basicAuthFailWindow {
					delete(basicAuthFailData, k)
				}
			}
			//Still full of live entries: evict arbitrary ones to make room
			for k := range basicAuthFailData {
				if len(basicAuthFailData) < basicAuthFailMax {
					break
				}
				delete(basicAuthFailData, k)
			}
		}
		st = &basicAuthFailState{}
		basicAuthFailData[key] = st
	}
	st.count++
	st.last = now
	if over := st.count - basicAuthFailFree; over > 0 {
		d := basicAuthBackoffMin
		for i := 1; i < over && d < basicAuthBackoffMax; i++ {
			d *= 2
		}
		if d > basicAuthBackoffMax {
			d = basicAuthBackoffMax
		}
		st.blockedUntil = now.Add(d)
	}
}

func basicAuthClearFailures(key string) {
	basicAuthFailMu.Lock()
	delete(basicAuthFailData, key)
	basicAuthFailMu.Unlock()
}
