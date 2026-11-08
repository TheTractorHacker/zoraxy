package cluster

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TokenWindow is how far a token timestamp may be from the verifier's clock
// (both directions, to tolerate small clock skew). Nodes should run NTP.
const TokenWindow = 60 * time.Second

var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Token errors. Handlers map all of them to the same 401 response.
var (
	ErrTokenMalformed = errors.New("malformed token")
	ErrTokenExpired   = errors.New("token timestamp outside the allowed window")
	ErrTokenInvalid   = errors.New("token signature invalid")
	ErrTokenReplayed  = errors.New("token already used")
)

var nonceHex = regexp.MustCompile(`^[0-9a-f]{16}$`)

func tokenMAC(secret, method, urlPath, ts, node, nonce string) string {
	m := hmac.New(sha256.New, DeriveKey(secret, PurposeSyncToken, 32))
	m.Write([]byte("zxc1\n" + method + "\n" + urlPath + "\n" + ts + "\n" + node + "\n" + nonce))
	return hex.EncodeToString(m.Sum(nil))
}

// MakeToken builds a bearer token bound to the HTTP method, path, time and
// node id. It reveals nothing about the secret and is useless for any other
// request.
func MakeToken(secret, method, urlPath, node string, now time.Time) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	nb := make([]byte, 8)
	rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	return "zxc1:" + ts + ":" + node + ":" + nonce + ":" + tokenMAC(secret, method, urlPath, ts, node, nonce)
}

// TokenVerifier verifies tokens and rejects reuse inside the window.
type TokenVerifier struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewTokenVerifier() *TokenVerifier {
	return &TokenVerifier{seen: map[string]time.Time{}}
}

// Verify checks a token for the given request. It returns the node id.
func (v *TokenVerifier) Verify(secret, method, urlPath, token string, now time.Time) (string, error) {
	parts := strings.Split(token, ":")
	if len(parts) != 5 || parts[0] != "zxc1" || !nodeIDPattern.MatchString(parts[2]) || !nonceHex.MatchString(parts[3]) {
		return "", ErrTokenMalformed
	}
	sec, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", ErrTokenMalformed
	}
	got, err := hex.DecodeString(parts[4])
	if err != nil {
		return "", ErrTokenMalformed
	}
	want, _ := hex.DecodeString(tokenMAC(secret, method, urlPath, parts[1], parts[2], parts[3]))
	if !hmac.Equal(got, want) { //constant time
		return "", ErrTokenInvalid
	}
	d := now.Sub(time.Unix(sec, 0))
	if d > TokenWindow || d < -TokenWindow {
		return "", ErrTokenExpired
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, t := range v.seen {
		if now.Sub(t) > 2*TokenWindow {
			delete(v.seen, k)
		}
	}
	if _, dup := v.seen[parts[4]]; dup {
		return "", ErrTokenReplayed
	}
	if len(v.seen) > 10000 {
		return "", ErrTokenReplayed //flood guard, fail closed
	}
	v.seen[parts[4]] = now
	return parts[2], nil
}

// RateLimiter is a fixed window limiter per key (client IP).
type RateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*rlEntry
}

type rlEntry struct {
	start time.Time
	n     int
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{limit: limit, window: window, hits: map[string]*rlEntry{}}
}

// Allow records a hit and reports whether it is within the limit.
func (r *RateLimiter) Allow(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hits) > 4096 {
		for k, e := range r.hits {
			if now.Sub(e.start) >= r.window {
				delete(r.hits, k)
			}
		}
	}
	e, ok := r.hits[key]
	if !ok || now.Sub(e.start) >= r.window {
		r.hits[key] = &rlEntry{start: now, n: 1}
		return true
	}
	e.n++
	return e.n <= r.limit
}
