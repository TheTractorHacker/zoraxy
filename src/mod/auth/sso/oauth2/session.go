package oauth2

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

/*
	session.go

	Server side login sessions and in-flight login attempts. The browser only ever holds an opaque,
	HMAC signed random identifier; tokens never leave Zoraxy. The signing key is derived from the
	node UUID, so cookies minted by one Zoraxy node are not valid on another.
*/

const (
	callbackPrefix = "/internal/oauth2"
	logoutPath     = callbackPrefix + "/logout"

	sessionCookie  = "z-session"
	pendingPrefix  = "z-oidc-"
	legacyToken    = "z-token"
	legacyVerifier = "z-verifier"

	pendingTTL     = 10 * time.Minute
	maxSessionLife = 7 * 24 * time.Hour
	noExpiryLife   = time.Hour
	refreshSkew    = 60 * time.Second
	cacheCapacity  = 10000
)

type session struct {
	mu           sync.Mutex
	host         string
	claims       map[string]any
	idToken      string
	refreshToken string
	accessExpiry time.Time
	hardExpiry   time.Time
}

// pendingLogin is the state of one in-flight authorization code flow.
type pendingLogin struct {
	host       string
	nonce      string
	verifier   string
	returnPath string
	bind       string
}

type sessionStore struct {
	key      []byte
	sessions *ttlcache.Cache[string, *session]
	pending  *ttlcache.Cache[string, *pendingLogin]
}

func newSessionStore(nodeUUID string) *sessionStore {
	secret := []byte(strings.TrimSpace(nodeUUID))
	if len(secret) == 0 {
		// No node identity available: use a per process random secret. Sessions then do not
		// survive a restart, which is also true for the in-memory session table anyway.
		secret = make([]byte, 32)
		rand.Read(secret)
	}
	key, err := hkdf.Key(sha256.New, secret, []byte("zoraxy-oauth2-session-v1"), "cookie-signing", 32)
	if err != nil {
		panic(err)
	}
	s := &sessionStore{
		key: key,
		sessions: ttlcache.New[string, *session](
			ttlcache.WithTTL[string, *session](maxSessionLife),
			ttlcache.WithCapacity[string, *session](cacheCapacity),
			ttlcache.WithDisableTouchOnHit[string, *session](),
		),
		pending: ttlcache.New[string, *pendingLogin](
			ttlcache.WithTTL[string, *pendingLogin](pendingTTL),
			ttlcache.WithCapacity[string, *pendingLogin](cacheCapacity),
			ttlcache.WithDisableTouchOnHit[string, *pendingLogin](),
		),
	}
	go s.sessions.Start()
	go s.pending.Start()
	return s
}

func (s *sessionStore) close() {
	s.sessions.Stop()
	s.pending.Stop()
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessionStore) sign(purpose, value string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(purpose))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return value + "." + hex.EncodeToString(m.Sum(nil))
}

// unsign returns the value if the signature is valid.
func (s *sessionStore) unsign(purpose, signed string) (string, bool) {
	idx := strings.LastIndex(signed, ".")
	if idx <= 0 {
		return "", false
	}
	value := signed[:idx]
	want := s.sign(purpose, value)
	if !hmac.Equal([]byte(want), []byte(signed)) {
		return "", false
	}
	return value, true
}

func (s *sessionStore) create(sess *session) string {
	id := randomToken(32)
	ttl := time.Until(sess.hardExpiry)
	if ttl <= 0 {
		ttl = time.Second
	}
	s.sessions.Set(id, sess, ttl)
	return s.sign("session", id)
}

// lookup returns the session for the request, or nil. A session is only valid for the host it was
// created on, so a cookie planted from a sibling subdomain cannot be replayed elsewhere.
func (s *sessionStore) lookup(r *http.Request) (string, *session) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return "", nil
	}
	id, ok := s.unsign("session", c.Value)
	if !ok {
		return "", nil
	}
	item := s.sessions.Get(id)
	if item == nil {
		return "", nil
	}
	sess := item.Value()
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.host != r.Host || time.Now().After(sess.hardExpiry) {
		return "", nil
	}
	return id, sess
}

func (s *sessionStore) destroy(id string) {
	if id != "" {
		s.sessions.Delete(id)
	}
}

func (s *sessionStore) newPending(p *pendingLogin) (state string) {
	state = randomToken(24)
	s.pending.Set(state, p, pendingTTL)
	return state
}

func cookieSecure(r *http.Request) bool { return r.TLS != nil }

func newCookie(r *http.Request, name, value string, expires time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	}
	if !expires.IsZero() {
		c.Expires = expires
		if d := time.Until(expires); d > 0 {
			c.MaxAge = int(d.Seconds())
		} else {
			c.MaxAge = -1
		}
	}
	return c
}

func expireCookie(w http.ResponseWriter, r *http.Request, name string) {
	c := newCookie(r, name, "", time.Unix(1, 0))
	c.MaxAge = -1
	http.SetCookie(w, c)
}

func pendingCookieName(state string) string {
	if len(state) > 10 {
		state = state[:10]
	}
	return pendingPrefix + state
}
