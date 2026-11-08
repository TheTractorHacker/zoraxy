package oauth2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/database"
)

/*
	persist.go

	Sessions survive a restart (fork #212). Every session is stored in the system database as
	{exp, provider, blob} where blob = AES-256-GCM(nonce | JSON(session)) with the session id as
	additional authenticated data, so a record cannot be moved to another id. The key is derived
	(HKDF) from the same secret as the cookie signing key: the node UUID, or, when a cluster secret
	is configured, the key material derived from it. Refresh tokens and ID tokens only ever exist
	server side (in memory and encrypted at rest), the browser holds an opaque signed id.

	The table is bounded (maxPersistedSessions, earliest expiry dropped first) and expired records
	are removed by a janitor and when read.

	Portable ticket (cluster secret only): the database is node local, so a second HA node does not
	have the record. With a shared secret the login also sets a short lived ticket cookie holding the
	AES-GCM sealed claims (never tokens). A node without the session record rebuilds a session from
	it that cannot be refreshed and ends with the ticket (ticketMaxLife at most), after which the
	browser silently re-authenticates against the identity provider.
*/

const (
	sessionTable         = "oauth2_sessions"
	maxPersistedSessions = 5000
	ticketMaxLife        = 30 * time.Minute
	ticketMaxBytes       = 3200
	persistJanitorEvery  = 10 * time.Minute
)

type sessionRecord struct {
	Exp  int64  `json:"exp"` //unix seconds, plaintext so cleanup needs no decryption
	Prov string `json:"p"`   //plaintext provider id, used to purge a provider's sessions
	Blob []byte `json:"blob"`
}

type sessionPayload struct {
	Provider     string         `json:"provider"`
	Host         string         `json:"host"`
	Claims       map[string]any `json:"claims"`
	IDToken      string         `json:"idToken,omitempty"`
	RefreshToken string         `json:"refreshToken,omitempty"`
	AccessExpiry int64          `json:"accessExpiry"`
	HardExpiry   int64          `json:"hardExpiry"`
}

type sessionPersister struct {
	db   *database.Database
	aead cipher.AEAD
	max  int
	now  func() time.Time

	mu    sync.Mutex
	count int
	stop  chan struct{}
}

func newSessionPersister(db *database.Database, secret []byte, max int) *sessionPersister {
	if max <= 0 {
		max = maxPersistedSessions
	}
	key, err := hkdf.Key(sha256.New, secret, []byte("zoraxy-oauth2-session-v1"), "session-at-rest", 32)
	if err != nil {
		panic(err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		panic(err)
	}
	db.NewTable(sessionTable)
	p := &sessionPersister{db: db, aead: aead, max: max, now: time.Now, stop: make(chan struct{})}
	p.cleanup()
	go func() {
		t := time.NewTicker(persistJanitorEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				p.cleanup()
			case <-p.stop:
				return
			}
		}
	}()
	return p
}

func (p *sessionPersister) close() {
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
}

func seal(aead cipher.AEAD, aad string, plain []byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return aead.Seal(nonce, nonce, plain, []byte(aad))
}

func openSealed(aead cipher.AEAD, aad string, blob []byte) ([]byte, bool) {
	n := aead.NonceSize()
	if len(blob) < n+aead.Overhead() {
		return nil, false
	}
	plain, err := aead.Open(nil, blob[:n], blob[n:], []byte(aad))
	return plain, err == nil
}

func sessionAAD(id string) string { return "session|" + id }

func (p *sessionPersister) save(s *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.saveHeld(s)
}

// saveHeld persists s; the caller holds s.mu.
func (p *sessionPersister) saveHeld(s *session) {
	pl := sessionPayload{
		Provider: s.provider, Host: s.host, Claims: s.claims, IDToken: s.idToken, RefreshToken: s.refreshToken,
		AccessExpiry: s.accessExpiry.UnixNano(), HardExpiry: s.hardExpiry.UnixNano(),
	}
	id, exp := s.id, s.hardExpiry
	raw, err := json.Marshal(pl)
	if err != nil {
		return
	}
	rec := sessionRecord{Exp: exp.Unix(), Prov: pl.Provider, Blob: seal(p.aead, sessionAAD(id), raw)}
	existed := p.db.KeyExists(sessionTable, id)
	if err := p.db.Write(sessionTable, id, rec); err != nil {
		return
	}
	if !existed {
		p.mu.Lock()
		p.count++
		over := p.count > p.max
		p.mu.Unlock()
		if over {
			p.cleanup()
		}
	}
}

// load returns the stored session or nil (missing, expired, tampered). Bad records are removed.
func (p *sessionPersister) load(id string) *session {
	if !p.db.KeyExists(sessionTable, id) {
		return nil
	}
	var rec sessionRecord
	if err := p.db.Read(sessionTable, id, &rec); err != nil {
		return nil
	}
	if rec.Exp <= p.now().Unix() {
		p.delete(id)
		return nil
	}
	plain, ok := openSealed(p.aead, sessionAAD(id), rec.Blob)
	if !ok {
		p.delete(id)
		return nil
	}
	var pl sessionPayload
	if json.Unmarshal(plain, &pl) != nil || pl.Provider == "" || pl.Host == "" {
		p.delete(id)
		return nil
	}
	return &session{
		id: id, provider: pl.Provider, host: pl.Host, claims: pl.Claims, idToken: pl.IDToken,
		refreshToken: pl.RefreshToken, accessExpiry: time.Unix(0, pl.AccessExpiry), hardExpiry: time.Unix(0, pl.HardExpiry),
	}
}

func (p *sessionPersister) delete(id string) {
	if p.db.KeyExists(sessionTable, id) {
		p.db.Delete(sessionTable, id)
		p.mu.Lock()
		if p.count > 0 {
			p.count--
		}
		p.mu.Unlock()
	}
}

type listedSession struct {
	id  string
	rec sessionRecord
}

func (p *sessionPersister) list() []listedSession {
	rows, err := p.db.ListTable(sessionTable)
	if err != nil {
		return nil
	}
	var out []listedSession
	for _, kv := range rows {
		if len(kv) < 2 {
			continue
		}
		var rec sessionRecord
		id := string(kv[0])
		if json.Unmarshal(kv[1], &rec) != nil {
			p.db.Delete(sessionTable, id)
			continue
		}
		out = append(out, listedSession{id, rec})
	}
	return out
}

// cleanup removes expired records and trims the table to its bound (earliest expiry first).
func (p *sessionPersister) cleanup() {
	now := p.now().Unix()
	var keep []listedSession
	for _, l := range p.list() {
		if l.rec.Exp <= now {
			p.db.Delete(sessionTable, l.id)
			continue
		}
		keep = append(keep, l)
	}
	if len(keep) > p.max {
		sort.Slice(keep, func(i, j int) bool { return keep[i].rec.Exp < keep[j].rec.Exp })
		for _, l := range keep[:len(keep)-p.max] {
			p.db.Delete(sessionTable, l.id)
		}
		keep = keep[len(keep)-p.max:]
	}
	p.mu.Lock()
	p.count = len(keep)
	p.mu.Unlock()
}

func (p *sessionPersister) purgeProvider(provider string) {
	for _, l := range p.list() {
		if l.rec.Prov == provider {
			p.delete(l.id)
		}
	}
}

/* Portable ticket */

type ticketPayload struct {
	SID      string         `json:"sid"`
	Provider string         `json:"p"`
	Host     string         `json:"h"`
	Claims   map[string]any `json:"c"`
	Exp      int64          `json:"e"` //unix seconds
}

func (s *sessionStore) ticketAEAD() cipher.AEAD {
	blk, err := aes.NewCipher(s.ticketKey)
	if err != nil {
		return nil
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil
	}
	return a
}

// issueTicket returns the cookie value of the portable ticket for sess ("" = none, e.g. too large).
func (s *sessionStore) issueTicket(sess *session) (value string, exp time.Time) {
	if !s.shared || s.ticketKey == nil {
		return "", time.Time{}
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	exp = time.Now().Add(ticketMaxLife)
	if sess.accessExpiry.Before(exp) {
		exp = sess.accessExpiry
	}
	if sess.hardExpiry.Before(exp) {
		exp = sess.hardExpiry
	}
	if !exp.After(time.Now().Add(5 * time.Second)) {
		return "", time.Time{}
	}
	raw, err := json.Marshal(ticketPayload{SID: sess.id, Provider: sess.provider, Host: sess.host, Claims: sess.claims, Exp: exp.Unix()})
	a := s.ticketAEAD()
	if err != nil || a == nil {
		return "", time.Time{}
	}
	v := base64.RawURLEncoding.EncodeToString(seal(a, "ticket|"+sess.id, raw))
	if len(v) > ticketMaxBytes {
		return "", time.Time{}
	}
	sess.ticketFor = sess.accessExpiry
	return v, exp
}

// openTicket rebuilds a (non refreshable) session from a ticket that belongs to the signed session id.
func (s *sessionStore) openTicket(value, sid, provider, host string) *session {
	a := s.ticketAEAD()
	if a == nil || len(value) > ticketMaxBytes+64 || strings.TrimSpace(sid) == "" {
		return nil
	}
	blob, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil
	}
	plain, ok := openSealed(a, "ticket|"+sid, blob)
	if !ok {
		return nil
	}
	var t ticketPayload
	if json.Unmarshal(plain, &t) != nil || t.SID != sid || t.Provider != normProvider(provider) || t.Host != host {
		return nil
	}
	exp := time.Unix(t.Exp, 0)
	if !exp.After(time.Now()) {
		return nil
	}
	return &session{id: sid, provider: t.Provider, host: t.Host, claims: t.Claims, accessExpiry: exp, hardExpiry: exp}
}

// refreshTicket sets (or renews) the portable ticket cookie when the session changed.
func (s *sessionStore) refreshTicket(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.shared {
		return
	}
	sess.mu.Lock()
	stale := sess.ticketFor != sess.accessExpiry
	provider := sess.provider
	sess.mu.Unlock()
	if !stale {
		return
	}
	if v, exp := s.issueTicket(sess); v != "" {
		http.SetCookie(w, newCookie(r, cookieNameFor(ticketCookie, provider), v, exp))
	}
}
