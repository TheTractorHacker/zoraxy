// Package apitoken implements scoped REST API tokens for the /api/v1 subset.
//
// Tokens are 256 bit random values ("zrx_" + base64url). Only the SHA-256 hash
// is persisted. The clear text token is returned once, at creation.
package apitoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	TokenPrefix = "zrx_"
	Table       = "apitokens"

	ScopeRead      = "read"
	ScopeReadWrite = "readwrite"
)

// KV is the subset of the system database used for persistence.
type KV interface {
	NewTable(tableName string) error
	Write(tableName string, key string, value interface{}) error
	Delete(tableName string, key string) error
	ListTable(tableName string) ([][][]byte, error)
}

// Logger is satisfied by the system logger.
type Logger interface {
	PrintAndLog(title string, message string, originalError error)
}

// Record is the persisted form. Hash is the hex SHA-256 of the token.
type Record struct {
	ID           string
	Name         string
	Scope        string
	Hash         string
	Created      int64
	Expires      int64 // unix seconds, 0 = never
	AllowedCIDRs []string
	LastUsed     int64
	Revoked      bool
	RevokedAt    int64
}

// Info is the public view of a token; it never contains the token or its hash.
type Info struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Scope        string   `json:"scope"`
	Created      int64    `json:"created"`
	Expires      int64    `json:"expires"`
	AllowedCIDRs []string `json:"allowedCidrs"`
	LastUsed     int64    `json:"lastUsed"`
	Revoked      bool     `json:"revoked"`
	Expired      bool     `json:"expired"`
}

type Manager struct {
	kv      KV
	log     Logger
	mu      sync.RWMutex
	tokens  map[string]*Record // by ID
	nets    map[string][]*net.IPNet
	now     func() time.Time
	limiter *limiter
}

func NewManager(kv KV, log Logger) (*Manager, error) {
	m := &Manager{kv: kv, log: log, tokens: map[string]*Record{}, nets: map[string][]*net.IPNet{}, now: time.Now}
	m.limiter = newLimiter(m.clock)
	if err := kv.NewTable(Table); err != nil {
		return nil, err
	}
	entries, err := kv.ListTable(Table)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if len(e) < 2 {
			continue
		}
		var rec Record
		if json.Unmarshal(e[1], &rec) != nil || rec.ID == "" {
			continue
		}
		m.tokens[rec.ID] = &rec
		m.nets[rec.ID], _ = ParseCIDRs(rec.AllowedCIDRs)
	}
	return m, nil
}

func (m *Manager) clock() time.Time {
	m.mu.RLock()
	f := m.now
	m.mu.RUnlock()
	return f()
}

// SetClock replaces the time source (tests).
func (m *Manager) SetClock(now func() time.Time) {
	m.mu.Lock()
	m.now = now
	m.mu.Unlock()
}

// ParseCIDRs accepts single IPs and CIDRs.
func ParseCIDRs(list []string) ([]*net.IPNet, error) {
	out := []*net.IPNet{}
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, errors.New("invalid IP or CIDR: " + s)
			}
			bits := 128
			if ip4 := ip.To4(); ip4 != nil {
				bits = 32
				ip = ip4
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, errors.New("invalid IP or CIDR: " + s)
		}
		out = append(out, n)
	}
	return out, nil
}

func hashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Create makes a new token. The returned string is the only time the clear
// text token is available.
func (m *Manager) Create(name, scope string, expires int64, cidrs []string) (string, *Info, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", nil, errors.New("name must be 1-64 characters")
	}
	if scope != ScopeRead && scope != ScopeReadWrite {
		return "", nil, errors.New("scope must be read or readwrite")
	}
	now := m.clock().Unix()
	if expires != 0 && expires <= now {
		return "", nil, errors.New("expiry must be in the future")
	}
	clean := []string{}
	for _, c := range cidrs {
		if c = strings.TrimSpace(c); c != "" {
			clean = append(clean, c)
		}
	}
	nets, err := ParseCIDRs(clean)
	if err != nil {
		return "", nil, err
	}
	raw := make([]byte, 32) // 256 bit
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	tok := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	rec := &Record{
		ID: randID(), Name: name, Scope: scope,
		Hash:    hex.EncodeToString(hashToken(tok)),
		Created: now, Expires: expires, AllowedCIDRs: clean,
	}
	if err := m.kv.Write(Table, rec.ID, rec); err != nil {
		return "", nil, err
	}
	m.mu.Lock()
	m.tokens[rec.ID] = rec
	m.nets[rec.ID] = nets
	info := m.info(rec, now)
	m.mu.Unlock()
	return tok, &info, nil
}

func (m *Manager) info(r *Record, now int64) Info {
	c := r.AllowedCIDRs
	if c == nil {
		c = []string{}
	}
	return Info{ID: r.ID, Name: r.Name, Scope: r.Scope, Created: r.Created, Expires: r.Expires,
		AllowedCIDRs: c, LastUsed: r.LastUsed, Revoked: r.Revoked,
		Expired: r.Expires != 0 && now >= r.Expires}
}

// List returns all tokens, newest first, without secrets.
func (m *Manager) List() []Info {
	now := m.clock().Unix()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Info{}
	for _, r := range m.tokens {
		out = append(out, m.info(r, now))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created != out[j].Created {
			return out[i].Created > out[j].Created
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (m *Manager) Revoke(id string) error {
	now := m.clock().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.tokens[id]
	if !ok {
		return errors.New("token not found")
	}
	r.Revoked = true
	r.RevokedAt = now
	return m.kv.Write(Table, id, r)
}

// Delete removes a token record entirely.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[id]; !ok {
		return errors.New("token not found")
	}
	delete(m.tokens, id)
	delete(m.nets, id)
	return m.kv.Delete(Table, id)
}

// lookup finds the record for a token using constant time hash comparison.
func (m *Manager) lookup(tok string) (*Record, []*net.IPNet) {
	want := hashToken(tok)
	m.mu.RLock()
	defer m.mu.RUnlock()
	var found *Record
	for _, r := range m.tokens {
		have, err := hex.DecodeString(r.Hash)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(have, want) == 1 {
			found = r
		}
	}
	if found == nil {
		return nil, nil
	}
	cp := *found
	return &cp, m.nets[found.ID]
}

func (m *Manager) touch(id string) {
	now := m.clock().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.tokens[id]
	if !ok || now-r.LastUsed < 60 { // limit database writes
		return
	}
	r.LastUsed = now
	m.kv.Write(Table, id, r)
}

// ClientIP is the address used for allow-listing and rate limiting. Forwarding
// headers are deliberately ignored: they are attacker controlled.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}

func ipAllowed(nets []*net.IPNet, ipStr string) bool {
	if len(nets) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// bearer extracts the token from an Authorization header.
func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	if !strings.HasPrefix(tok, TokenPrefix) || len(tok) > 128 || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead
}

// authenticate returns the HTTP status (0 = success) and the token record
// (when one was identified, for audit logging).
func (m *Manager) authenticate(r *http.Request, ip string) (int, *Record) {
	if !m.limiter.failureAllowed(ip) {
		return http.StatusTooManyRequests, nil
	}
	tok, ok := bearer(r)
	if !ok {
		m.limiter.recordFailure(ip)
		return http.StatusUnauthorized, nil
	}
	rec, nets := m.lookup(tok)
	if rec == nil || rec.Revoked || (rec.Expires != 0 && m.clock().Unix() >= rec.Expires) {
		m.limiter.recordFailure(ip)
		return http.StatusUnauthorized, nil
	}
	if !ipAllowed(nets, ip) {
		m.limiter.recordFailure(ip)
		return http.StatusForbidden, rec
	}
	if rec.Scope != ScopeReadWrite && !isSafeMethod(r.Method) {
		return http.StatusForbidden, rec
	}
	if !m.limiter.allow(rec.ID, ip) {
		return http.StatusTooManyRequests, rec
	}
	m.touch(rec.ID)
	return 0, rec
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) {
	s.status = c
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func deny(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="zoraxy"`)
	}
	if code == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(code)
	msg := map[int]string{401: "unauthorized", 403: "forbidden", 429: "too many requests"}[code]
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type tokenNameKey struct{}

// TokenName returns the name of the API token that authenticated the request
// (only set inside Middleware), for the configuration history.
func TokenName(r *http.Request) string {
	n, _ := r.Context().Value(tokenNameKey{}).(string)
	return n
}

// Middleware authenticates a Bearer token and audit logs the outcome. Only
// wrap /api/v1 handlers with it.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		code, rec := m.authenticate(r, ip)
		name := "-"
		if rec != nil {
			name = rec.Name
		}
		if code != 0 {
			deny(w, code)
			m.logUse(name, r, ip, code)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), tokenNameKey{}, name)))
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		m.logUse(name, r, ip, sw.status)
	})
}

func (m *Manager) logUse(name string, r *http.Request, ip string, status int) {
	if m.log == nil {
		return
	}
	q := strings.NewReplacer("\n", " ", "\r", " ").Replace
	m.log.PrintAndLog("apitoken", "token="+q(name)+" method="+q(r.Method)+" route="+q(r.URL.Path)+
		" ip="+ip+" status="+strconv.Itoa(status), nil)
}
