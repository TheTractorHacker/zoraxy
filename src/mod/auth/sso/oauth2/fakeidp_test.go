package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

const (
	testClientID     = "zoraxy-client"
	testClientSecret = "s3cret-s3cret-s3cret-s3cret-s3cret-0123456789"
)

type codeRec struct {
	clientID, redirectURI, nonce string
	challenge, method            string
	claims                       map[string]any
}

// fakeIdP is a minimal OpenID Provider (discovery, JWKS, authorize helper, token, userinfo,
// end_session) good enough to exercise the relying party code. It is NOT Authentik.
type fakeIdP struct {
	*httptest.Server
	mu sync.Mutex

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	kid    string
	useEC  bool

	signAlg    string // RS256 (default), ES256, HS256
	advertise  []string
	pkceMeth   []string
	issuerOver string // issuer reported (default: server URL + "/application/o/app/")

	user          map[string]any
	expiresIn     int
	withRefresh   bool
	refreshIDTok  bool
	mutateClaims  func(c map[string]any)
	idTokenSigner func(claims map[string]any) string // overrides signing (forgery tests)

	codes         map[string]*codeRec
	refreshTokens map[string]map[string]any
	accessTokens  map[string]map[string]any

	refreshCount int
	jwksFetches  int
	failRefresh  bool
	userinfoOK   bool
	lastEndSess  url.Values
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{
		kid: "k1", signAlg: "RS256", advertise: []string{"RS256"}, pkceMeth: []string{"S256", "plain"},
		user:      map[string]any{"sub": "user-1", "email": "a@example.com", "preferred_username": "alice", "name": "Alice", "groups": []any{"users"}},
		expiresIn: 3600, withRefresh: true, userinfoOK: true,
		codes: map[string]*codeRec{}, refreshTokens: map[string]map[string]any{}, accessTokens: map[string]map[string]any{},
	}
	f.rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("/application/o/app/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/application/o/jwks/", f.jwks)
	mux.HandleFunc("/application/o/token/", f.token)
	mux.HandleFunc("/application/o/userinfo/", f.userinfo)
	mux.HandleFunc("/application/o/app/end-session/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.lastEndSess = r.URL.Query()
		f.mu.Unlock()
		w.WriteHeader(200)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIdP) issuer() string {
	if f.issuerOver != "" {
		return f.issuerOver
	}
	return f.URL + "/application/o/app/"
}

func (f *fakeIdP) discovery(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.issuer(),
		"authorization_endpoint":                f.URL + "/application/o/authorize/",
		"token_endpoint":                        f.URL + "/application/o/token/",
		"userinfo_endpoint":                     f.URL + "/application/o/userinfo/",
		"end_session_endpoint":                  f.URL + "/application/o/app/end-session/",
		"jwks_uri":                              f.URL + "/application/o/jwks/",
		"code_challenge_methods_supported":      f.pkceMeth,
		"id_token_signing_alg_values_supported": f.advertise,
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
	})
}

func (f *fakeIdP) jwks(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksFetches++
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &f.rsaKey.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"},
		{Key: &f.ecKey.PublicKey, KeyID: f.kid + "-ec", Algorithm: "ES256", Use: "sig"},
	}}
	json.NewEncoder(w).Encode(set)
}

// rotate replaces the signing keys (new kid), as a provider does on key rollover.
func (f *fakeIdP) rotate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.kid = f.kid + "x"
}

func (f *fakeIdP) signClaims(claims map[string]any) string {
	if f.idTokenSigner != nil {
		return f.idTokenSigner(claims)
	}
	var key jose.SigningKey
	switch f.signAlg {
	case "ES256":
		key = jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: f.ecKey, KeyID: f.kid + "-ec"}}
	case "HS256":
		key = jose.SigningKey{Algorithm: jose.HS256, Key: []byte(testClientSecret)}
	default:
		key = jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: f.rsaKey, KeyID: f.kid}}
	}
	return signWith(key, claims)
}

func signWith(key jose.SigningKey, claims map[string]any) string {
	sig, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	s, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return s
}

func (f *fakeIdP) idClaims(rec *codeRec, user map[string]any) map[string]any {
	c := map[string]any{}
	for k, v := range user {
		c[k] = v
	}
	now := time.Now()
	c["iss"] = f.issuer()
	c["aud"] = rec.clientID
	c["iat"] = now.Unix()
	c["exp"] = now.Add(time.Hour).Unix()
	if rec.nonce != "" {
		c["nonce"] = rec.nonce
	}
	if f.mutateClaims != nil {
		f.mutateClaims(c)
	}
	return c
}

// authorize plays the browser + user at the provider: it consumes the authorization URL produced
// by the relying party and returns the callback URL the browser would be redirected to.
func (f *fakeIdP) authorize(t *testing.T, authURL string) (callback string, state string) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != testClientID {
		t.Fatalf("bad authorize request: %v", q)
	}
	code := randomToken(12)
	f.mu.Lock()
	f.codes[code] = &codeRec{clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"), nonce: q.Get("nonce"),
		challenge: q.Get("code_challenge"), method: q.Get("code_challenge_method"), claims: f.user}
	f.mu.Unlock()
	cb, _ := url.Parse(q.Get("redirect_uri"))
	cq := cb.Query()
	cq.Set("code", code)
	cq.Set("state", q.Get("state"))
	cb.RawQuery = cq.Encode()
	return cb.String(), q.Get("state")
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id, sec, hasBasic := r.BasicAuth()
	if !hasBasic {
		id, sec = r.Form.Get("client_id"), r.Form.Get("client_secret")
	}
	if id != testClientID || sec != testClientSecret {
		http.Error(w, `{"error":"invalid_client"}`, 401)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	resp := map[string]any{"token_type": "Bearer", "expires_in": f.expiresIn}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		rec := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		if rec == nil || rec.redirectURI != r.Form.Get("redirect_uri") {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		if rec.challenge != "" {
			v := r.Form.Get("code_verifier")
			ok := false
			if rec.method == "S256" {
				h := sha256.Sum256([]byte(v))
				ok = v != "" && base64.RawURLEncoding.EncodeToString(h[:]) == rec.challenge
			} else {
				ok = v != "" && v == rec.challenge
			}
			if !ok {
				http.Error(w, `{"error":"invalid_grant","error_description":"PKCE verification failed"}`, 400)
				return
			}
		}
		at := randomToken(16)
		f.accessTokens[at] = f.user
		resp["access_token"] = at
		resp["id_token"] = f.signClaims(f.idClaims(rec, f.user))
		if f.withRefresh {
			rt := randomToken(16)
			f.refreshTokens[rt] = f.user
			resp["refresh_token"] = rt
		}
	case "refresh_token":
		f.refreshCount++
		user := f.refreshTokens[r.Form.Get("refresh_token")]
		if user == nil || f.failRefresh {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		at := randomToken(16)
		f.accessTokens[at] = f.user
		resp["access_token"] = at
		resp["refresh_token"] = r.Form.Get("refresh_token")
		if f.refreshIDTok {
			resp["id_token"] = f.signClaims(f.idClaims(&codeRec{clientID: testClientID}, f.user))
		}
	default:
		http.Error(w, `{"error":"unsupported_grant_type"}`, 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (f *fakeIdP) userinfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(p) || !f.userinfoOK {
		http.Error(w, "no", 401)
		return
	}
	u := f.accessTokens[h[len(p):]]
	if u == nil {
		http.Error(w, "no", 401)
		return
	}
	json.NewEncoder(w).Encode(u)
}

/* test harness */

func newTestDB(t *testing.T) *database.Database {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "o.db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func newTestRouter(t *testing.T, idp *fakeIdP, mutate func(o *OAuth2RouterOptions)) *OAuth2Router {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "o.db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	lg, _ := logger.NewFmtLogger()
	o := &OAuth2RouterOptions{
		Logger: lg, Database: db, SystemUUID: "11111111-2222-3333-4444-555555555555",
		OAuth2ClientId: testClientID, OAuth2ClientSecret: testClientSecret,
		OAuth2Issuer: idp.issuer(), OAuth2CodeChallengeMethod: "PKCE_S256",
	}
	if mutate != nil {
		mutate(o)
	}
	ar := NewOAuth2Router(o)
	t.Cleanup(ar.Close)
	return ar
}

// browser is a tiny cookie jar scoped to one test.
type browser struct {
	t       *testing.T
	ar      *OAuth2Router
	ro      RuleOptions
	cookies map[string]*http.Cookie
}

func newBrowser(t *testing.T, ar *OAuth2Router) *browser {
	return &browser{t: t, ar: ar, cookies: map[string]*http.Cookie{}}
}

func (b *browser) request(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	return r
}

func (b *browser) absorb(w *httptest.ResponseRecorder) {
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
}

// do sends a request through the router. handled reports whether the router wrote a response.
func (b *browser) do(r *http.Request) (w *httptest.ResponseRecorder, err error) {
	w = httptest.NewRecorder()
	err = b.ar.HandleOAuth2AuthFor(w, r, b.ro)
	b.absorb(w)
	return
}

// login performs the full flow starting at target and returns the final recorder (callback response).
func (b *browser) login(idp *fakeIdP, target string) *httptest.ResponseRecorder {
	b.t.Helper()
	w, err := b.do(b.request("GET", target))
	if err == nil || w.Code != http.StatusFound {
		b.t.Fatalf("expected redirect to provider, got %d err=%v", w.Code, err)
	}
	cb, _ := idp.authorize(b.t, w.Header().Get("Location"))
	cw, _ := b.do(b.request("GET", cb))
	return cw
}
