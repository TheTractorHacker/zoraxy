package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const appURL = "http://app.example.com"

func mustLogin(t *testing.T, b *browser, idp *fakeIdP) {
	t.Helper()
	w := b.login(idp, appURL+"/dash?x=1")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/dash?x=1" {
		t.Fatalf("login failed: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if _, ok := b.cookies[sessionCookie]; !ok {
		t.Fatal("no session cookie issued")
	}
}

func TestAuthorizationRequestParameters(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	w, err := b.do(b.request("GET", appURL+"/dash"))
	if err == nil || w.Code != http.StatusFound {
		t.Fatal("expected redirect")
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	q := u.Query()
	if !strings.HasPrefix(w.Header().Get("Location"), idp.URL+"/application/o/authorize/") {
		t.Fatalf("authorize endpoint from discovery not used: %s", u)
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if len(q.Get(k)) < 16 {
			t.Errorf("%s too short/missing: %q", k, q.Get(k))
		}
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" ||
		q.Get("redirect_uri") != appURL+"/internal/oauth2" || q.Get("client_id") != testClientID {
		t.Fatalf("bad params: %v", q)
	}
	if q.Get("state") == "/dash" || strings.Contains(q.Get("state"), "app.example.com") {
		t.Fatal("state must be an opaque random value, not the return URL")
	}
	scopes := strings.Fields(q.Get("scope"))
	for _, want := range []string{"openid", "profile", "email", "offline_access"} {
		if !containsStr(scopes, want) {
			t.Errorf("scope %s missing in %v", want, scopes)
		}
	}
	// the pending-login cookie must be HttpOnly + SameSite=Lax
	found := false
	for _, c := range w.Result().Cookies() {
		if strings.HasPrefix(c.Name, pendingPrefix) {
			found = true
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
				t.Fatalf("bad cookie flags: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("no bind cookie")
	}
}

func TestFullLoginPKCES256AndSessionCookieFlags(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) {
		o.OAuth2HeaderMappings = "X-Auth-User=preferred_username,X-Auth-Email=email,X-Auth-Groups=groups"
	})
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	c := b.cookies[sessionCookie]
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie flags: %+v", c)
	}
	if strings.Contains(c.Value, "alice") || len(c.Value) < 40 {
		t.Fatal("session cookie must be opaque")
	}
	r := b.request("GET", appURL+"/dash")
	r.Header.Set("X-Auth-User", "root")
	r.Header.Set("X-Auth-Email", "evil@example.com")
	w, err := b.do(r)
	if err != nil {
		t.Fatalf("authenticated request rejected: %d %s", w.Code, w.Body.String())
	}
	if r.Header.Get("X-Auth-User") != "alice" || r.Header.Get("X-Auth-Email") != "a@example.com" ||
		r.Header.Get("X-Auth-Groups") != "users" {
		t.Fatalf("headers: %v", r.Header)
	}
}

func TestSecureCookieOnTLS(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	w := httptest.NewRecorder()
	ar.HandleOAuth2Auth(w, r)
	for _, c := range w.Result().Cookies() {
		if !c.Secure {
			t.Fatalf("cookie %s not Secure on TLS", c.Name)
		}
	}
	if !strings.Contains(w.Header().Get("Location"), url.QueryEscape("https://app.example.com/internal/oauth2")) {
		t.Fatal("redirect_uri should use https")
	}
}

func TestPKCEChallengeMatchesVerifier(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	w, _ := b.do(b.request("GET", appURL+"/"))
	u, _ := url.Parse(w.Header().Get("Location"))
	challenge := u.Query().Get("code_challenge")
	// Find the stored verifier and recompute S256 ourselves.
	var verifier string
	for _, item := range ar.store.pending.Items() {
		verifier = item.Value().verifier
	}
	h := sha256.Sum256([]byte(verifier))
	if verifier == "" || base64.RawURLEncoding.EncodeToString(h[:]) != challenge {
		t.Fatalf("challenge %q does not match S256(verifier %q)", challenge, verifier)
	}
	if len(verifier) < 43 {
		t.Fatalf("verifier too short: %d", len(verifier))
	}
}

func TestPKCEWrongVerifierRejectedByProvider(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	w, _ := b.do(b.request("GET", appURL+"/"))
	cb, _ := idp.authorize(t, w.Header().Get("Location"))
	// Tamper: replace the stored verifier before the callback.
	for _, item := range ar.store.pending.Items() {
		item.Value().verifier = "a-different-verifier-a-different-verifier-aaaa"
	}
	cw, err := b.do(b.request("GET", cb))
	if err == nil || cw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", cw.Code)
	}
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Fatal("session must not be created")
	}
}

func TestPlainPKCELegacyMode(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) { o.OAuth2CodeChallengeMethod = "PKCE" })
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
}

func TestStateMismatchRejected(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	w, _ := b.do(b.request("GET", appURL+"/"))
	cb, _ := idp.authorize(t, w.Header().Get("Location"))

	// 1. wrong state value
	bad := strings.Replace(cb, "state=", "state=x", 1)
	cw, err := b.do(b.request("GET", bad))
	if err == nil || cw.Code != http.StatusBadRequest {
		t.Fatalf("forged state accepted: %d", cw.Code)
	}
	// 2. legacy style state (the return URL itself, as the old implementation used)
	cw, _ = b.do(b.request("GET", appURL+"/internal/oauth2?code=x&state="+url.QueryEscape("http://evil.example/")))
	if cw.Code != http.StatusBadRequest || cw.Header().Get("Location") != "" {
		t.Fatalf("URL state accepted: %d", cw.Code)
	}
	// 3. correct state but attacker's browser (no bind cookie) = login CSRF
	attacker := newBrowser(t, ar)
	cw, err = attacker.do(attacker.request("GET", cb))
	if err == nil || cw.Code != http.StatusBadRequest {
		t.Fatalf("callback without bind cookie accepted: %d", cw.Code)
	}
	// the state was consumed by the failed attempt: the legit browser cannot replay it either
	cw, _ = b.do(b.request("GET", cb))
	if cw.Code != http.StatusBadRequest {
		t.Fatalf("state replay accepted: %d", cw.Code)
	}
}

func TestStateIsSingleUse(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	w, _ := b.do(b.request("GET", appURL+"/"))
	cb, _ := idp.authorize(t, w.Header().Get("Location"))
	saved := map[string]*http.Cookie{}
	for k, v := range b.cookies {
		saved[k] = v
	}
	if cw, _ := b.do(b.request("GET", cb)); cw.Code != http.StatusFound {
		t.Fatalf("first use failed: %d", cw.Code)
	}
	b.cookies = saved
	if cw, _ := b.do(b.request("GET", cb)); cw.Code != http.StatusBadRequest {
		t.Fatalf("replay accepted: %d", cw.Code)
	}
}

func TestNonceMismatchRejected(t *testing.T) {
	idp := newFakeIdP(t)
	idp.mutateClaims = func(c map[string]any) { c["nonce"] = "attacker-chosen" }
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	w := b.login(idp, appURL+"/")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("nonce mismatch accepted: %d", w.Code)
	}
	idp.mutateClaims = func(c map[string]any) { delete(c, "nonce") }
	b = newBrowser(t, ar)
	if w := b.login(idp, appURL+"/"); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing nonce accepted: %d", w.Code)
	}
}

func TestBadIDTokensRejected(t *testing.T) {
	cases := map[string]func(idp *fakeIdP){
		"expired": func(i *fakeIdP) {
			i.mutateClaims = func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }
		},
		"wrong aud": func(i *fakeIdP) { i.mutateClaims = func(c map[string]any) { c["aud"] = "someone-else" } },
		"wrong iss": func(i *fakeIdP) { i.mutateClaims = func(c map[string]any) { c["iss"] = "https://evil.example/" } },
		"no exp":    func(i *fakeIdP) { i.mutateClaims = func(c map[string]any) { delete(c, "exp") } },
		"no sub":    func(i *fakeIdP) { i.mutateClaims = func(c map[string]any) { delete(c, "sub") } },
		"iat future": func(i *fakeIdP) {
			i.mutateClaims = func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }
		},
		"multi aud without azp": func(i *fakeIdP) {
			i.mutateClaims = func(c map[string]any) { c["aud"] = []string{testClientID, "other"} }
		},
		"forged signature (foreign RSA key)": func(i *fakeIdP) {
			evil := newFakeIdP(t)
			i.idTokenSigner = func(claims map[string]any) string {
				return signWith(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: evil.rsaKey, KeyID: i.kid}}, claims)
			}
		},
		"forged signature (foreign EC key)": func(i *fakeIdP) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			i.idTokenSigner = func(claims map[string]any) string {
				return signWith(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: k, KeyID: i.kid + "-ec"}}, claims)
			}
		},
		"HS256 not advertised (alg confusion)": func(i *fakeIdP) {
			pub, _ := x509.MarshalPKIXPublicKey(&i.rsaKey.PublicKey)
			i.idTokenSigner = func(claims map[string]any) string {
				return signWith(jose.SigningKey{Algorithm: jose.HS256, Key: pub}, claims)
			}
		},
		"HS256 signed with wrong secret": func(i *fakeIdP) {
			i.advertise = []string{"HS256"}
			i.idTokenSigner = func(claims map[string]any) string {
				return signWith(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("not-the-secret-not-the-secret")}, claims)
			}
		},
		"alg none": func(i *fakeIdP) {
			i.idTokenSigner = func(claims map[string]any) string {
				h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
				cj, _ := json.Marshal(claims)
				return h + "." + base64.RawURLEncoding.EncodeToString(cj) + "."
			}
		},
		"tampered payload": func(i *fakeIdP) {
			i.idTokenSigner = func(claims map[string]any) string {
				good := signWith(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: i.rsaKey, KeyID: i.kid}}, claims)
				parts := strings.Split(good, ".")
				claims["sub"] = "admin"
				cj, _ := json.Marshal(claims)
				return parts[0] + "." + base64.RawURLEncoding.EncodeToString(cj) + "." + parts[2]
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			setup(idp)
			ar := newTestRouter(t, idp, nil)
			b := newBrowser(t, ar)
			w := b.login(idp, appURL+"/")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("bad token accepted: %d %s", w.Code, w.Body.String())
			}
			if _, ok := b.cookies[sessionCookie]; ok {
				t.Fatal("session issued for bad token")
			}
		})
	}
}

func TestMissingIDTokenWithOpenIDScopeRejected(t *testing.T) {
	idp := newFakeIdP(t)
	idp.idTokenSigner = nil
	ar := newTestRouter(t, idp, nil)
	// strip id_token from the token response via a proxying client
	ar.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err == nil && strings.HasSuffix(r.URL.Path, "/token/") {
			var m map[string]any
			json.NewDecoder(resp.Body).Decode(&m)
			delete(m, "id_token")
			b, _ := json.Marshal(m)
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			rec.Write(b)
			return rec.Result(), nil
		}
		return resp, err
	})}
	b := newBrowser(t, ar)
	if w := b.login(idp, appURL+"/"); w.Code != http.StatusUnauthorized {
		t.Fatalf("accepted login without id_token: %d", w.Code)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestES256AndHS256Accepted(t *testing.T) {
	for _, alg := range []string{"ES256", "HS256"} {
		t.Run(alg, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.signAlg = alg
			idp.advertise = []string{alg}
			ar := newTestRouter(t, idp, nil)
			mustLogin(t, newBrowser(t, ar), idp)
		})
	}
}

func TestJWKSRefreshOnUnknownKid(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	ar.jwks.minRefresh = time.Millisecond
	mustLogin(t, newBrowser(t, ar), idp)
	first := idp.jwksFetches
	if first != 1 {
		t.Fatalf("expected one JWKS fetch, got %d", first)
	}
	// A second login must use the cache.
	mustLogin(t, newBrowser(t, ar), idp)
	if idp.jwksFetches != first {
		t.Fatalf("JWKS not cached (%d fetches)", idp.jwksFetches)
	}
	// Provider rotates keys: unknown kid triggers a refresh and login keeps working.
	idp.rotate()
	time.Sleep(5 * time.Millisecond)
	mustLogin(t, newBrowser(t, ar), idp)
	if idp.jwksFetches != first+1 {
		t.Fatalf("expected refresh on unknown kid, fetches=%d", idp.jwksFetches)
	}
}

func TestJWKSUnknownKidRefreshIsRateLimited(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	mustLogin(t, newBrowser(t, ar), idp)
	before := idp.jwksFetches
	idp.rotate()
	for i := 0; i < 5; i++ {
		b := newBrowser(t, ar)
		w := b.login(idp, appURL+"/")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected rate-limited refresh to fail closed, got %d", w.Code)
		}
	}
	if idp.jwksFetches != before {
		t.Fatalf("JWKS refetched %d times inside rate-limit window", idp.jwksFetches-before)
	}
}

func TestGroupAllowList(t *testing.T) {
	idp := newFakeIdP(t)
	idp.user["groups"] = []any{"staff", "ops"}
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) { o.OAuth2AllowedGroups = "admins, ops" })
	mustLogin(t, newBrowser(t, ar), idp)

	idp.user["groups"] = []any{"staff"}
	b := newBrowser(t, ar)
	w := b.login(idp, appURL+"/")
	if w.Code != http.StatusForbidden {
		t.Fatalf("user outside allow-list: %d", w.Code)
	}
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Fatal("session issued to denied user")
	}

	// custom claim name
	idp.user["roles"] = []any{"vpn"}
	ar2 := newTestRouter(t, idp, func(o *OAuth2RouterOptions) {
		o.OAuth2AllowedGroups = "vpn"
		o.OAuth2GroupsClaim = "roles"
	})
	mustLogin(t, newBrowser(t, ar2), idp)

	// missing claim fails closed
	delete(idp.user, "roles")
	if w := newBrowser(t, ar2).login(idp, appURL+"/"); w.Code != http.StatusForbidden {
		t.Fatalf("missing claim must deny: %d", w.Code)
	}
}

func TestGroupsFromUserinfoWhenNotInIDToken(t *testing.T) {
	idp := newFakeIdP(t)
	idp.mutateClaims = func(c map[string]any) { delete(c, "groups") }
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) { o.OAuth2AllowedGroups = "users" })
	mustLogin(t, newBrowser(t, ar), idp)
}

func TestHeaderMappingParsing(t *testing.T) {
	m, err := ParseHeaderMappings("X-Auth-User=preferred_username, x-auth-groups=groups")
	if err != nil || len(m) != 2 || m[1].Header != "X-Auth-Groups" {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"Host=email", "Authorization=email", "X-A B=email", "noequals", "=claim", "X-Forwarded-For=email", "Cookie=x"} {
		if _, err := ParseHeaderMappings(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHeaderInjectionSanitised(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	applyHeaderMappings(r, []HeaderMapping{{"X-Auth-User", "u"}}, map[string]any{"u": "bob\r\nX-Evil: 1"})
	if strings.ContainsAny(r.Header.Get("X-Auth-User"), "\r\n") {
		t.Fatal("control characters survived")
	}
	if r.Header.Get("X-Evil") != "" {
		t.Fatal("header injection")
	}
}

func TestRefreshFlow(t *testing.T) {
	idp := newFakeIdP(t)
	idp.expiresIn = 30 // inside the 60s refresh skew: first use after login must refresh
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) {
		o.OAuth2AllowedGroups = "users"
		o.OAuth2HeaderMappings = "X-Auth-Groups=groups"
	})
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)

	idp.expiresIn = 3600
	r := b.request("GET", appURL+"/dash")
	if w, err := b.do(r); err != nil {
		t.Fatalf("refresh should keep the session alive: %d", w.Code)
	}
	if idp.refreshCount != 1 {
		t.Fatalf("refresh count %d", idp.refreshCount)
	}
	// now fresh for an hour: no further refreshes
	b.do(b.request("GET", appURL+"/dash"))
	if idp.refreshCount != 1 {
		t.Fatalf("unexpected extra refresh: %d", idp.refreshCount)
	}

	// Group membership is re-evaluated: force the next refresh and drop the group at the provider.
	for _, item := range ar.store.sessions.Items() {
		s := item.Value()
		s.mu.Lock()
		s.accessExpiry = time.Now().Add(10 * time.Second)
		s.mu.Unlock()
	}
	idp.user = map[string]any{"sub": "user-1", "groups": []any{"nobody"}}
	r = b.request("GET", appURL+"/dash")
	w, err := b.do(r)
	if err == nil || w.Code != http.StatusForbidden {
		t.Fatalf("revoked group not enforced after refresh: err=%v code=%d", err, w.Code)
	}
}

func TestRefreshFailureForcesRelogin(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	for _, item := range ar.store.sessions.Items() {
		item.Value().accessExpiry = time.Now().Add(5 * time.Second)
	}
	idp.failRefresh = true
	w, err := b.do(b.request("GET", appURL+"/dash"))
	if err == nil || w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), idp.URL+"/application/o/authorize/") {
		t.Fatalf("failed refresh must restart login: %d %q", w.Code, w.Header().Get("Location"))
	}
	if ar.store.sessions.Len() != 0 {
		t.Fatal("dead session not removed")
	}
}

func TestExpiredAccessTokenWithoutRefreshTokenRelogin(t *testing.T) {
	idp := newFakeIdP(t)
	idp.withRefresh = false
	idp.expiresIn = 3600
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	if _, err := b.do(b.request("GET", appURL+"/")); err != nil {
		t.Fatal("session should be valid")
	}
	for _, item := range ar.store.sessions.Items() {
		item.Value().accessExpiry = time.Now().Add(-time.Minute)
	}
	if w, err := b.do(b.request("GET", appURL+"/")); err == nil || w.Code != http.StatusFound {
		t.Fatalf("expired session accepted: %d", w.Code)
	}
}

func TestLogoutRPInitiated(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) { o.OAuth2PostLogoutRedirectUrl = "https://app.example.com/" })
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	w, err := b.do(b.request("GET", appURL+"/internal/oauth2/logout"))
	if err == nil || w.Code != http.StatusFound {
		t.Fatalf("logout: %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), idp.URL+"/application/o/app/end-session/") {
		t.Fatalf("not redirected to end_session_endpoint: %s", loc)
	}
	q := loc.Query()
	if q.Get("id_token_hint") == "" || q.Get("client_id") != testClientID ||
		q.Get("post_logout_redirect_uri") != "https://app.example.com/" {
		t.Fatalf("bad logout params: %v", q)
	}
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Fatal("cookie not cleared")
	}
	if ar.store.sessions.Len() != 0 {
		t.Fatal("session not destroyed server side")
	}
	// the old cookie must not work any more
	if _, err := b.do(b.request("GET", appURL+"/")); err == nil {
		t.Fatal("request authenticated after logout")
	}
}

func TestLogoutIgnoresCallerSuppliedRedirect(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	w, _ := b.do(b.request("GET", appURL+"/internal/oauth2/logout?post_logout_redirect_uri=https://evil.example/&rd=https://evil.example"))
	if strings.Contains(w.Header().Get("Location"), "evil.example") {
		t.Fatalf("caller supplied redirect reflected: %s", w.Header().Get("Location"))
	}
}

func TestOpenRedirectAttemptsCollapse(t *testing.T) {
	for in, want := range map[string]string{
		"/dash?x=1":             "/dash?x=1",
		"//evil.example/x":      "/",
		"/\\evil.example":       "/",
		"http://evil.example/":  "/",
		"https://evil.example/": "/",
		"javascript:alert(1)":   "/",
		"":                      "/",
		"/ok\r\nSet-Cookie: a":  "/",
		"/internal/oauth2?code": "/",
	} {
		if got := safeReturnPath(in); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
	// end to end: a request whose URI is scheme-relative must come back to "/"
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	r := b.request("GET", appURL+"/x")
	r.URL.Path = "//evil.example/steal"
	w := httptest.NewRecorder()
	ar.HandleOAuth2Auth(w, r)
	b.absorb(w)
	cb, _ := idp.authorize(t, w.Header().Get("Location"))
	cw, _ := b.do(b.request("GET", cb))
	if cw.Header().Get("Location") != "/" {
		t.Fatalf("post-login redirect = %q", cw.Header().Get("Location"))
	}
}

func TestSessionCookieTamperAndHostBinding(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	good := b.cookies[sessionCookie]

	// bit-flipped signature
	bad := *good
	bad.Value = good.Value[:len(good.Value)-1] + "0"
	if good.Value[len(good.Value)-1] == '0' {
		bad.Value = good.Value[:len(good.Value)-1] + "1"
	}
	r := httptest.NewRequest("GET", appURL+"/", nil)
	r.AddCookie(&bad)
	if err := ar.HandleOAuth2Auth(httptest.NewRecorder(), r); err == nil {
		t.Fatal("tampered cookie accepted")
	}
	// unsigned id guess
	id := strings.Split(good.Value, ".")[0]
	r = httptest.NewRequest("GET", appURL+"/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
	if err := ar.HandleOAuth2Auth(httptest.NewRecorder(), r); err == nil {
		t.Fatal("unsigned session id accepted")
	}
	// same valid cookie replayed against another host
	r = httptest.NewRequest("GET", "http://other.example.com/", nil)
	r.AddCookie(good)
	if err := ar.HandleOAuth2Auth(httptest.NewRecorder(), r); err == nil {
		t.Fatal("cookie accepted on a different host")
	}
	// cookie signed by a node with a different UUID
	ar2 := newTestRouter(t, idp, func(o *OAuth2RouterOptions) { o.SystemUUID = "another-node" })
	r = httptest.NewRequest("GET", appURL+"/", nil)
	r.AddCookie(good)
	if err := ar2.HandleOAuth2Auth(httptest.NewRecorder(), r); err == nil {
		t.Fatal("cookie from another node accepted")
	}
}

func TestProviderErrorFailsClosed(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	idp.Close()
	b := newBrowser(t, ar)
	w, err := b.do(b.request("GET", appURL+"/"))
	if err == nil || w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestIssuerMismatchInDiscoveryRejected(t *testing.T) {
	idp := newFakeIdP(t)
	idp.issuerOver = "https://evil.example/"
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) { o.OAuth2Issuer = idp.URL + "/application/o/app/" })
	b := newBrowser(t, ar)
	if w, err := b.do(b.request("GET", appURL+"/")); err == nil || w.Code != http.StatusInternalServerError {
		t.Fatalf("issuer mismatch accepted: %d", w.Code)
	}
}

func TestErrorFromProviderOnCallback(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	b := newBrowser(t, ar)
	w, _ := b.do(b.request("GET", appURL+"/"))
	st := mustQuery(t, w.Header().Get("Location"), "state")
	cw, _ := b.do(b.request("GET", appURL+"/internal/oauth2?error=access_denied&error_description=<script>&state="+st))
	if cw.Code != http.StatusForbidden || strings.Contains(cw.Body.String(), "script") {
		t.Fatalf("%d %q", cw.Code, cw.Body.String())
	}
}

func mustQuery(t *testing.T, raw, key string) string {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

/* Backwards compatibility with configs written by the previous implementation */

func TestLegacyWellKnownOnlyConfig(t *testing.T) {
	idp := newFakeIdP(t)
	// previous config: well-known URL, client id/secret, no issuer, no PKCE, no scopes
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) {
		o.OAuth2Issuer = ""
		o.OAuth2CodeChallengeMethod = ""
		o.OAuth2WellKnownUrl = idp.URL + "/application/o/app/.well-known/openid-configuration"
	})
	b := newBrowser(t, ar)
	w, _ := b.do(b.request("GET", appURL+"/"))
	if strings.Contains(w.Header().Get("Location"), "code_challenge") {
		t.Fatal("PKCE must stay off when the legacy method is empty")
	}
	mustLogin(t, newBrowser(t, ar), idp)
}

func TestLegacyManualEndpointsPlainOAuth2(t *testing.T) {
	idp := newFakeIdP(t)
	idp.idTokenSigner = nil
	// Plain OAuth2 (no openid scope): identity comes from the userinfo endpoint.
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) {
		o.OAuth2Issuer = ""
		o.OAuth2CodeChallengeMethod = ""
		o.OAuth2ServerURL = idp.URL + "/application/o/authorize/"
		o.OAuth2TokenURL = idp.URL + "/application/o/token/"
		o.OAuth2UserInfoUrl = idp.URL + "/application/o/userinfo/"
		o.OAuth2Scopes = "profile,email"
	})
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	// userinfo failing at login must fail closed
	idp.userinfoOK = false
	if w := newBrowser(t, ar).login(idp, appURL+"/"); w.Code != http.StatusUnauthorized {
		t.Fatalf("plain oauth2 login without userinfo accepted: %d", w.Code)
	}
}

func TestLegacySettingsKeysLoadedFromDatabase(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	db := ar.options.Database
	db.Write("oauth2", "oauth2WellKnownUrl", idp.URL+"/application/o/app/.well-known/openid-configuration")
	db.Write("oauth2", "oauth2ClientId", testClientID)
	db.Write("oauth2", "oauth2ClientSecret", testClientSecret)
	db.Write("oauth2", "oauth2CodeChallengeMethod", "PKCE_S256")
	d := 2 * time.Minute
	db.Write("oauth2", "oauth2ConfigurationCacheTime", &d)
	lg := ar.options.Logger
	ar2 := NewOAuth2Router(&OAuth2RouterOptions{Logger: lg, Database: db})
	defer ar2.Close()
	o := ar2.snapshot()
	if o.OAuth2ClientId != testClientID || o.OAuth2CodeChallengeMethod != "PKCE_S256" || *o.OAuth2ConfigurationCacheTime != d ||
		o.OAuth2WellKnownUrl == "" || o.OAuth2Issuer != "" || o.OAuth2AllowedGroups != "" {
		t.Fatalf("unexpected options %+v", o)
	}
	mustLogin(t, newBrowser(t, ar2), idp)
}

/* Settings + discovery test endpoint */

func postForm(h http.HandlerFunc, method string, vals url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/sso/OAuth2", strings.NewReader(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestSettingsAPIRoundTripAndValidation(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	ok := url.Values{
		"oauth2ClientId": {testClientID}, "oauth2ClientSecret": {testClientSecret},
		"oauth2Issuer": {idp.issuer()}, "oauth2CodeChallengeMethod": {"PKCE_S256"},
		"oauth2AllowedGroups": {"admins"}, "oauth2GroupsClaim": {"groups"},
		"oauth2HeaderMappings": {"X-Auth-User=preferred_username"},
	}
	if w := postForm(ar.HandleSetOAuth2Settings, "POST", ok); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	w := postForm(ar.HandleSetOAuth2Settings, "GET", nil)
	var got map[string]string
	json.Unmarshal(w.Body.Bytes(), &got)
	if got["oauth2Issuer"] != idp.issuer() || got["oauth2AllowedGroups"] != "admins" {
		t.Fatalf("%v", got)
	}
	for name, mod := range map[string]func(v url.Values){
		"bad mapping":   func(v url.Values) { v.Set("oauth2HeaderMappings", "Host=email") },
		"bad pkce":      func(v url.Values) { v.Set("oauth2CodeChallengeMethod", "weird") },
		"bad issuer":    func(v url.Values) { v.Set("oauth2Issuer", "javascript:alert(1)") },
		"no endpoints":  func(v url.Values) { v.Del("oauth2Issuer") },
		"missing id":    func(v url.Values) { v.Del("oauth2ClientId") },
		"missing secre": func(v url.Values) { v.Del("oauth2ClientSecret") },
	} {
		v := url.Values{}
		for k, x := range ok {
			v[k] = x
		}
		mod(v)
		if w := postForm(ar.HandleSetOAuth2Settings, "POST", v); !strings.Contains(w.Body.String(), "error") {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDiscoveryTestEndpoint(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	w := postForm(ar.HandleDiscoveryTest, "POST", url.Values{"oauth2Issuer": {idp.issuer()}})
	var res map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(w.Body.String())
	}
	if res["issuer"] != idp.issuer() || res["pkceS256Supported"] != true || res["jwksReachable"] != true ||
		res["jwksKeyCount"].(float64) != 2 || res["refreshSupported"] != true ||
		res["endSessionEndpoint"] == "" || res["tokenEndpoint"] == "" {
		t.Fatalf("%v", res)
	}
	// unreachable / wrong issuer
	w = postForm(ar.HandleDiscoveryTest, "POST", url.Values{"oauth2Issuer": {idp.URL + "/nope/"}})
	if !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("expected error: %s", w.Body.String())
	}
	// no PKCE support gets a warning
	idp.pkceMeth = nil
	w = postForm(ar.HandleDiscoveryTest, "POST", url.Values{"oauth2Issuer": {idp.issuer()}})
	if !strings.Contains(w.Body.String(), "PKCE") {
		t.Fatalf("expected PKCE warning: %s", w.Body.String())
	}
	// non-http scheme refused
	w = postForm(ar.HandleDiscoveryTest, "POST", url.Values{"oauth2WellKnownUrl": {"file:///etc/passwd"}})
	if !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("file scheme must be refused: %s", w.Body.String())
	}
}
