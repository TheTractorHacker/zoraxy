package forward

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// Compatibility tests against fake servers that reproduce the documented forward-auth behaviour of
// oauth2-proxy (/oauth2/auth), Authelia (/api/authz/forward-auth) and VoidAuth (/api/authz/forward-auth).
// They back the upstream reports #698 (v3.2.3 redirect error), #958 (VoidAuth) and #1032 (oauth2-proxy
// behind a Cloudflare Tunnel).

type seenAuthReq struct {
	mu   sync.Mutex
	hdr  http.Header
	host string
}

func (s *seenAuthReq) record(r *http.Request) {
	s.mu.Lock()
	s.hdr = r.Header.Clone()
	s.host = r.Host
	s.mu.Unlock()
}

func (s *seenAuthReq) get(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hdr.Get(k)
}

// oauth2-proxy: GET /oauth2/auth -> 202 + X-Auth-Request-* when the session cookie is valid, else 401.
// The sign-in redirect URL it later builds from X-Forwarded-Proto/Host/Uri must be https for a tunnel.
func fakeOAuth2Proxy(t *testing.T, seen *seenAuthReq) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		if c, err := r.Cookie("_oauth2_proxy"); err == nil && c.Value == "ok" {
			w.Header().Set("X-Auth-Request-User", "alice")
			w.Header().Set("X-Auth-Request-Email", "alice@example.com")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestForwardOAuth2ProxySemantics(t *testing.T) {
	seen := &seenAuthReq{}
	op := fakeOAuth2Proxy(t, seen)
	ar := newTestRouter(t, func(o *AuthRouterOptions) {
		o.Address = op.URL + "/oauth2/auth"
		o.ResponseHeaders = []string{"X-Auth-Request-User", "X-Auth-Request-Email"}
	})

	// 202 Accepted counts as success and identity headers are copied to the upstream request.
	r := httptest.NewRequest("GET", "http://app.example.com/x", nil)
	r.AddCookie(&http.Cookie{Name: "_oauth2_proxy", Value: "ok"})
	w := httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err != nil {
		t.Fatalf("202 must be treated as allow, got %v", err)
	}
	if r.Header.Get("X-Auth-Request-User") != "alice" || r.Header.Get("X-Auth-Request-Email") != "alice@example.com" {
		t.Fatalf("identity headers not copied: %v", r.Header)
	}

	// 401 is relayed and blocks.
	r = httptest.NewRequest("GET", "http://app.example.com/x", nil)
	w = httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err != ErrUnauthorized {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
	if w.Code != 401 {
		t.Fatalf("code = %d", w.Code)
	}
	// Spoofed identity headers from the client must not reach the upstream.
	r = httptest.NewRequest("GET", "http://app.example.com/x", nil)
	r.Header.Set("X-Auth-Request-User", "admin")
	w = httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err == nil {
		t.Fatal("unauthenticated request must be blocked")
	}
}

// Behind a Cloudflare Tunnel the TCP peer is cloudflared (plain HTTP hop). oauth2-proxy must be told
// the browser used https and who the client is, otherwise its redirect_uri is http:// and the login loops.
func TestForwardBehindTLSTerminatingTunnel(t *testing.T) {
	seen := &seenAuthReq{}
	op := fakeOAuth2Proxy(t, seen)
	trusted := map[string]bool{"10.1.2.3": true}
	ar := newTestRouter(t, func(o *AuthRouterOptions) {
		o.Address = op.URL + "/oauth2/auth"
		o.IsTrustedProxy = func(ip string) bool { return trusted[ip] }
	})

	mk := func(peer string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/path?q=1", nil)
		r.RemoteAddr = peer + ":4444"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("CF-Connecting-IP", "203.0.113.9")
		return r
	}

	// Trusted tunnel peer: scheme and client IP are taken from the tunnel's headers.
	ar.HandleAuthProviderRouting(httptest.NewRecorder(), mk("10.1.2.3"))
	if got := seen.get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("trusted peer: auth saw X-Forwarded-Proto %q, want https", got)
	}
	if got := seen.get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Fatalf("trusted peer: auth saw X-Forwarded-For %q, want the real client", got)
	}

	// Untrusted peer: it cannot choose the scheme or client address.
	ar.HandleAuthProviderRouting(httptest.NewRecorder(), mk("198.51.100.7"))
	if got := seen.get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("untrusted peer: auth saw X-Forwarded-Proto %q, want http", got)
	}
	if got := seen.get("X-Forwarded-For"); got != "198.51.100.7" {
		t.Fatalf("untrusted peer: auth saw X-Forwarded-For %q, want the TCP peer", got)
	}

	// X-Original-* mode keeps the same guarantees and the original URL gets the right scheme.
	ar.options.UseXOriginalHeaders = true
	ar.HandleAuthProviderRouting(httptest.NewRecorder(), mk("10.1.2.3"))
	if got := seen.get("X-Original-Url"); got != "https://app.example.com/path?q=1" {
		t.Fatalf("X-Original-URL = %q", got)
	}
	if got := seen.get("X-Original-Ip"); got != "203.0.113.9" {
		t.Fatalf("X-Original-IP = %q", got)
	}
	ar.HandleAuthProviderRouting(httptest.NewRecorder(), mk("198.51.100.7"))
	if got := seen.get("X-Original-Url"); got != "http://app.example.com/path?q=1" {
		t.Fatalf("untrusted X-Original-URL = %q", got)
	}
}

// Authelia answers an unauthenticated browser navigation with 302 + Location to its portal (the portal
// URL contains the rd= target). Zoraxy has to pass the redirect through untouched (#698).
func TestForwardAutheliaRedirectPassthrough(t *testing.T) {
	var seen seenAuthReq
	au := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		if r.Header.Get("Cookie") == "authelia_session=good" {
			w.Header().Set("Remote-User", "bob")
			w.Header().Set("Remote-Groups", "dev,admins")
			w.Header().Set("Remote-Email", "bob@example.com")
			w.Header().Set("Remote-Name", "Bob")
			w.WriteHeader(200)
			return
		}
		if r.Header.Get("X-Forwarded-Method") == "GET" && r.Header.Get("Accept") != "application/json" {
			rd := r.Header.Get("X-Forwarded-Proto") + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
			w.Header().Set("Location", "https://auth.example.com/?rd="+url.QueryEscape(rd)+"&rm=GET")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer au.Close()
	ar := newTestRouter(t, func(o *AuthRouterOptions) {
		o.Address = au.URL + "/api/authz/forward-auth"
		o.ResponseHeaders = []string{"Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name"}
		o.IsTrustedProxy = func(string) bool { return false }
	})

	// Unauthenticated browser navigation: 302 with the portal Location is relayed as-is.
	r := httptest.NewRequest("GET", "http://app.example.com/dash", nil)
	w := httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err != ErrUnauthorized {
		t.Fatalf("got %v", err)
	}
	if w.Code != 302 {
		t.Fatalf("status %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://auth.example.com/?rd=http%3A%2F%2Fapp.example.com%2Fdash&rm=GET" {
		t.Fatalf("Location = %q", loc)
	}
	// Authelia reads X-Forwarded-Method/Host/Uri.
	if seen.get("X-Forwarded-Method") != "GET" || seen.get("X-Forwarded-Host") != "app.example.com" || seen.get("X-Forwarded-Uri") != "/dash" {
		t.Fatalf("authelia headers missing: %v", seen.hdr)
	}

	// Authenticated: Remote-* copied to the upstream request.
	r = httptest.NewRequest("GET", "http://app.example.com/dash", nil)
	r.Header.Set("Cookie", "authelia_session=good")
	if err := ar.HandleAuthProviderRouting(httptest.NewRecorder(), r); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get("Remote-User") != "bob" || r.Header.Get("Remote-Groups") != "dev,admins" || r.Header.Get("Remote-Name") != "Bob" {
		t.Fatalf("Remote-* not copied: %v", r.Header)
	}
}

// VoidAuth (#958): the session cookie is set by the auth server on its own domain; the auth subrequest must
// carry the browser Cookie header and Zoraxy must relay Set-Cookie from the auth reply when configured, and
// must not follow the auth server's redirect itself (which would otherwise look like a loop).
func TestForwardVoidAuthCookieAndRedirect(t *testing.T) {
	var seen seenAuthReq
	var hits int
	var mu sync.Mutex
	va := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		mu.Lock()
		hits++
		mu.Unlock()
		if c, err := r.Cookie("voidauth_session"); err == nil && c.Value == "s1" {
			w.Header().Set("Remote-User", "carol")
			w.Header().Add("Set-Cookie", "voidauth_session=s1; Path=/; Max-Age=3600; Domain=example.com")
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Location", "https://void.example.com/login?redirect="+url.QueryEscape(r.Header.Get("X-Forwarded-Proto")+"://"+r.Header.Get("X-Forwarded-Host")+r.Header.Get("X-Forwarded-Uri")))
		w.WriteHeader(http.StatusFound)
	}))
	defer va.Close()
	ar := newTestRouter(t, func(o *AuthRouterOptions) {
		o.Address = va.URL + "/api/authz/forward-auth"
		o.ResponseHeaders = []string{"Remote-User"}
		o.ResponseClientHeaders = []string{"Set-Cookie"}
	})

	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	w := httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err != ErrUnauthorized || w.Code != 302 {
		t.Fatalf("err=%v code=%d", err, w.Code)
	}
	mu.Lock()
	if hits != 1 {
		t.Fatalf("auth redirect must not be followed by Zoraxy, hits=%d", hits)
	}
	mu.Unlock()

	r = httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.AddCookie(&http.Cookie{Name: "voidauth_session", Value: "s1"})
	w = httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err != nil {
		t.Fatal(err)
	}
	if seen.get("Cookie") != "voidauth_session=s1" {
		t.Fatalf("session cookie did not reach the auth server: %q", seen.get("Cookie"))
	}
	if w.Header().Get("Set-Cookie") == "" {
		t.Fatal("Set-Cookie from the auth server was not relayed to the browser")
	}
	if r.Header.Get("Remote-User") != "carol" {
		t.Fatal("Remote-User not copied")
	}
}
