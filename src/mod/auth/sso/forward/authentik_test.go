package forward

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

// fakeOutpost emulates the parts of an Authentik proxy outpost that Zoraxy talks to.
type fakeOutpost struct {
	*httptest.Server
	mu       sync.Mutex
	lastAuth http.Header
	authHost string
	lastPath string
	lastHost string
}

func newFakeOutpost(t *testing.T) *fakeOutpost {
	fo := &fakeOutpost{}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) {
		fo.mu.Lock()
		fo.lastAuth = r.Header.Clone()
		fo.authHost = r.Host
		fo.mu.Unlock()
		if c, err := r.Cookie("authentik_proxy_session"); err != nil || c.Value != "good" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("sign in required"))
			return
		}
		w.Header().Set("X-authentik-username", "akadmin")
		w.Header().Set("X-authentik-groups", "admins|users")
		w.Header().Set("X-authentik-email", "a@example.com")
		w.Header().Set("X-authentik-meta-app", "myapp")
		w.Header().Set("Set-Cookie", "authentik_proxy_session=good; Path=/")
		w.Header().Set("X-Not-Listed", "leak")
		w.WriteHeader(http.StatusOK)
	}
	mux.HandleFunc("/outpost.goauthentik.io/auth/nginx", auth)
	mux.HandleFunc("/outpost.goauthentik.io/auth/traefik", auth)
	mux.HandleFunc("/outpost.goauthentik.io/", func(w http.ResponseWriter, r *http.Request) {
		fo.mu.Lock()
		fo.lastPath = r.URL.RequestURI()
		fo.lastHost = r.Host
		fo.mu.Unlock()
		w.Header().Set("X-Seen-Original-URL", r.Header.Get("X-Original-URL"))
		w.Header().Set("X-Seen-Fwd-Host", r.Header.Get("X-Forwarded-Host"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("outpost:" + r.URL.Path))
	})
	fo.Server = httptest.NewServer(mux)
	t.Cleanup(fo.Close)
	return fo
}

func newTestRouter(t *testing.T, mutate func(o *AuthRouterOptions)) *AuthRouter {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "fwd.db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	lg, _ := logger.NewFmtLogger()
	o := &AuthRouterOptions{Logger: lg, Database: db}
	ar := NewAuthRouter(o)
	if mutate != nil {
		mutate(o)
		ar.initOutpostProxy()
	}
	return ar
}

func authentikPreset(fo *fakeOutpost, variant string) func(o *AuthRouterOptions) {
	return func(o *AuthRouterOptions) {
		o.Address = fo.URL + "/outpost.goauthentik.io/auth/" + variant
		o.OutpostURL = fo.URL
		o.StartRedirect = StartRedirectLocal
		o.PreserveHost = true
		o.UseXOriginalHeaders = variant == "nginx"
		o.ResponseHeaders = []string{"X-authentik-username", "X-authentik-groups", "X-authentik-email", "X-authentik-meta-*"}
		o.ResponseClientHeaders = []string{"Set-Cookie"}
	}
}

func browserReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("Accept", "text/html")
	return r
}

func TestForwardAuthentikAllowCopiesHeadersAndStripsSpoofed(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, authentikPreset(fo, "nginx"))

	r := browserReq("GET", "http://app.example.com/dash?x=1")
	r.AddCookie(&http.Cookie{Name: "authentik_proxy_session", Value: "good"})
	// Attacker supplied identity + forwarding headers.
	r.Header.Set("X-authentik-username", "root")
	r.Header.Set("X-authentik-meta-evil", "1")
	r.Header.Set("X-authentik-uid", "spoof") // not in the configured list, still ours to forward as-is
	r.Header.Set("X-Original-URL", "https://evil.example/")
	r.Header.Set("X-Forwarded-Host", "evil.example")
	w := httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if got := r.Header.Get("X-authentik-username"); got != "akadmin" {
		t.Fatalf("username = %q", got)
	}
	if got := r.Header.Get("X-authentik-groups"); got != "admins|users" {
		t.Fatalf("groups = %q", got)
	}
	if got := r.Header.Get("X-authentik-meta-app"); got != "myapp" {
		t.Fatalf("meta app = %q", got)
	}
	if r.Header.Get("X-authentik-meta-evil") != "" {
		t.Fatal("spoofed X-authentik-meta-* header was not stripped (wildcard)")
	}
	if r.Header.Get("X-authentik-uid") != "" {
		t.Fatal("unlisted spoofed X-authentik-uid reached upstream")
	}
	if r.Header.Get("X-Not-Listed") != "" {
		t.Fatal("unlisted header leaked")
	}
	if w.Header().Get("Set-Cookie") == "" {
		t.Fatal("Set-Cookie not relayed to client")
	}
	fo.mu.Lock()
	defer fo.mu.Unlock()
	if got := fo.lastAuth.Get("X-Original-URL"); got != "http://app.example.com/dash?x=1" {
		t.Fatalf("X-Original-URL = %q", got)
	}
	if fo.lastAuth.Get("X-Forwarded-Host") != "app.example.com" {
		t.Fatalf("client supplied X-Forwarded-Host reached outpost: %q", fo.lastAuth.Get("X-Forwarded-Host"))
	}
	if fo.authHost != "app.example.com" {
		t.Fatalf("subrequest Host = %q, want protected host", fo.authHost)
	}
}

func TestForwardAuthentikTraefikVariantHeaders(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, authentikPreset(fo, "traefik"))
	r := browserReq("GET", "http://app.example.com/a/b?q=2")
	r.AddCookie(&http.Cookie{Name: "authentik_proxy_session", Value: "good"})
	r.Header.Set("X-Original-URL", "https://evil.example/")
	if err := ar.HandleAuthProviderRouting(httptest.NewRecorder(), r); err != nil {
		t.Fatal(err)
	}
	fo.mu.Lock()
	defer fo.mu.Unlock()
	if fo.lastAuth.Get("X-Forwarded-Uri") != "/a/b?q=2" || fo.lastAuth.Get("X-Forwarded-Host") != "app.example.com" ||
		fo.lastAuth.Get("X-Forwarded-Proto") != "http" {
		t.Fatalf("bad forwarded headers: %v", fo.lastAuth)
	}
	if fo.lastAuth.Get("X-Original-Url") != "" {
		t.Fatal("client X-Original-URL reached outpost in X-Forwarded mode")
	}
}

func TestForwardAuthentikDenyRedirectsToStart(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, authentikPreset(fo, "nginx"))
	r := browserReq("GET", "http://app.example.com/secret?a=b&c=d")
	w := httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err == nil {
		t.Fatal("expected deny")
	}
	if w.Code != http.StatusFound {
		t.Fatalf("status %d", w.Code)
	}
	loc := w.Header().Get("Location")
	want := "/outpost.goauthentik.io/start?rd=" + url.QueryEscape("http://app.example.com/secret?a=b&c=d")
	if loc != want {
		t.Fatalf("Location = %q want %q", loc, want)
	}
}

func TestForwardAuthentikOutpostModeRedirect(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, func(o *AuthRouterOptions) {
		authentikPreset(fo, "nginx")(o)
		o.StartRedirect = StartRedirectOutpost
	})
	w := httptest.NewRecorder()
	ar.HandleAuthProviderRouting(w, browserReq("GET", "http://app.example.com/"))
	if !strings.HasPrefix(w.Header().Get("Location"), fo.URL+"/outpost.goauthentik.io/start?rd=") {
		t.Fatalf("Location = %q", w.Header().Get("Location"))
	}
}

func TestForwardAuthentikRedirectNotReflectingClientInput(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, authentikPreset(fo, "nginx"))
	r := browserReq("GET", "http://app.example.com/x?rd=https://evil.example/&redirect=//evil.example")
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Original-URL", "https://evil.example/")
	w := httptest.NewRecorder()
	ar.HandleAuthProviderRouting(w, r)
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/outpost.goauthentik.io/start?rd=") {
		t.Fatalf("redirect must be local, got %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host != "" {
		t.Fatalf("redirect not relative: %q", loc)
	}
	rd := u.Query().Get("rd")
	if !strings.HasPrefix(rd, "http://app.example.com/") {
		t.Fatalf("rd not anchored to protected host: %q", rd)
	}
}

func TestForwardAuthentikAPIClientGetsPlain401(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, authentikPreset(fo, "nginx"))
	r := httptest.NewRequest("GET", "http://app.example.com/api", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, r); err == nil {
		t.Fatal("expected deny")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestForwardAuthentikOutpostCallbackProxying(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, authentikPreset(fo, "nginx"))

	r := browserReq("GET", "http://app.example.com/outpost.goauthentik.io/callback?code=1&state=2")
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Original-URL", "https://evil.example/")
	w := httptest.NewRecorder()
	err := ar.HandleAuthProviderRouting(w, r)
	if err == nil {
		t.Fatal("proxied outpost request must be reported as handled")
	}
	if w.Code != 200 || w.Body.String() != "outpost:/outpost.goauthentik.io/callback" {
		t.Fatalf("not proxied: %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Seen-Fwd-Host") != "app.example.com" {
		t.Fatalf("forwarded host = %q", w.Header().Get("X-Seen-Fwd-Host"))
	}
	if !strings.HasPrefix(w.Header().Get("X-Seen-Original-URL"), "http://app.example.com/outpost.goauthentik.io/callback") {
		t.Fatalf("original url = %q", w.Header().Get("X-Seen-Original-URL"))
	}
	fo.mu.Lock()
	defer fo.mu.Unlock()
	if fo.lastHost != "app.example.com" {
		t.Fatalf("outpost saw Host %q", fo.lastHost)
	}
	if fo.lastPath != "/outpost.goauthentik.io/callback?code=1&state=2" {
		t.Fatalf("outpost saw %q", fo.lastPath)
	}
}

func TestForwardAuthentikOutpostPathBoundaries(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, authentikPreset(fo, "nginx"))
	for _, p := range []string{
		"/outpost.goauthentik.io.evil/x",
		"/outpost.goauthentik.io/../admin",
		"/outpost.goauthentik.io/%2e%2e/admin",
		"/other/outpost.goauthentik.io/start",
	} {
		r := browserReq("GET", "http://app.example.com"+p)
		w := httptest.NewRecorder()
		err := ar.HandleAuthProviderRouting(w, r)
		if err == nil || w.Code != http.StatusFound {
			t.Errorf("%s: expected authentication to be enforced, err=%v code=%d", p, err, w.Code)
		}
	}
}

func TestForwardOutpostProxyDisabledWithoutOutpostURL(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, func(o *AuthRouterOptions) {
		authentikPreset(fo, "nginx")(o)
		o.OutpostURL = ""
		o.StartRedirect = ""
	})
	w := httptest.NewRecorder()
	ar.HandleAuthProviderRouting(w, browserReq("GET", "http://app.example.com/outpost.goauthentik.io/start"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("without an outpost URL the path must be authenticated, got %d", w.Code)
	}
}

func TestForwardAuthFailsClosedWhenAuthServerDown(t *testing.T) {
	fo := newFakeOutpost(t)
	ar := newTestRouter(t, authentikPreset(fo, "nginx"))
	fo.Close()
	w := httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, browserReq("GET", "http://app.example.com/")); err == nil {
		t.Fatal("must fail closed")
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHeaderReplaceWildcard(t *testing.T) {
	dst := http.Header{}
	dst.Set("X-Authentik-Meta-A", "spoof")
	dst.Set("X-Other", "keep")
	src := http.Header{}
	src.Set("X-authentik-meta-b", "real")
	headerReplaceIncluded(src, dst, []string{"X-authentik-meta-*"})
	if dst.Get("X-Authentik-Meta-A") != "" || dst.Get("X-Authentik-Meta-B") != "real" || dst.Get("X-Other") != "keep" {
		t.Fatalf("unexpected: %v", dst)
	}
	// A bare "*" must not wipe everything.
	headerReplaceIncluded(src, dst, []string{"*"})
	if dst.Get("X-Other") != "keep" {
		t.Fatal("bare * must be ignored")
	}
}

func TestLegacyConfigStillWorks(t *testing.T) {
	// A pre-existing Authelia-style configuration (no outpost fields) keeps working unchanged.
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "ok" {
			w.Header().Set("Remote-User", "bob")
			return
		}
		w.Header().Set("Location", "https://auth.example/login")
		w.WriteHeader(401)
	}))
	defer auth.Close()
	ar := newTestRouter(t, func(o *AuthRouterOptions) {
		o.Address = auth.URL
		o.ResponseHeaders = []string{"Remote-User"}
		o.UseXOriginalHeaders = true
	})
	r := browserReq("GET", "http://app.example.com/")
	r.Header.Set("Authorization", "ok")
	r.Header.Set("Remote-User", "spoof")
	if err := ar.HandleAuthProviderRouting(httptest.NewRecorder(), r); err != nil || r.Header.Get("Remote-User") != "bob" {
		t.Fatalf("legacy allow failed: %v %q", err, r.Header.Get("Remote-User"))
	}
	w := httptest.NewRecorder()
	if err := ar.HandleAuthProviderRouting(w, browserReq("GET", "http://app.example.com/")); err == nil || w.Code != 302 ||
		w.Header().Get("Location") != "https://auth.example/login" {
		t.Fatalf("legacy redirect failed: %v %d %v", err, w.Code, w.Header())
	}
}
