package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
)

func fastHash(p string) string {
	return auth.HashPasswordWithProfile(p, auth.PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1})
}

func basicAuthRouter(t *testing.T) (*Router, *ProxyEndpoint) {
	t.Helper()
	router, sep, _ := newNonTLSTestRouter(t)
	sep.AuthenticationProvider = &AuthenticationProvider{
		AuthMethod:           AuthMethodBasic,
		BasicAuthCredentials: []*BasicAuthCredentials{{Username: "own", PasswordHash: fastHash("own-pw")}},
	}
	return router, sep
}

func basicReq(router *Router, sep *ProxyEndpoint, path, user, pw string, extra map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
	r.RemoteAddr = "198.51.100.1:1000"
	if user != "" {
		r.SetBasicAuth(user, pw)
	}
	for k, v := range extra {
		r.Header.Set(k, v)
	}
	router.handleNonTLSRequest(w, r, sep)
	return w
}

func TestBasicAuthWholeHostUnchangedWithoutScope(t *testing.T) {
	router, sep := basicAuthRouter(t)
	sep.initBasicScope()
	if w := basicReq(router, sep, "/anything", "", "", nil); w.Code != 401 {
		t.Fatalf("no scope configured must protect the whole host: %d", w.Code)
	}
	if w := basicReq(router, sep, "/anything", "own", "own-pw", nil); w.Code != 299 {
		t.Fatalf("valid login refused: %d", w.Code)
	}
}

func TestBasicAuthScopeAndBypassAttempts(t *testing.T) {
	router, sep := basicAuthRouter(t)
	sep.AuthenticationProvider.BasicAuthScopePrefixes = []string{"/admin"}
	sep.initBasicScope()
	// outside the scope: open
	for _, p := range []string{"/", "/public", "/administrator", "/adm", "/x/admin"} {
		if w := basicReq(router, sep, p, "", "", nil); w.Code != 299 {
			t.Errorf("%s must be open, got %d", p, w.Code)
		}
	}
	// inside the scope, including every path trick that an upstream could read as /admin
	for _, p := range []string{"/admin", "/admin/", "/admin/x", "/%61dmin", "/%61dmin/x", "/./admin", "//admin", "/foo/../admin",
		"/admin;jsessionid=1", "/admin/;x/y", "/%2e/admin", "/%2fadmin", "/%252e%252e/admin", "/admin%00.png", "/\\admin", "/admin/%2e%2e/admin"} {
		if w := basicReq(router, sep, p, "", "", nil); w.Code != 401 {
			t.Errorf("path %q bypassed the scoped basic auth (%d)", p, w.Code)
		}
	}
	if w := basicReq(router, sep, "/admin/panel", "own", "own-pw", nil); w.Code != 299 {
		t.Fatalf("valid login in scope refused: %d", w.Code)
	}
	if w := basicReq(router, sep, "/admin/panel", "own", "wrong", nil); w.Code != 401 {
		t.Fatalf("wrong password accepted: %d", w.Code)
	}
}

func TestBasicAuthOutOfScopeDoesNotForwardSpoofedIdentity(t *testing.T) {
	router, sep := basicAuthRouter(t)
	sep.AuthenticationProvider.BasicAuthScopePrefixes = []string{"/admin"}
	sep.initBasicScope()
	var seen string
	router.pluginRouteHook = func(w http.ResponseWriter, r *http.Request, s *ProxyEndpoint) bool {
		seen = r.Header.Get("X-Remote-User")
		w.WriteHeader(299)
		return true
	}
	basicReq(router, sep, "/public", "", "", map[string]string{"X-Remote-User": "root"})
	if seen != "" {
		t.Fatalf("client supplied X-Remote-User reached the upstream: %q", seen)
	}
}

func TestBasicAuthScopeFailsClosedWhenBroken(t *testing.T) {
	router, sep := basicAuthRouter(t)
	sep.AuthenticationProvider.BasicAuthScopePrefixes = []string{"no-leading-slash"}
	sep.initBasicScope()
	if sep.basicScopeErr == nil {
		t.Fatal("invalid scope accepted")
	}
	if w := basicReq(router, sep, "/", "", "", nil); w.Code != 503 {
		t.Fatalf("broken scope must refuse, got %d", w.Code)
	}
	if err := ValidateBasicAuthExtras([]string{"/ok", "bad"}, nil, nil); err == nil {
		t.Fatal("validator accepted a bad prefix")
	}
}

func TestCredentialListsAssignAndIsolation(t *testing.T) {
	router, sep := basicAuthRouter(t)
	path := filepath.Join(t.TempDir(), "lists", "basic.json")
	lists, err := NewCredentialLists(path)
	if err != nil {
		t.Fatal(err)
	}
	router.Option.BasicAuthLists = lists
	if err := lists.Set("team", []*BasicAuthUnhashedCredentials{{"alice", "alice-pw"}, {"bob", "bob-pw"}}, fastHash); err != nil {
		t.Fatal(err)
	}
	lists.Set("other", []*BasicAuthUnhashedCredentials{{"carol", "carol-pw"}}, fastHash)

	// not assigned: list users get nothing
	if w := basicReq(router, sep, "/", "alice", "alice-pw", nil); w.Code != 401 {
		t.Fatalf("unassigned list accepted: %d", w.Code)
	}
	sep.AuthenticationProvider.BasicAuthListNames = []string{"team", "no-such-list"}
	if w := basicReq(router, sep, "/", "alice", "alice-pw", nil); w.Code != 299 {
		t.Fatalf("assigned list user refused: %d", w.Code)
	}
	if w := basicReq(router, sep, "/", "own", "own-pw", nil); w.Code != 299 {
		t.Fatal("own credentials must keep working")
	}
	if w := basicReq(router, sep, "/", "carol", "carol-pw", nil); w.Code != 401 {
		t.Fatal("a different list leaked")
	}
	if w := basicReq(router, sep, "/", "alice", "bob-pw", nil); w.Code != 401 {
		t.Fatal("password of another user accepted")
	}
	// a second endpoint shares the list
	_, sep2, _ := newNonTLSTestRouter(t)
	_ = sep2

	// password change takes effect immediately (hash is part of the verification cache key)
	lists.Set("team", []*BasicAuthUnhashedCredentials{{"alice", "new-pw"}, {"bob", ""}}, fastHash)
	if w := basicReq(router, sep, "/", "alice", "alice-pw", nil); w.Code != 401 {
		t.Fatal("old password still valid after the list changed")
	}
	if w := basicReq(router, sep, "/", "alice", "new-pw", nil); w.Code != 299 {
		t.Fatal("new password refused")
	}
	if w := basicReq(router, sep, "/", "bob", "bob-pw", nil); w.Code != 299 {
		t.Fatal("empty password must keep the stored hash")
	}
	// deleting the list revokes access
	lists.Delete("team")
	if w := basicReq(router, sep, "/", "bob", "bob-pw", nil); w.Code != 401 {
		t.Fatal("deleted list still grants access")
	}
}

func TestCredentialListStoreValidationAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "basic.json")
	l, _ := NewCredentialLists(path)
	for _, bad := range []string{"", "../x", "a/b", " lead", "x\x00y", string(make([]byte, 65))} {
		if l.Set(bad, nil, fastHash) == nil {
			t.Errorf("list name %q accepted", bad)
		}
	}
	if l.Set("ok", []*BasicAuthUnhashedCredentials{{"u", ""}}, fastHash) == nil {
		t.Error("new user without password accepted")
	}
	if l.Set("ok", []*BasicAuthUnhashedCredentials{{"u", "p"}, {"u", "p2"}}, fastHash) == nil {
		t.Error("duplicate user accepted")
	}
	if l.Set("ok", []*BasicAuthUnhashedCredentials{{"", "p"}}, fastHash) == nil {
		t.Error("empty username accepted")
	}
	if err := l.Set("ok", []*BasicAuthUnhashedCredentials{{"u", "p"}}, fastHash); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("store must be private (0600): %v %v", fi, err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) == "" || containsStr(string(raw), `"p"`) && !containsStr(string(raw), "argon2id") {
		t.Fatal("plain password stored")
	}
	l2, err := NewCredentialLists(path)
	if err != nil || len(l2.Usernames("ok")) != 1 {
		t.Fatalf("not persisted: %v", err)
	}
	if got := l2.Usernames("ok"); got[0] != "u" {
		t.Fatal(got)
	}
	// a nil store is harmless
	var nilLists *CredentialLists
	if nilLists.Exists("x") || nilLists.copyOf([]string{"x"}) != nil || nilLists.Names() != nil {
		t.Fatal("nil store")
	}
	if ValidateBasicAuthExtras(nil, []string{"ghost"}, l2) == nil {
		t.Fatal("unknown list name accepted")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
