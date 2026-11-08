package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fast hashing for tests that create many accounts
func fastPW(t *testing.T) {
	t.Helper()
	old := ProfileAdmin
	ProfileAdmin = testProfile
	t.Cleanup(func() { ProfileAdmin = old })
}

func login(t *testing.T, a *AuthAgent, user, pw string) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pw}}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "198.51.100.1:1234"
	w := httptest.NewRecorder()
	a.HandleLogin(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == a.SessionName && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

func reqWith(c *http.Cookie, method, path string, form url.Values) *http.Request {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = "198.51.100.1:1234"
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func TestUpgradeKeepsExistingAdminAndSession(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	//Account and a session created the way the previous version did (no role / sessver records)
	a.CreateUserAccount("admin", "old-password", "")
	if a.GetRole("admin") != RoleAdmin {
		t.Fatal("legacy account without a role record must be admin")
	}
	c := login(t, a, "admin", "old-password")
	if c == nil || !a.CheckAuth(reqWith(c, "GET", "/", nil)) {
		t.Fatal("login/session failed")
	}
	//A cookie from before the upgrade has no sessver value at all
	s, _ := a.SessionStore.New(httptest.NewRequest("GET", "/", nil), a.SessionName)
	s.Values["authenticated"] = true
	s.Values["username"] = "admin"
	w := httptest.NewRecorder()
	s.Save(httptest.NewRequest("GET", "/", nil), w)
	old := w.Result().Cookies()[0]
	if !a.CheckAuth(reqWith(old, "GET", "/", nil)) {
		t.Fatal("existing sessions must survive the upgrade")
	}
}

func TestLastAdminProtection(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	if err := a.DeleteUser("root"); err == nil {
		t.Fatal("deleted the last admin")
	}
	if err := a.SetDisabled("root", true); err == nil {
		t.Fatal("disabled the last admin")
	}
	if err := a.SetRole("root", RoleViewer); err == nil {
		t.Fatal("demoted the last admin")
	}
	if err := a.CreateUser("viewer1", "password-2", RoleViewer); err != nil {
		t.Fatal(err)
	}
	//a viewer does not count as an admin
	if err := a.DeleteUser("root"); err == nil {
		t.Fatal("a viewer must not satisfy the last-admin rule")
	}
	a.CreateUser("admin2", "password-3", RoleAdmin)
	if err := a.SetDisabled("admin2", true); err != nil {
		t.Fatal(err) //root still enabled
	}
	if err := a.DeleteUser("root"); err == nil {
		t.Fatal("a disabled admin must not satisfy the last-admin rule")
	}
	a.SetDisabled("admin2", false)
	if err := a.DeleteUser("root"); err != nil {
		t.Fatalf("deleting a non-last admin must work: %v", err)
	}
	if err := a.DeleteUser("admin2"); err == nil {
		t.Fatal("deleted the (now) last admin")
	}
}

func TestSessionsInvalidatedOnPasswordChangeDisableDeleteRename(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	a.CreateUser("bob", "password-2", RoleAdmin)

	c := login(t, a, "bob", "password-2")
	valid := func() bool { return a.CheckAuth(reqWith(c, "GET", "/", nil)) }
	if !valid() {
		t.Fatal("fresh session invalid")
	}
	if err := a.SetPassword("bob", "password-new"); err != nil {
		t.Fatal(err)
	}
	if valid() {
		t.Fatal("session survived a password change")
	}
	if login(t, a, "bob", "password-2") != nil {
		t.Fatal("old password still works")
	}
	c = login(t, a, "bob", "password-new")
	if c == nil || !valid() {
		t.Fatal("login with the new password failed")
	}
	a.SetDisabled("bob", true)
	if valid() {
		t.Fatal("session survived disabling")
	}
	if login(t, a, "bob", "password-new") != nil {
		t.Fatal("disabled account can log in")
	}
	a.SetDisabled("bob", false)
	c = login(t, a, "bob", "password-new")
	if c == nil {
		t.Fatal("re-enabled account cannot log in")
	}
	if err := a.RenameUser("bob", "robert"); err != nil {
		t.Fatal(err)
	}
	if valid() {
		t.Fatal("session survived a rename")
	}
	if a.UserExists("bob") || !a.UserExists("robert") {
		t.Fatal("rename did not move the account")
	}
	if login(t, a, "robert", "password-new") == nil {
		t.Fatal("renamed account cannot log in")
	}
	c = login(t, a, "robert", "password-new")
	a.DeleteUser("robert")
	if valid() {
		t.Fatal("session survived deletion")
	}
}

func TestRenameKeepsRoleAndRejectsBadNames(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	a.CreateUser("v", "password-2", RoleViewer)
	if err := a.RenameUser("v", "viewer-two"); err != nil {
		t.Fatal(err)
	}
	if a.GetRole("viewer-two") != RoleViewer || a.GetRole("v") != "" {
		t.Fatal("role not carried over / old name still resolves")
	}
	for _, bad := range []string{"", "a/b", "../x", "a b", strings.Repeat("a", 65), "root", "-lead", "x\x00y", "<script>"} {
		if err := a.RenameUser("viewer-two", bad); err == nil {
			t.Errorf("rename to %q accepted", bad)
		}
	}
	if err := a.CreateUser("a/b", "password-1", RoleAdmin); err == nil {
		t.Error("created a user with a slash (would corrupt key layout)")
	}
	if err := a.CreateUser("shortpw", "1234567", RoleAdmin); err == nil {
		t.Error("short password accepted")
	}
	if err := a.CreateUser("x", "password-1", "superuser"); err == nil {
		t.Error("invalid role accepted")
	}
}

func TestViewerRoleEnforcement(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	a.CreateUser("view", "password-2", RoleViewer)
	vc := login(t, a, "view", "password-2")
	ac := login(t, a, "root", "password-1")

	a.LoginRedirectionHandler = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "login", http.StatusTemporaryRedirect) }
	called := 0
	mux := http.NewServeMux()
	rt := NewManagedHTTPRouter(RouterOption{AuthAgent: a, RequireAuth: true, TargetMux: mux})
	h := func(w http.ResponseWriter, r *http.Request) { called++; w.Write([]byte("ok")) }
	for _, p := range []string{"/api/x/list", "/api/x/del", "/api/conf/export", "/api/info/pprof", "/api/users/list", "/api/users/action", "/api/abuse/config"} {
		if err := rt.HandleFunc(p, h); err != nil {
			t.Fatal(err)
		}
	}
	do := func(c *http.Cookie, method, path string) int {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, reqWith(c, method, path, url.Values{"a": {"b"}}))
		return w.Code
	}
	// viewer: reads pass, every mutating method is refused and the handler is never reached
	if do(vc, "GET", "/api/x/list") != 200 {
		t.Fatal("viewer GET refused")
	}
	called = 0
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if code := do(vc, m, "/api/x/del"); code != 403 {
			t.Fatalf("viewer %s allowed: %d", m, code)
		}
	}
	if called != 0 {
		t.Fatal("handler invoked for a refused viewer request")
	}
	for _, p := range []string{"/api/conf/export", "/api/info/pprof", "/api/users/list", "/api/abuse/config"} {
		if do(vc, "GET", p) != 403 {
			t.Fatalf("viewer GET %s must be refused", p)
		}
		if do(ac, "GET", p) != 200 {
			t.Fatalf("admin GET %s refused", p)
		}
	}
	// admin: everything works
	if do(ac, "POST", "/api/x/del") != 200 {
		t.Fatal("admin POST refused")
	}
	// anonymous: login redirect, not the handler
	called = 0
	if do(nil, "POST", "/api/x/del") == 200 || called != 0 {
		t.Fatal("anonymous request reached the handler")
	}
	// path tricks do not unlock the deny list
	for _, p := range []string{"/api/conf/export/", "/api/users/list"} {
		if ViewerAllowed("GET", p) {
			t.Fatalf("ViewerAllowed(%s)", p)
		}
	}
	if ViewerAllowed("POST", "/api/anything") || ViewerAllowed("DELETE", "/api/anything") {
		t.Fatal("mutations must be refused by default")
	}
}

func TestUserManagementAPIRequiresAdmin(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	a.CreateUser("view", "password-2", RoleViewer)
	vc := login(t, a, "view", "password-2")
	ac := login(t, a, "root", "password-1")

	post := func(c *http.Cookie, form url.Values) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.HandleUserAction(w, reqWith(c, "POST", "/api/users/action", form))
		return w
	}
	if w := post(vc, url.Values{"action": {"setRole"}, "username": {"view"}, "role": {"admin"}}); w.Code != 403 {
		t.Fatalf("viewer escalated its own role: %d", w.Code)
	}
	if a.GetRole("view") != RoleViewer {
		t.Fatal("role changed")
	}
	if w := post(nil, url.Values{"action": {"delete"}, "username": {"view"}}); w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if w := post(ac, url.Values{"action": {"delete"}, "username": {"root"}}); !strings.Contains(w.Body.String(), "error") {
		t.Fatal("admin deleted itself")
	}
	if w := post(ac, url.Values{"action": {"disable"}, "username": {"root"}}); !strings.Contains(w.Body.String(), "error") {
		t.Fatal("admin disabled itself")
	}
	if w := post(ac, url.Values{"action": {"create"}, "username": {"n1"}, "password": {"password-9"}, "role": {"viewer"}}); strings.Contains(w.Body.String(), "error") {
		t.Fatalf("create failed: %s", w.Body.String())
	}
	// GET is refused for the action endpoint
	w := httptest.NewRecorder()
	a.HandleUserAction(w, reqWith(ac, "GET", "/api/users/action", nil))
	if w.Code != 405 {
		t.Fatal("GET mutation accepted")
	}
	// audit trail recorded
	found := map[string]bool{}
	for _, e := range a.RecentAudit() {
		found[e.Event] = true
		if strings.Contains(e.Detail, "password-") {
			t.Fatal("audit log contains a password")
		}
	}
	for _, ev := range []string{"login", "user.create", "user.delete.failed"} {
		if !found[ev] {
			t.Errorf("audit event %s missing: %v", ev, found)
		}
	}
}

func TestChangeOwnPasswordKeepsCurrentSessionOnly(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	c1 := login(t, a, "root", "password-1")
	c2 := login(t, a, "root", "password-1")
	r := reqWith(c1, "POST", "/api/auth/changePassword", url.Values{"oldPassword": {"password-1"}, "newPassword": {"password-NEW"}, "confirmPassword": {"password-NEW"}})
	w := httptest.NewRecorder()
	a.HandleChangeOwnPassword(w, r)
	if strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	if a.CheckAuth(reqWith(c2, "GET", "/", nil)) {
		t.Fatal("other session survived the password change")
	}
	var fresh *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == a.SessionName {
			fresh = c
		}
	}
	if fresh == nil || !a.CheckAuth(reqWith(fresh, "GET", "/", nil)) {
		t.Fatal("current session not re-issued")
	}
	// wrong current password / mismatch do not change anything
	w = httptest.NewRecorder()
	a.HandleChangeOwnPassword(w, reqWith(fresh, "POST", "/x", url.Values{"oldPassword": {"nope"}, "newPassword": {"password-X"}, "confirmPassword": {"password-X"}}))
	if !strings.Contains(w.Body.String(), "error") || !a.ValidateUsernameAndPassword("root", "password-NEW") {
		t.Fatal("wrong current password accepted")
	}
}

func TestLoginHooks(t *testing.T) {
	fastPW(t)
	a := newTestAgent(t)
	a.CreateUserAccount("root", "password-1", "")
	fails, guard := 0, true
	a.OnLoginFailure = func(r *http.Request, u string) { fails++ }
	a.LoginGuard = func(r *http.Request) bool { return guard }
	if login(t, a, "root", "bad") != nil || fails != 1 {
		t.Fatal("failure hook not called")
	}
	guard = false
	if login(t, a, "root", "password-1") != nil {
		t.Fatal("guard did not block the login")
	}
	if fails != 1 {
		t.Fatal("blocked attempts must not count as failures again")
	}
}
