package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
)

const testNodeUUID = "11111111-2222-3333-4444-555555555555"

// addProvider registers provider id (settings of the fake IdP) on the router.
func addProvider(t *testing.T, ar *OAuth2Router, id string, idp *fakeIdP, mutate func(rec *providerRecord)) {
	t.Helper()
	rec := &providerRecord{
		ID: id, Name: "Provider " + id, ClientId: testClientID, ClientSecret: testClientSecret,
		Issuer: idp.issuer(), CodeChallengeMethod: "PKCE_S256",
	}
	if mutate != nil {
		mutate(rec)
	}
	if err := ar.saveProvider(rec); err != nil {
		t.Fatal(err)
	}
}

func twoProviders(t *testing.T) (*OAuth2Router, *fakeIdP, *fakeIdP) {
	idpA, idpB := newFakeIdP(t), newFakeIdP(t)
	idpB.user = map[string]any{"sub": "bob-1", "email": "bob@example.org", "preferred_username": "bob", "groups": []any{"ops"}}
	ar := newTestRouter(t, idpA, nil)
	addProvider(t, ar, "b", idpB, nil)
	return ar, idpA, idpB
}

func loginOn(t *testing.T, b *browser, idp *fakeIdP, target string) {
	t.Helper()
	w := b.login(idp, target)
	if w.Code != http.StatusFound {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
}

func authed(b *browser, target string) bool {
	_, err := b.do(b.request("GET", target))
	return err == nil
}

func TestTwoProvidersSameHostAreIsolated(t *testing.T) {
	ar, idpA, idpB := twoProviders(t)
	b := newBrowser(t, ar)
	b.ro = RuleOptions{ProviderID: "b"}

	// An anonymous visitor of a rule with provider b is sent to IdP B, with B's own redirect URI
	w, err := b.do(b.request("GET", appURL+"/b/"))
	if err == nil || !strings.HasPrefix(w.Header().Get("Location"), idpB.URL+"/application/o/authorize/") {
		t.Fatalf("provider b must redirect to IdP B: %d %q", w.Code, w.Header().Get("Location"))
	}
	au, _ := url.Parse(w.Header().Get("Location"))
	if got := au.Query().Get("redirect_uri"); got != appURL+"/internal/oauth2/p/b" {
		t.Fatalf("redirect uri of provider b: %q", got)
	}
	b.cookies = map[string]*http.Cookie{}

	loginOn(t, b, idpB, appURL+"/b/")
	b.ro = RuleOptions{}
	loginOn(t, b, idpA, appURL+"/a/")

	ca, cb := b.cookies[sessionCookie], b.cookies[sessionCookie+"-b"]
	if ca == nil || cb == nil || ca.Value == cb.Value {
		t.Fatalf("each provider needs its own cookie: %v", b.cookies)
	}
	for _, rule := range []RuleOptions{{}, {ProviderID: "b"}, {ProviderID: DefaultProviderID}} {
		b.ro = rule
		if !authed(b, appURL+"/x") {
			t.Fatalf("both sessions must be valid side by side (rule %+v)", rule)
		}
	}

	// Cookie of provider A presented as provider B's cookie (and vice versa) is rejected
	b.ro = RuleOptions{ProviderID: "b"}
	swapped := newBrowser(t, ar)
	swapped.ro = b.ro
	swapped.cookies[sessionCookie+"-b"] = &http.Cookie{Name: sessionCookie + "-b", Value: ca.Value}
	if authed(swapped, appURL+"/x") {
		t.Fatal("default provider session accepted by provider b")
	}
	swapped = newBrowser(t, ar)
	swapped.cookies[sessionCookie] = &http.Cookie{Name: sessionCookie, Value: cb.Value}
	if authed(swapped, appURL+"/x") {
		t.Fatal("provider b session accepted by the default provider")
	}

	// Logout of one provider leaves the other signed in
	if w, _ := b.do(b.request("GET", appURL+"/internal/oauth2/p/b/logout")); w.Code != http.StatusFound {
		t.Fatalf("logout: %d", w.Code)
	}
	if authed(b, appURL+"/x") {
		t.Fatal("provider b session survived its logout")
	}
	b.ro = RuleOptions{}
	if !authed(b, appURL+"/x") {
		t.Fatal("logging out of provider b ended the default session")
	}
}

func TestStateCannotCrossProviders(t *testing.T) {
	ar, idpA, _ := twoProviders(t)
	b := newBrowser(t, ar)
	w, err := b.do(b.request("GET", appURL+"/"))
	if err == nil {
		t.Fatal("expected redirect")
	}
	cb, _ := idpA.authorize(t, w.Header().Get("Location"))
	// the default provider's code + state replayed on provider b's callback path
	forged := strings.Replace(cb, "/internal/oauth2?", "/internal/oauth2/p/b?", 1)
	if forged == cb {
		t.Fatalf("callback url shape: %s", cb)
	}
	b.ro = RuleOptions{ProviderID: "b"}
	cw, _ := b.do(b.request("GET", forged))
	if cw.Code != http.StatusBadRequest {
		t.Fatalf("state of another provider accepted: %d", cw.Code)
	}
	if _, ok := b.cookies[sessionCookie+"-b"]; ok {
		t.Fatal("session issued")
	}
	// the state was consumed by the failed attempt: the genuine callback fails too
	b.ro = RuleOptions{}
	if cw, _ := b.do(b.request("GET", cb)); cw.Code != http.StatusBadRequest {
		t.Fatalf("state must be single use: %d", cw.Code)
	}
}

func TestProviderCallbackPathIsPerProvider(t *testing.T) {
	ar, _, _ := twoProviders(t)
	b := newBrowser(t, ar)
	// B's callback path on a rule bound to the default provider is just an ordinary protected path
	w, err := b.do(b.request("GET", appURL+"/internal/oauth2/p/b?code=x&state=y"))
	if err == nil || w.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d", w.Code)
	}
}

func TestRevokedProvider(t *testing.T) {
	ar, _, idpB := twoProviders(t)
	b := newBrowser(t, ar)
	b.ro = RuleOptions{ProviderID: "b"}
	loginOn(t, b, idpB, appURL+"/")
	old := b.cookies[sessionCookie+"-b"]

	if err := ar.deleteProvider("b"); err != nil {
		t.Fatal(err)
	}
	if ar.ProviderExists("b") {
		t.Fatal("provider still registered")
	}
	w, err := b.do(b.request("GET", appURL+"/"))
	if err == nil || w.Code != http.StatusInternalServerError {
		t.Fatalf("rule of a deleted provider must fail closed: %d", w.Code)
	}
	// Re-creating the id must not resurrect the old session
	addProvider(t, ar, "b", idpB, nil)
	nb := newBrowser(t, ar)
	nb.ro = b.ro
	nb.cookies[old.Name] = old
	if authed(nb, appURL+"/") {
		t.Fatal("session of a revoked provider accepted after re-creation")
	}
	if n := ar.store.persist.count; n != 0 {
		t.Fatalf("persisted sessions of deleted provider left: %d", n)
	}
}

func TestEditingProviderEndsItsSessionsOnly(t *testing.T) {
	ar, idpA, idpB := twoProviders(t)
	b := newBrowser(t, ar)
	loginOn(t, b, idpA, appURL+"/")
	b.ro = RuleOptions{ProviderID: "b"}
	loginOn(t, b, idpB, appURL+"/")
	addProvider(t, ar, "b", idpB, func(rec *providerRecord) { rec.AllowedGroups = "ops" })
	if authed(b, appURL+"/") {
		t.Fatal("session survived an edit of its provider")
	}
	b.ro = RuleOptions{}
	if !authed(b, appURL+"/") {
		t.Fatal("editing provider b ended default sessions")
	}
}

func TestDeletingProviderInUseIsRefused(t *testing.T) {
	ar, _, _ := twoProviders(t)
	ar.options.InUse = func(id string) []string {
		if id == "b" {
			return []string{"b.example.com"}
		}
		return nil
	}
	err := ar.deleteProvider("b")
	if err == nil || !strings.Contains(err.Error(), "b.example.com") {
		t.Fatalf("delete of a provider in use must be refused: %v", err)
	}
	if !ar.ProviderExists("b") {
		t.Fatal("provider removed")
	}
	// the same through the HTTP API
	dw := httptest.NewRecorder()
	ar.HandleProviders(dw, httptest.NewRequest(http.MethodDelete, "/api/sso/OAuth2/providers?id=b", nil))
	w := dw
	if !strings.Contains(w.Body.String(), "error") || !ar.ProviderExists("b") {
		t.Fatalf("api: %s", w.Body.String())
	}
	ar.options.InUse = nil
	if err := ar.deleteProvider("b"); err != nil {
		t.Fatal(err)
	}
}

func TestRuleLevelAllowListsAreAdditional(t *testing.T) {
	idp := newFakeIdP(t)
	idp.user["groups"] = []any{"staff"}
	idp.user["roles"] = []any{"viewer"}
	ar := newTestRouter(t, idp, nil)
	cases := []struct {
		ro   RuleOptions
		want bool
	}{
		{RuleOptions{}, true},
		{RuleOptions{AllowedGroups: "staff"}, true},
		{RuleOptions{AllowedGroups: "admins"}, false},
		{RuleOptions{AllowedClaims: "roles=viewer,editor"}, true},
		{RuleOptions{AllowedClaims: "roles=editor"}, false},
		{RuleOptions{AllowedEmails: "a@example.com"}, true},
		{RuleOptions{AllowedEmails: "x@example.com"}, false},
		{RuleOptions{AllowedEmailDomains: "example.com"}, true},
		{RuleOptions{AllowedEmailDomains: "example.org"}, false},
		{RuleOptions{AllowedGroups: "staff", AllowedEmailDomains: "example.org"}, false},
		{RuleOptions{AllowedClaims: "broken"}, false}, // a broken rule never opens access
	}
	for _, c := range cases {
		b := newBrowser(t, ar)
		b.ro = c.ro
		w := b.login(idp, appURL+"/")
		got := w.Code == http.StatusFound
		if got != c.want {
			t.Errorf("%+v: allowed=%v want %v (code %d)", c.ro, got, c.want, w.Code)
		}
		if c.want {
			if !authed(b, appURL+"/") {
				t.Errorf("%+v: session not accepted", c.ro)
			}
			// the same session is refused by a stricter rule on the same provider (re-checked per request)
			b.ro = RuleOptions{AllowedGroups: "nobody"}
			if w, _ := b.do(b.request("GET", appURL+"/")); w.Code != http.StatusForbidden {
				t.Errorf("stricter rule on existing session: %d", w.Code)
			}
		}
	}
	// provider and rule lists are AND-combined
	ar2 := newTestRouter(t, idp, func(o *OAuth2RouterOptions) { o.OAuth2AllowedGroups = "staff" })
	b := newBrowser(t, ar2)
	b.ro = RuleOptions{AllowedClaims: "roles=editor"}
	if w := b.login(idp, appURL+"/"); w.Code != http.StatusForbidden {
		t.Fatalf("provider OK but rule failing must deny: %d", w.Code)
	}
}

func TestLegacyConfigMigratesToDefaultProvider(t *testing.T) {
	idp := newFakeIdP(t)
	db := newTestDB(t)
	db.NewTable("oauth2")
	db.Write("oauth2", "oauth2ClientId", testClientID)
	db.Write("oauth2", "oauth2ClientSecret", testClientSecret)
	db.Write("oauth2", "oauth2Issuer", idp.issuer())
	db.Write("oauth2", "oauth2CodeChallengeMethod", "PKCE_S256")
	db.Write("oauth2", "oauth2AllowedGroups", "users")
	db.Write("oauth2", "oauth2HeaderMappings", "X-Auth-User=preferred_username")
	lg, _ := logger.NewFmtLogger()
	opt := func() *OAuth2RouterOptions {
		return &OAuth2RouterOptions{Logger: lg, Database: db, SystemUUID: testNodeUUID}
	}
	ar := NewOAuth2Router(opt())
	if ids := ar.ProviderIDs(); len(ids) != 1 || ids[0] != DefaultProviderID {
		t.Fatalf("migration result: %v", ids)
	}
	c := ar.prov("").config()
	if c.OAuth2ClientId != testClientID || c.OAuth2AllowedGroups != "users" || c.OAuth2HeaderMappings != "X-Auth-User=preferred_username" {
		t.Fatalf("settings not carried over: %+v", c)
	}
	// behaves as before for a rule that names no provider
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	ar.Close()

	// The legacy keys stay (downgrade safe) and an edit of "default" is mirrored to them
	ar = NewOAuth2Router(opt())
	defer ar.Close()
	w := postForm(ar.HandleSetOAuth2Settings, "POST", url.Values{
		"oauth2ClientId": {testClientID}, "oauth2ClientSecret": {testClientSecret},
		"oauth2Issuer": {idp.issuer()}, "oauth2AllowedGroups": {"admins"},
	})
	if strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	var groups string
	db.Read("oauth2", "oauth2AllowedGroups", &groups)
	if groups != "admins" {
		t.Fatalf("legacy key not mirrored: %q", groups)
	}
	// a later start must not re-import (or overwrite) from the legacy keys
	db.Write("oauth2", "oauth2AllowedGroups", "stale")
	ar3 := NewOAuth2Router(opt())
	defer ar3.Close()
	if ar3.prov("").config().OAuth2AllowedGroups != "admins" {
		t.Fatal("registry must win over legacy keys after the migration")
	}
}

func TestMigrationWithNoLegacyConfigCreatesNothing(t *testing.T) {
	db := newTestDB(t)
	lg, _ := logger.NewFmtLogger()
	ar := NewOAuth2Router(&OAuth2RouterOptions{Logger: lg, Database: db, SystemUUID: testNodeUUID})
	defer ar.Close()
	if len(ar.ProviderIDs()) != 0 {
		t.Fatalf("unexpected providers %v", ar.ProviderIDs())
	}
	b := newBrowser(t, ar)
	if w, err := b.do(b.request("GET", appURL+"/")); err == nil || w.Code != http.StatusInternalServerError {
		t.Fatalf("unconfigured must fail closed: %d", w.Code)
	}
}

func TestProviderAPI(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, nil)
	form := func(id string) url.Values {
		return url.Values{"id": {id}, "name": {"Keycloak"}, "oauth2ClientId": {testClientID}, "oauth2ClientSecret": {testClientSecret},
			"oauth2Issuer": {idp.issuer()}, "oauth2CodeChallengeMethod": {"PKCE_S256"}, "preset": {"keycloak"}}
	}
	if w := postForm(ar.HandleProviders, "POST", form("kc")); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	for _, bad := range []string{"", "Bad Id", "UPPER", "../x", strings.Repeat("a", 33)} {
		if w := postForm(ar.HandleProviders, "POST", form(bad)); !strings.Contains(w.Body.String(), "error") {
			t.Errorf("id %q accepted", bad)
		}
	}
	// list: secrets are never returned
	w := postForm(ar.HandleProviders, "GET", nil)
	if strings.Contains(w.Body.String(), testClientSecret) {
		t.Fatalf("secret leaked in list: %s", w.Body.String())
	}
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("list: %v %s", err, w.Body.String())
	}
	// update with the masked secret keeps the stored secret
	f := form("kc")
	f.Set("oauth2ClientSecret", secretMask)
	f.Set("name", "Renamed")
	if w := postForm(ar.HandleProviders, "POST", f); strings.Contains(w.Body.String(), "error") {
		t.Fatal(w.Body.String())
	}
	if ar.prov("kc").config().OAuth2ClientSecret != testClientSecret || ar.prov("kc").config().ProviderName != "Renamed" {
		t.Fatalf("masked secret must keep the stored one: %+v", ar.prov("kc").config())
	}
	// creating without a secret is refused
	f = form("new")
	f.Del("oauth2ClientSecret")
	if w := postForm(ar.HandleProviders, "POST", f); !strings.Contains(w.Body.String(), "error") {
		t.Fatal("create without secret accepted")
	}
	// test discovery of a saved provider
	r := postForm(ar.HandleDiscoveryTest, "POST", url.Values{"id": {"kc"}})
	if !strings.Contains(r.Body.String(), `"jwksReachable":true`) {
		t.Fatalf("saved provider discovery test: %s", r.Body.String())
	}
	// the provider limit
	for i := 0; i < maxProviders; i++ {
		postForm(ar.HandleProviders, "POST", form("p"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	if n := len(ar.ProviderIDs()); n > maxProviders {
		t.Fatalf("provider limit exceeded: %d", n)
	}
}

func TestIdentityHeadersOfOtherProvidersAreScrubbed(t *testing.T) {
	ar, idpA, _ := twoProviders(t)
	addProvider(t, ar, "b", idpA, func(rec *providerRecord) { rec.HeaderMappings = "X-B-User=preferred_username" })
	ar.saveProvider(func() *providerRecord {
		r := ar.recordOf(DefaultProviderID)
		r.HeaderMappings = "X-A-User=preferred_username"
		return r
	}())
	b := newBrowser(t, ar)
	loginOn(t, b, idpA, appURL+"/")
	r := b.request("GET", appURL+"/")
	r.Header.Set("X-B-User", "forged")
	r.Header.Set("X-A-User", "forged")
	if _, err := b.do(r); err != nil {
		t.Fatal(err)
	}
	if r.Header.Get("X-B-User") != "" || r.Header.Get("X-A-User") != "alice" {
		t.Fatalf("headers: A=%q B=%q", r.Header.Get("X-A-User"), r.Header.Get("X-B-User"))
	}
}
