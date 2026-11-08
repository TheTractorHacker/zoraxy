package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/auth/sso/oauth2"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

// Two OAuth2 providers on two rules: every rule signs in with its own provider, the path exemptions
// work with each of them, and a rule that names no provider keeps using the legacy "default" one.
func TestOAuth2ProviderPerRule(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "o.db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	lg, _ := logger.NewFmtLogger()
	oa := oauth2.NewOAuth2Router(&oauth2.OAuth2RouterOptions{
		Logger: lg, Database: db, SystemUUID: "11111111-2222-3333-4444-555555555555",
		// legacy single configuration, becomes provider "default"
		OAuth2ClientId: "cid-default", OAuth2ClientSecret: "s", OAuth2ServerURL: "https://idp-default.test/authorize",
		OAuth2TokenURL: "https://idp-default.test/token", OAuth2UserInfoUrl: "https://idp-default.test/userinfo", OAuth2Scopes: "profile",
	})
	t.Cleanup(oa.Close)
	router.Option.OAuth2Router = oa

	add := func(id, host string) {
		t.Helper()
		form := url.Values{"id": {id}, "oauth2ClientId": {"cid-" + id}, "oauth2ClientSecret": {"secret"},
			"oauth2ServerUrl": {"https://" + host + "/authorize"}, "oauth2TokenUrl": {"https://" + host + "/token"},
			"oauth2UserInfoUrl": {"https://" + host + "/userinfo"}, "oauth2Scopes": {"profile"}}
		r := httptest.NewRequest(http.MethodPost, "/api/sso/OAuth2/providers", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		oa.HandleProviders(w, r)
		if strings.Contains(w.Body.String(), "error") {
			t.Fatal(w.Body.String())
		}
	}
	add("corp", "idp-corp.test")
	add("partners", "idp-partners.test")

	mk := func(provider string) *ProxyEndpoint {
		cp := *sep
		cp.AuthenticationProvider = &AuthenticationProvider{
			AuthMethod: AuthMethodOauth2, OAuth2ProviderID: provider,
			ExternalAuthExceptionRules: []*AuthExceptionRule{exRule("prefix", "/webhook", false)},
		}
		return &cp
	}
	h := router.mux.(*ProxyHandler)
	do := func(ep *ProxyEndpoint, target string) (handled bool, loc string) {
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		r.RequestURI = target
		w := httptest.NewRecorder()
		handled = handleAuthProviderRouting(ep, w, r, h)
		return handled, w.Header().Get("Location")
	}
	for provider, want := range map[string]string{
		"":         "https://idp-default.test/authorize",
		"default":  "https://idp-default.test/authorize",
		"corp":     "https://idp-corp.test/authorize",
		"partners": "https://idp-partners.test/authorize",
	} {
		ep := mk(provider)
		handled, loc := do(ep, "/private")
		if !handled || !strings.HasPrefix(loc, want) {
			t.Errorf("provider %q: handled=%v location %q, want %s", provider, handled, loc, want)
		}
		if provider != "" && provider != "default" && !strings.Contains(loc, "redirect_uri="+url.QueryEscape("http://app.example.com/internal/oauth2/p/"+provider)) {
			t.Errorf("provider %q: redirect uri %q", provider, loc)
		}
		// the exemption works with every provider, traversal tricks do not
		if handled, _ := do(ep, "/webhook/github"); handled {
			t.Errorf("provider %q: exempt path gated", provider)
		}
		for _, bad := range []string{"/webhook/../private", "/webhook/%2e%2e/private", "/webhookx"} {
			if handled, _ := do(ep, bad); !handled {
				t.Errorf("provider %q: %s bypassed authentication", provider, bad)
			}
		}
	}
	// a rule pointing at a provider that does not exist fails closed
	if handled, loc := do(mk("ghost"), "/private"); !handled || loc != "" {
		t.Errorf("unknown provider must fail closed (handled=%v loc=%q)", handled, loc)
	}
	// per rule allow-lists travel with the endpoint
	ep := mk("corp")
	ep.AuthenticationProvider.OAuth2AllowedGroups = "staff"
	if ro := oauth2RuleOptions(ep); ro.ProviderID != "corp" || ro.AllowedGroups != "staff" {
		t.Errorf("rule options: %+v", ro)
	}
}

func TestOAuth2ProviderFieldsAreAdditiveJSON(t *testing.T) {
	// Rules saved by older versions (no provider fields) still load, and unset fields are not written.
	ap := &AuthenticationProvider{AuthMethod: AuthMethodOauth2}
	js := mustJSON(t, ap)
	for _, f := range []string{"OAuth2ProviderID", "OAuth2AllowedGroups", "OAuth2AllowedClaims", "OAuth2AllowedEmails", "OAuth2AllowedEmailDomains"} {
		if strings.Contains(js, f) {
			t.Errorf("%s written while empty: %s", f, js)
		}
	}
}
