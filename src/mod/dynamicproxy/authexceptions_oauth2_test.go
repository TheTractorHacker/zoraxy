package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/auth/sso/oauth2"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

func TestOAuth2ExceptionsEndToEnd(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "o.db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	lg, _ := logger.NewFmtLogger()
	oa := oauth2.NewOAuth2Router(&oauth2.OAuth2RouterOptions{Logger: lg, Database: db, SystemUUID: "11111111-2222-3333-4444-555555555555"})
	t.Cleanup(oa.Close)
	router.Option.OAuth2Router = oa //not configured: every non-exempt request is refused
	sep.AuthenticationProvider = &AuthenticationProvider{
		AuthMethod:                 AuthMethodOauth2,
		ExternalAuthExceptionRules: []*AuthExceptionRule{exRule("prefix", "/webhook", false), ipRule("203.0.113.7")},
	}
	h := router.mux.(*ProxyHandler)
	do := func(target, remote string) bool {
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		r.RequestURI = target
		r.RemoteAddr = remote
		return handleAuthProviderRouting(sep, httptest.NewRecorder(), r, h)
	}
	if do("/webhook/github", "198.51.100.1:1") {
		t.Fatal("exempt path was gated")
	}
	if do("/private", "203.0.113.7:1") {
		t.Fatal("exempt IP was gated")
	}
	for _, target := range []string{"/private", "/webhook/../private", "/webhook/%2e%2e/private", "/webhookx"} {
		if !do(target, "198.51.100.1:1") {
			t.Errorf("%s bypassed OAuth2", target)
		}
	}
}
