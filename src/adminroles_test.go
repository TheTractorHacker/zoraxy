package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
	db "imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

// Every route registered on the managed router must refuse mutating requests from a
// viewer (read-only) account, and the admin-only prefixes must be closed for GET as well.
func TestViewerCannotReachAnyMutatingRoute(t *testing.T) {
	CONF_FOLDER = t.TempDir()
	sysdb, err := db.NewDatabase(filepath.Join(t.TempDir(), "sys"), db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer sysdb.Close()
	lg, _ := logger.NewFmtLogger()
	old := auth.ProfileAdmin
	auth.ProfileAdmin = auth.PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1}
	defer func() { auth.ProfileAdmin = old }()
	authAgent = auth.NewAuthenticationAgent("t", []byte("0123456789abcdef0123456789abcdef"), sysdb, false, lg, nil)
	authAgent.CreateUserAccount("root", "password-1", "")
	authAgent.CreateUser("view", "password-2", auth.RoleViewer)

	mux := http.NewServeMux()
	rt := auth.NewManagedHTTPRouter(auth.RouterOption{AuthAgent: authAgent, RequireAuth: true, TargetMux: mux})
	RegisterHTTPProxyAPIs(rt)
	RegisterWAFAPIs(rt)
	RegisterNetworkingAPIs(rt)
	RegisterTLSAPIs(rt)
	RegisterAuthenticationHandlerAPIs(rt)
	RegisterZorxAuthUserManagementAPIs(rt)
	RegisterRedirectionAPIs(rt)
	RegisterAccessRuleAPIs(rt)
	RegisterPathRuleAPIs(rt)
	RegisterStatisticalAPIs(rt)
	RegisterStreamProxyAPIs(rt)
	RegisterMDNSAPIs(rt)
	RegisterNetworkUtilsAPIs(rt)
	RegisterUpdaterAPIs(rt)
	RegisterClusterAPIs(rt)
	RegisterMetricsAPIs(rt)
	RegisterACMEAndAutoRenewerAPIs(rt)
	RegisterStaticWebServerAPIs(rt)
	RegisterPluginAPIs(rt)
	RegisterAbuseAPIs(rt)
	defer stopAbuseManager()
	rt.HandleFunc("/api/users/list", authAgent.HandleUserList)
	rt.HandleFunc("/api/users/action", authAgent.HandleUserAction)

	eps := rt.Endpoints()
	if len(eps) < 100 {
		t.Fatalf("only %d routes enumerated, the audit is not covering the API", len(eps))
	}

	login := func(user, pw string) *http.Cookie {
		form := url.Values{"username": {user}, "password": {pw}}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		authAgent.HandleLogin(w, r)
		for _, c := range w.Result().Cookies() {
			if c.Name == authAgent.SessionName && c.Value != "" {
				return c
			}
		}
		t.Fatal("login failed for " + user)
		return nil
	}
	vc := login("view", "password-2")

	for _, ep := range eps {
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			r := httptest.NewRequest(method, ep, strings.NewReader("a=b"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(vc)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Errorf("viewer %s %s was not refused (status %d)", method, ep, w.Code)
			}
		}
	}
	for _, ep := range []string{"/api/users/list", "/api/abuse/config"} {
		r := httptest.NewRequest("GET", ep, nil)
		r.AddCookie(vc)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("viewer GET %s must be refused, got %d", ep, w.Code)
		}
	}
}
