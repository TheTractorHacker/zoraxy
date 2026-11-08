package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// With -webui_tls the plain HTTP loopback listener exists only for plugins and
// must serve nothing but /plugin/ (fork #133).
func TestPluginLoopbackServesOnlyPluginAPI(t *testing.T) {
	pluginAPI := http.NewServeMux()
	pluginAPI.HandleFunc("/plugin/api/proxy/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("plugin-api"))
	})
	h := newPluginLoopbackHandler(pluginAPI)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil))
		return rec
	}

	if rec := get("/plugin/api/proxy/list"); rec.Code != 200 || rec.Body.String() != "plugin-api" {
		t.Fatalf("plugin API not reachable: %d %q", rec.Code, rec.Body.String())
	}
	for _, p := range []string{"/", "/index.html", "/login.html", "/api/auth/login", "/api/proxy/list", "/plugin.ui/x/", "/cluster/snapshot", "/script/utils.js"} {
		if rec := get(p); rec.Code != http.StatusNotFound {
			t.Errorf("%s must be 404 on the loopback listener, got %d", p, rec.Code)
		}
	}
	//path tricks must not reach anything outside /plugin/
	if rec := get("/plugin/../api/proxy/list"); rec.Code == 200 {
		t.Errorf("traversal reached the admin API: %d", rec.Code)
	}
}
