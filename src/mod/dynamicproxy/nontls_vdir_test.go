package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Upstream #890: virtual directories must also be served on the plain HTTP
// (port 80 / "Allow plain HTTP access") path, not only over TLS.
func TestNonTLS_VirtualDirectoryIsProxied(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = nil

	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("vdir-backend"))
	}))
	defer backend.Close()

	sep.ProxyType = ProxyTypeHost
	sep.VirtualDirectories = []*VirtualDirectoryEndpoint{{
		MatchingPath: "/Server1/",
		Domain:       strings.TrimPrefix(backend.URL, "http://") + "/Server1/",
	}}
	if _, err := router.PrepareProxyRoute(sep); err != nil {
		t.Fatal(err)
	}

	w := serveNonTLS(router, sep, "/Server1/index.html", "198.51.100.1:1000")
	if w.Code != 200 || w.Body.String() != "vdir-backend" {
		t.Fatalf("vdir over plain HTTP: code=%d body=%.60q", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(gotPath, "/Server1/") {
		t.Fatalf("upstream saw path %q", gotPath)
	}

	// Missing trailing slash is redirected like on the TLS path
	w = serveNonTLS(router, sep, "/Server1", "198.51.100.1:1000")
	if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != "/Server1/" {
		t.Fatalf("expected redirect to /Server1/, got %d %q", w.Code, w.Header().Get("Location"))
	}
}
