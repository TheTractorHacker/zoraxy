package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func acmeProbe(target string, port string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RequestURI = target
	w := httptest.NewRecorder()
	serveACMEChallenge(w, r, port)
	return w
}

// Upstream #655: probes of the well-known path while no certificate request is
// running used to get an empty "200 OK" (and noise on stdout). The status of
// the internal ACME listener must also be passed through.
func TestServeACMEChallengeStatuses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/acme-challenge/goodtoken" {
			w.Write([]byte("keyauth"))
			return
		}
		http.NotFound(w, r)
	}))
	u, _ := url.Parse(backend.URL)
	port := u.Port()

	if w := acmeProbe("/.well-known/acme-challenge/goodtoken", port); w.Code != 200 || w.Body.String() != "keyauth" {
		t.Fatalf("valid challenge: %d %q", w.Code, w.Body.String())
	}
	if w := acmeProbe("/.well-known/acme-challenge/unknowntoken", port); w.Code != 404 {
		t.Fatalf("unknown token must keep the listener's 404, got %d", w.Code)
	}
	if w := acmeProbe("/.well-known/acme-challenge/my1.php", port); w.Code != 400 {
		t.Fatalf("invalid token chars must be rejected, got %d", w.Code)
	}

	backend.Close() // no certificate request in progress any more
	if w := acmeProbe("/.well-known/acme-challenge/goodtoken", port); w.Code != 404 {
		t.Fatalf("closed listener must answer 404, got %d", w.Code)
	}
}
