package oauth2

import (
	"net/http/httptest"
	"testing"
)

func TestScrubIdentityHeaders(t *testing.T) {
	idp := newFakeIdP(t)
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) {
		o.OAuth2HeaderMappings = "X-Auth-Email=email,X-Auth-User=preferred_username"
	})
	r := httptest.NewRequest("GET", "http://app.example.com/public", nil)
	r.Header.Set("X-Auth-Email", "root@example.com")
	r.Header.Set("X-Auth-User", "root")
	r.Header.Set("X-Other", "keep")
	ar.ScrubIdentityHeaders(r)
	if r.Header.Get("X-Auth-Email") != "" || r.Header.Get("X-Auth-User") != "" {
		t.Fatalf("mapped identity headers survived: %v", r.Header)
	}
	if r.Header.Get("X-Other") != "keep" {
		t.Fatal("unrelated header removed")
	}
	var nilRouter *OAuth2Router
	nilRouter.ScrubIdentityHeaders(r) //must not panic
}
