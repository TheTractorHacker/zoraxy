package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy"
)

func authProviderForm(values url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/proxy/edit", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// Upstream #1109: an edit request that does not carry the "authprovider" parameter
// (stale cached UI, API client, plugin) must keep the rule's authentication instead of
// silently switching it to "None" and exposing the service.
func TestAuthMethodFromRequest(t *testing.T) {
	_, given, err := authMethodFromRequest(authProviderForm(url.Values{"rootname": {"app.example.com"}}))
	if err != nil || given {
		t.Fatalf("missing parameter must be reported as not given, got given=%v err=%v", given, err)
	}

	cases := map[string]dynamicproxy.AuthMethod{
		"0": dynamicproxy.AuthMethodNone,
		"1": dynamicproxy.AuthMethodBasic,
		"2": dynamicproxy.AuthMethodForward,
		"3": dynamicproxy.AuthMethodOauth2,
		"4": dynamicproxy.AuthMethodZorxAuth,
	}
	for raw, want := range cases {
		got, given, err := authMethodFromRequest(authProviderForm(url.Values{"authprovider": {raw}}))
		if err != nil || !given || got != want {
			t.Errorf("authprovider=%s: got method=%v given=%v err=%v, want %v", raw, got, given, err, want)
		}
	}

	if _, _, err := authMethodFromRequest(authProviderForm(url.Values{"authprovider": {"abc"}})); err == nil {
		t.Error("a non numeric authprovider must be rejected")
	}
}
