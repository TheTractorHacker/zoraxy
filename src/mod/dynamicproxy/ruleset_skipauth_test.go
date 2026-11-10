package dynamicproxy

import (
	"testing"

	"imuslab.com/zoraxy/mod/ruleset"
)

func TestRulesSkipAuth(t *testing.T) {
	router, sep, eng := newRulesRouter(t)
	sep.AuthenticationProvider = &AuthenticationProvider{AuthMethod: AuthMethodBasic, BasicAuthCredentials: []*BasicAuthCredentials{{Username: "alice", PasswordHash: "x"}}}
	if c := rsGet(router, sep, "http://app.example.com/status", rsIPA, nil).Code; c != 401 {
		t.Fatalf("baseline: basic auth must refuse the request: %d", c)
	}
	addRule(t, eng, "", "status page is public", `http.path == "/status"`, ruleset.Action{Type: ruleset.ActSkip, Skip: []string{ruleset.SkipAuth}})
	if c := rsGet(router, sep, "http://app.example.com/status", rsIPA, nil).Code; c != okCode {
		t.Fatalf("skip auth: %d", c)
	}
	if c := rsGet(router, sep, "http://app.example.com/private", rsIPA, nil).Code; c != 401 {
		t.Fatalf("skip leaked to another path: %d", c)
	}
}
