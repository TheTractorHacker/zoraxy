package dynamicproxy

import (
	"strings"
	"testing"
)

func TestAuditAuthMethodsAndWeaknesses(t *testing.T) {
	cases := []struct {
		name     string
		ap       *AuthenticationProvider
		method   string
		weakHint string // substring expected in the weaknesses ("" = none expected)
	}{
		{"nil provider", nil, "none", ""},
		{"explicit none", &AuthenticationProvider{AuthMethod: AuthMethodNone}, "none", ""},
		{"basic clean", &AuthenticationProvider{AuthMethod: AuthMethodBasic, BasicAuthCredentials: []*BasicAuthCredentials{{Username: "a"}}}, "basic", ""},
		{"basic exceptions", &AuthenticationProvider{AuthMethod: AuthMethodBasic, BasicAuthCredentials: []*BasicAuthCredentials{{Username: "a"}},
			BasicAuthExceptionRules: []*BasicAuthExceptionRule{{RuleType: AuthExceptionType_Paths, PathPrefix: "/api"}, nil}}, "basic", "skip basic auth"},
		{"basic trusting exception", &AuthenticationProvider{AuthMethod: AuthMethodBasic, BasicAuthCredentials: []*BasicAuthCredentials{{Username: "a"}},
			BasicAuthExceptionRules: []*BasicAuthExceptionRule{{RuleType: AuthExceptionType_CIDR, CIDR: "10.0.0.0/8", UseTrustedProxy: true}}}, "basic", "trust forwarded"},
		{"basic scoped", &AuthenticationProvider{AuthMethod: AuthMethodBasic, BasicAuthCredentials: []*BasicAuthCredentials{{Username: "a"}},
			BasicAuthScopePrefixes: []string{"/admin"}}, "basic", "rest of the host is open"},
		{"basic without users", &AuthenticationProvider{AuthMethod: AuthMethodBasic}, "basic", "no users"},
		{"basic list only", &AuthenticationProvider{AuthMethod: AuthMethodBasic, BasicAuthListNames: []string{"x"}}, "basic", ""},
		{"oauth2 exceptions", &AuthenticationProvider{AuthMethod: AuthMethodOauth2, ExternalAuthExceptionRules: []*AuthExceptionRule{{}}}, "oauth2", "skip oauth2"},
		{"forward clean", &AuthenticationProvider{AuthMethod: AuthMethodForward}, "forward", ""},
		{"zorxauth exceptions", &AuthenticationProvider{AuthMethod: AuthMethodZorxAuth, ZorxAuthExceptionRules: []*ZorxAuthExceptionRule{{RuleType: AuthExceptionType_CIDR, UseTrustedProxy: true}}}, "zorxauth", "trust forwarded"},
	}
	for _, c := range cases {
		row := AuditAuth(&ProxyEndpoint{RootOrMatchingDomain: "x.example.com", AuthenticationProvider: c.ap, Tags: []string{"prod"}})
		if row.Method != c.method || row.WantedTag != "auth:"+c.method {
			t.Errorf("%s: method %q tag %q", c.name, row.Method, row.WantedTag)
		}
		joined := strings.Join(row.Weaknesses, "|")
		if c.weakHint == "" && joined != "" || c.weakHint != "" && !strings.Contains(joined, c.weakHint) {
			t.Errorf("%s: weaknesses %q, want hint %q", c.name, joined, c.weakHint)
		}
	}
}

func TestAuditDoesNotMutateAndRetag(t *testing.T) {
	pe := &ProxyEndpoint{RootOrMatchingDomain: "a.example.com", Tags: []string{"prod", "auth:none", "auth:oauth2"}}
	before := strings.Join(pe.Tags, ",")
	row := AuditAuth(pe)
	row.Tags[0] = "tampered"
	if strings.Join(pe.Tags, ",") != before {
		t.Fatal("audit shares or changes the endpoint tags")
	}
	got := RetagAuth(pe.Tags, "auth:basic")
	if strings.Join(got, ",") != "prod,auth:basic" {
		t.Fatalf("retag: %v", got)
	}
	// idempotent and keeps foreign tags that merely contain "auth"
	again := RetagAuth(RetagAuth([]string{"authors", "x-auth:y"}, "auth:none"), "auth:none")
	if strings.Join(again, ",") != "authors,x-auth:y,auth:none" {
		t.Fatalf("retag: %v", again)
	}
}

func TestAuditAllAuthSortedAndComplete(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.ProxyEndpoints.Store("b.example.com", &ProxyEndpoint{RootOrMatchingDomain: "b.example.com", AuthenticationProvider: &AuthenticationProvider{AuthMethod: AuthMethodForward}})
	router.ProxyEndpoints.Store("a.example.com", &ProxyEndpoint{RootOrMatchingDomain: "a.example.com"})
	_ = sep
	rows := router.AuditAllAuth()
	if len(rows) != 2 || rows[0].Name != "a.example.com" || rows[0].Method != "none" || rows[1].Method != "forward" {
		t.Fatalf("%+v", rows)
	}
}
