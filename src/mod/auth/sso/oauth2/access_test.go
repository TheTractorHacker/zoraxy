package oauth2

import (
	"net/http"
	"strings"
	"testing"
)

func TestClaimRulesParsing(t *testing.T) {
	good := map[string]int{"": 0, "roles=admin": 1, "roles=admin,editor; department=it": 2, " ; roles = a ; ": 1}
	for in, n := range good {
		r, err := ParseClaimRules(in)
		if err != nil || len(r) != n {
			t.Errorf("%q: %v %d", in, err, len(r))
		}
	}
	for _, bad := range []string{"roles", "=x", "roles=", "roles=,,", strings.Repeat("a", 300) + "=x", "r=" + strings.Repeat("v", 300),
		strings.Repeat("a=b;", 21)} {
		if _, err := ParseClaimRules(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAccessAllowedMatrix(t *testing.T) {
	type m = map[string]any
	cases := []struct {
		name   string
		o      OAuth2RouterOptions
		claims map[string]any
		want   bool
	}{
		{"nothing configured allows", OAuth2RouterOptions{}, m{}, true},
		{"role match", OAuth2RouterOptions{OAuth2AllowedClaims: "roles=admin,editor"}, m{"roles": []any{"viewer", "editor"}}, true},
		{"role miss", OAuth2RouterOptions{OAuth2AllowedClaims: "roles=admin"}, m{"roles": []any{"viewer"}}, false},
		{"role claim missing fails closed", OAuth2RouterOptions{OAuth2AllowedClaims: "roles=admin"}, m{}, false},
		{"scalar claim", OAuth2RouterOptions{OAuth2AllowedClaims: "department=it"}, m{"department": "it"}, true},
		{"value is exact, not substring", OAuth2RouterOptions{OAuth2AllowedClaims: "roles=admin"}, m{"roles": []any{"administrator", "sysadmin"}}, false},
		{"case sensitive", OAuth2RouterOptions{OAuth2AllowedClaims: "roles=Admin"}, m{"roles": []any{"admin"}}, false},
		{"nested claim", OAuth2RouterOptions{OAuth2AllowedClaims: "realm_access.roles=ops"}, m{"realm_access": m{"roles": []any{"ops"}}}, true},
		{"all rules must match", OAuth2RouterOptions{OAuth2AllowedClaims: "roles=a; department=it"}, m{"roles": []any{"a"}, "department": "hr"}, false},
		{"broken rule set never opens access", OAuth2RouterOptions{OAuth2AllowedClaims: "roles"}, m{"roles": []any{"a"}}, false},
		{"groups AND claims", OAuth2RouterOptions{OAuth2AllowedGroups: "g1", OAuth2AllowedClaims: "roles=a"}, m{"groups": []any{"g1"}, "roles": []any{"b"}}, false},
		{"email exact", OAuth2RouterOptions{OAuth2AllowedEmails: "Alice@Example.com"}, m{"email": "alice@example.COM"}, true},
		{"email other", OAuth2RouterOptions{OAuth2AllowedEmails: "alice@example.com"}, m{"email": "bob@example.com"}, false},
		{"domain match", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com, @corp.test"}, m{"email": "x@corp.test"}, true},
		{"subdomain not included", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": "x@sub.example.com"}, false},
		{"suffix trick", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": "x@evil-example.com"}, false},
		{"prefix trick", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": "x@example.com.evil.test"}, false},
		{"double at", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": "x@evil.test@example.com"}, false},
		{"quoted local part tricks", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": `"a@example.com"@evil.test`}, false},
		{"whitespace trick", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": "x@evil.test example.com"}, false},
		{"unverified email denied", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": "x@example.com", "email_verified": false}, false},
		{"unverified string", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": "x@example.com", "email_verified": "false"}, false},
		{"verified ok", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": "x@example.com", "email_verified": true}, true},
		{"missing email fails closed", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{}, false},
		{"non string email", OAuth2RouterOptions{OAuth2AllowedEmailDomains: "example.com"}, m{"email": []any{"x@example.com"}}, false},
		{"email list OR domain list", OAuth2RouterOptions{OAuth2AllowedEmails: "z@other.test", OAuth2AllowedEmailDomains: "example.com"}, m{"email": "z@other.test"}, true},
	}
	for _, c := range cases {
		o := c.o
		if got := accessAllowed(&o, c.claims); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// End to end through the real login flow with the fake IdP used by the other tests
func TestClaimAndEmailAllowListEndToEnd(t *testing.T) {
	idp := newFakeIdP(t)
	idp.user["roles"] = []any{"editor"}
	idp.user["email"] = "alice@example.com"
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) {
		o.OAuth2AllowedClaims = "roles=admin,editor"
		o.OAuth2AllowedEmailDomains = "example.com"
	})
	mustLogin(t, newBrowser(t, ar), idp)

	idp.user["roles"] = []any{"viewer"}
	b := newBrowser(t, ar)
	if w := b.login(idp, appURL+"/"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong role: %d", w.Code)
	}
	if _, ok := b.cookies[sessionCookie]; ok {
		t.Fatal("session issued to a denied user")
	}
	idp.user["roles"] = []any{"admin"}
	idp.user["email"] = "mallory@evil.test"
	if w := newBrowser(t, ar).login(idp, appURL+"/"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong e-mail domain: %d", w.Code)
	}
}
