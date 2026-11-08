package oauth2

import (
	"encoding/json"
	"testing"
)

// claims decoded from JSON exactly like the real ones (arrays are []any, objects map[string]any)
func jsonClaims(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Allowed-claim-values on the shapes real identity providers emit (fork #172).
func TestRoleClaimShapesOfCommonProviders(t *testing.T) {
	keycloak := jsonClaims(t, `{
		"sub":"1","preferred_username":"alice",
		"realm_access":{"roles":["offline_access","realm-admin"]},
		"resource_access":{"grafana":{"roles":["editor"]},"my.app":{"roles":["viewer"]},"account":{"roles":["manage-account"]}},
		"groups":["/ops","/ops/oncall"]}`)
	entra := jsonClaims(t, `{
		"sub":"2","tid":"72f988bf-86f1-41af-91ab-2d7cd011db47","roles":["Task.Admin","User"],
		"groups":["9a1d6c3e-0000-4000-8000-000000000001","9a1d6c3e-0000-4000-8000-000000000002"]}`)
	entraOverage := jsonClaims(t, `{"sub":"2","_claim_names":{"groups":"src1"},"_claim_sources":{"src1":{"endpoint":"https://graph.microsoft.com/..."}}}`)
	authentik := jsonClaims(t, `{"sub":"3","groups":["authentik Admins","engineering"],"email":"c@corp.example","email_verified":true}`)
	google := jsonClaims(t, `{"sub":"4","email":"d@corp.example","email_verified":true,"hd":"corp.example"}`)
	urlStyle := jsonClaims(t, `{"sub":"5","https://example.com/roles":["admin"]}`)

	cases := []struct {
		name   string
		claims map[string]any
		rules  string // OAuth2AllowedClaims
		groups string // OAuth2AllowedGroups
		gclaim string
		want   bool
	}{
		{"keycloak realm role", keycloak, "realm_access.roles=realm-admin", "", "", true},
		{"keycloak realm role missing", keycloak, "realm_access.roles=superuser", "", "", false},
		{"keycloak one of several", keycloak, "realm_access.roles=superuser,realm-admin", "", "", true},
		{"keycloak client role", keycloak, "resource_access.grafana.roles=editor", "", "", true},
		{"keycloak client role of another client", keycloak, "resource_access.account.roles=editor", "", "", false},
		{"keycloak client id containing a dot", keycloak, "resource_access.my.app.roles=viewer", "", "", true},
		{"keycloak client missing", keycloak, "resource_access.nope.roles=viewer", "", "", false},
		{"keycloak both realm and client", keycloak, "realm_access.roles=realm-admin; resource_access.grafana.roles=editor", "", "", true},
		{"keycloak both, one fails", keycloak, "realm_access.roles=realm-admin; resource_access.grafana.roles=admin", "", "", false},
		{"keycloak group path", keycloak, "", "/ops", "", true},
		{"keycloak group path is exact", keycloak, "", "ops", "", false},
		{"keycloak nested scalar is not a role list", keycloak, "realm_access=realm-admin", "", "", false},
		{"entra app role", entra, "roles=Task.Admin", "", "", true},
		{"entra app role case sensitive", entra, "roles=task.admin", "", "", false},
		{"entra group object id", entra, "", "9a1d6c3e-0000-4000-8000-000000000002", "", true},
		{"entra group via rule", entra, "groups=9a1d6c3e-0000-4000-8000-000000000001", "", "", true},
		{"entra tenant", entra, "tid=72f988bf-86f1-41af-91ab-2d7cd011db47", "", "", true},
		{"entra other tenant", entra, "tid=00000000-0000-0000-0000-000000000000", "", "", false},
		{"entra group overage fails closed", entraOverage, "", "9a1d6c3e-0000-4000-8000-000000000001", "", false},
		{"authentik group", authentik, "", "authentik Admins", "", true},
		{"authentik group missing", authentik, "", "finance", "", false},
		{"authentik group via claim rule", authentik, "groups=engineering", "", "", true},
		{"google hosted domain", google, "hd=corp.example", "", "", true},
		{"google other domain", google, "hd=evil.example", "", "", false},
		{"google personal account has no hd", jsonClaims(t, `{"sub":"6","email":"x@gmail.com"}`), "hd=corp.example", "", "", false},
		{"url style claim name", urlStyle, "https://example.com/roles=admin", "", "", true},
		{"custom groups claim", entra, "", "Task.Admin", "roles", true},
		{"object claim is not matched", jsonClaims(t, `{"roles":{"admin":true}}`), "roles=admin", "", "", false},
		{"number claim", jsonClaims(t, `{"level":3}`), "level=3", "", "", true},
		{"boolean claim", jsonClaims(t, `{"staff":true}`), "staff=true", "", "", true},
		{"mixed array", jsonClaims(t, `{"roles":["a",1,{"x":1},["b"]]}`), "roles=b", "", "", true},
		{"empty array", jsonClaims(t, `{"roles":[]}`), "roles=admin", "", "", false},
		{"null claim", jsonClaims(t, `{"roles":null}`), "roles=admin", "", "", false},
		{"values are not substring matched", keycloak, "realm_access.roles=admin", "", "", false},
	}
	for _, c := range cases {
		o := &OAuth2RouterOptions{OAuth2AllowedClaims: c.rules, OAuth2AllowedGroups: c.groups, OAuth2GroupsClaim: c.gclaim}
		if got := accessAllowed(o, c.claims); got != c.want {
			t.Errorf("%s: allowed=%v want %v", c.name, got, c.want)
		}
	}
}

func TestClaimPathResolution(t *testing.T) {
	claims := jsonClaims(t, `{"a.b":{"c":"literal-prefix"},"a":{"b":{"c":"nested"}},"x.y.z":"flat","k":{"m.n":{"o":"mixed"}}}`)
	for name, want := range map[string]string{
		"a.b.c":   "literal-prefix", // the longest literal key wins at the first level
		"x.y.z":   "flat",
		"k.m.n.o": "mixed",
	} {
		v, ok := claimValue(claims, name)
		if !ok {
			t.Errorf("%s not resolved", name)
			continue
		}
		var got string
		if m, isMap := v.(map[string]any); isMap {
			got = "map"
			_ = m
		} else {
			got, _ = v.(string)
		}
		if name == "a.b.c" {
			// "a.b" literal holds {"c": ...}; resolving a.b.c descends into it
			if got != want {
				t.Errorf("%s = %v", name, v)
			}
			continue
		}
		if got != want {
			t.Errorf("%s = %v, want %s", name, v, want)
		}
	}
	if _, ok := claimValue(claims, "a.b.nope"); ok {
		t.Error("missing path resolved")
	}
	if _, ok := claimValue(claims, ""); ok {
		t.Error("empty name resolved")
	}
	if _, ok := claimValue(claims, "a..b"); ok {
		t.Error("empty segment resolved")
	}
}

// End to end: roles carried in the ID token (Keycloak shape) gate the login, and are re-evaluated on every request.
func TestKeycloakRolesEndToEnd(t *testing.T) {
	idp := newFakeIdP(t)
	idp.user["realm_access"] = map[string]any{"roles": []any{"viewer"}}
	idp.user["resource_access"] = map[string]any{"app": map[string]any{"roles": []any{"editor"}}}
	ar := newTestRouter(t, idp, func(o *OAuth2RouterOptions) {
		o.OAuth2AllowedClaims = "resource_access.app.roles=editor,admin; realm_access.roles=viewer"
		o.OAuth2HeaderMappings = "X-Roles=realm_access.roles"
	})
	b := newBrowser(t, ar)
	mustLogin(t, b, idp)
	r := b.request("GET", appURL+"/")
	if _, err := b.do(r); err != nil || r.Header.Get("X-Roles") != "viewer" {
		t.Fatalf("nested claim header mapping: %q err=%v", r.Header.Get("X-Roles"), err)
	}
	idp.user["resource_access"] = map[string]any{"app": map[string]any{"roles": []any{"guest"}}}
	if w := newBrowser(t, ar).login(idp, appURL+"/"); w.Code != 403 {
		t.Fatalf("missing client role must deny: %d", w.Code)
	}
}
