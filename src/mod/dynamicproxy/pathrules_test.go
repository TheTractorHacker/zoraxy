package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustCompileRule(t *testing.T, r PathRule) *compiledPathRule {
	t.Helper()
	c, err := compilePathRule(&r)
	if err != nil {
		t.Fatalf("compile %+v: %v", r, err)
	}
	return c
}

// Bypass oriented table: every spelling of /admin that a backend might resolve to /admin must be caught by a deny rule
func TestPathRule_DenyPrefixNormalisation(t *testing.T) {
	rule := mustCompileRule(t, PathRule{MatchMode: PathRuleMatchPrefix, Pattern: "/admin", Action: PathRuleDeny})
	blocked := []string{
		"/admin", "/admin/", "/admin/users", "/admin?x=1", "/admin/?x=/other",
		"//admin", "///admin/x", "/./admin", "/a/../admin", "/public/../admin",
		"/%61dmin", "/%41dmin" /* upper A is a different path for case sensitive rules, see below */, "/%2e/admin", "/%2e%2e/admin",
		"/public/%2e%2e/admin", "/public/..%2fadmin", "/public%2f..%2fadmin", "/admin%2fusers", "/%2fadmin",
		"/%2561dmin", "/%252e/admin", "/%252e%252e/admin", "/%25252e%25252e/admin",
		"/admin;x=1", "/admin;/x", "/public/..;/admin", "/;a=b/admin",
		"/\\admin", "/public\\..\\admin", "/admin%5cx", "/admin%00.png", "/admin\x00",
		"http://example.com/admin", "http://example.com//admin",
		"/%2e%2e/%2e%2e/admin",
	}
	for _, target := range blocked {
		if target == "/%41dmin" {
			continue //case difference, covered in the case-insensitive test
		}
		if !rule.matchesRequest(target, "GET") {
			t.Errorf("deny /admin did not match %q", target)
		}
	}
	allowed := []string{"/", "/administrator", "/adminx", "/admin-x", "/public", "/x/admin", "/public/admin", "/adm", "/admin.bak", "/ADMIN"}
	for _, target := range allowed {
		if rule.matchesRequest(target, "GET") {
			t.Errorf("deny /admin wrongly matched %q", target)
		}
	}
}

func TestPathRule_CaseInsensitive(t *testing.T) {
	rule := mustCompileRule(t, PathRule{Pattern: "/admin", CaseInsensitive: true, Action: PathRuleDeny})
	for _, target := range []string{"/ADMIN", "/Admin/x", "/%41dmin", "//AdMiN", "/%2541DMIN"} {
		if !rule.matchesRequest(target, "GET") {
			t.Errorf("case insensitive deny did not match %q", target)
		}
	}
}

func TestPathRule_ExactAndRegex(t *testing.T) {
	exact := mustCompileRule(t, PathRule{MatchMode: PathRuleMatchExact, Pattern: "/login", Action: PathRuleDeny})
	for target, want := range map[string]bool{"/login": true, "/login/": true, "//login": true, "/%6cogin": true, "/login/x": false, "/loginx": false, "/": false} {
		if got := exact.matchesRequest(target, "GET"); got != want {
			t.Errorf("exact /login vs %q = %v, want %v", target, got, want)
		}
	}
	re := mustCompileRule(t, PathRule{MatchMode: PathRuleMatchRegex, Pattern: `/(admin|internal)/.*`, Action: PathRuleDeny})
	for target, want := range map[string]bool{
		"/admin/x": true, "/internal/a/b": true, "/%61dmin/x": true, "//admin//x": true, "/public/%2e%2e/internal/x": true,
		"/admin": false, "/other/admin/x": false, "/administrator/x": false,
	} {
		if got := re.matchesRequest(target, "GET"); got != want {
			t.Errorf("regex vs %q = %v, want %v", target, got, want)
		}
	}
	//regex is anchored, an unanchored pattern can not match a part of the path
	partial := mustCompileRule(t, PathRule{MatchMode: PathRuleMatchRegex, Pattern: `admin`, Action: PathRuleDeny})
	if partial.matchesRequest("/admin/x", "GET") {
		t.Error("regex matched a part of the path, it must match the whole path")
	}
}

func TestPathRule_RootPrefix(t *testing.T) {
	rule := mustCompileRule(t, PathRule{Pattern: "/", Action: PathRuleDeny})
	for _, target := range []string{"/", "/a", "//a", "/a/b"} {
		if !rule.matchesRequest(target, "GET") {
			t.Errorf("/ prefix did not match %q", target)
		}
	}
}

func TestPathRule_Methods(t *testing.T) {
	rule := mustCompileRule(t, PathRule{Pattern: "/api", Methods: []string{"post", "DELETE"}, Action: PathRuleDeny})
	for m, want := range map[string]bool{"POST": true, "post": true, "DELETE": true, "GET": false, "PUT": false, "HEAD": false} {
		if got := rule.matchesRequest("/api/x", m); got != want {
			t.Errorf("method %s = %v, want %v", m, got, want)
		}
	}
}

func TestPathRule_AllowOnlyForCanonicalTargets(t *testing.T) {
	rule := mustCompileRule(t, PathRule{MatchMode: PathRuleMatchExact, Pattern: "/api/health", Action: PathRuleAllow})
	if !rule.matchesRequest("/api/health", "GET") {
		t.Fatal("allow rule did not match the canonical path")
	}
	for _, target := range []string{"//api/health", "/api/./health", "/api/%68ealth", "/api/health;x=1", "/x/../api/health", "/api%2fhealth", "/api\\health", "/api/health%00"} {
		if rule.matchesRequest(target, "GET") {
			t.Errorf("allow rule matched non canonical target %q", target)
		}
	}
}

func TestPathRule_CompileErrors(t *testing.T) {
	bad := []PathRule{
		{Pattern: "", Action: PathRuleDeny},
		{Pattern: "admin", Action: PathRuleDeny},
		{Pattern: "/a", Action: "explode"},
		{Pattern: "/a", Action: ""},
		{Pattern: "/a", Action: PathRuleRateLimit},
		{Pattern: "/a", Action: PathRuleRateLimit, RateLimit: 1, RateBurst: -1},
		{MatchMode: PathRuleMatchRegex, Pattern: "(", Action: PathRuleDeny},
		{MatchMode: "fuzzy", Pattern: "/a", Action: PathRuleDeny},
		{Pattern: "/a", Action: PathRuleDeny, Methods: []string{"G ET"}},
		{Pattern: "/a", Action: PathRuleDeny, CIDRs: []string{"300.1.1.1/8"}},
		{Pattern: "/a", Action: PathRuleDeny, Countries: []string{"USA"}},
		{Pattern: "/a", Action: PathRuleDeny, ScopeInvert: true},
		{Pattern: "/" + strings.Repeat("a", maxPathRulePatternLen), Action: PathRuleDeny},
	}
	for i, r := range bad {
		rule := r
		if _, err := compilePathRule(&rule); err == nil {
			t.Errorf("case %d (%+v) compiled but should be rejected", i, r)
		}
	}
	if err := ValidatePathRules(make([]*PathRule, maxPathRules+1)); err == nil {
		t.Error("too many rules accepted")
	}
}

/* End to end through the shared chain */

func pathRuleRouter(t *testing.T, rules ...*PathRule) (*Router, *ProxyEndpoint) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.PathRules = rules
	sep.initNetworkOptions()
	if sep.pathRulesErr != nil {
		t.Fatal(sep.pathRulesErr)
	}
	return router, sep
}

func serveRaw(router *Router, sep *ProxyEndpoint, method, target, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, "http://app.example.com/", nil)
	r.RequestURI = target
	if i := strings.IndexAny(target, "?"); i >= 0 {
		r.URL.RawQuery = target[i+1:]
		target = target[:i]
	}
	r.URL.Path = target
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	router.handleNonTLSRequest(w, r, sep)
	return w
}

func TestPathRule_ChainDenyAndAllow(t *testing.T) {
	router, sep := pathRuleRouter(t,
		&PathRule{MatchMode: PathRuleMatchExact, Pattern: "/api/health", Action: PathRuleAllow},
		&PathRule{Pattern: "/api", Action: PathRuleDeny},
		&PathRule{Pattern: "/admin", Methods: []string{"POST"}, Action: PathRuleDeny},
	)
	cases := []struct {
		method, target string
		want           int
	}{
		{"GET", "/", 299}, {"GET", "/api/health", 299}, {"GET", "/api/other", 403}, {"GET", "/api", 403},
		{"GET", "//api/health", 403}, {"GET", "/api/%68ealth", 403}, {"GET", "/api/health;x", 403}, {"GET", "/x/../api/other", 403},
		{"GET", "/admin", 299}, {"POST", "/admin", 403}, {"POST", "//admin", 403}, {"POST", "/%61dmin", 403},
		{"GET", "/apiary", 299},
	}
	for _, c := range cases {
		if w := serveRaw(router, sep, c.method, c.target, "198.51.100.1:1000", nil); w.Code != c.want {
			t.Errorf("%s %q = %d, want %d", c.method, c.target, w.Code, c.want)
		}
	}
}

func TestPathRule_ScopeAndSpoofedForwardedFor(t *testing.T) {
	//deny /admin for everybody outside 10.0.0.0/8
	router, sep := pathRuleRouter(t, &PathRule{Pattern: "/admin", Action: PathRuleDeny, CIDRs: []string{"10.0.0.0/8", "fd00::/8"}, ScopeInvert: true})
	cases := []struct {
		remote string
		hdr    map[string]string
		want   int
	}{
		{"10.1.2.3:1", nil, 299},
		{"[fd00::5]:1", nil, 299},
		{"[::ffff:10.1.2.3]:1", nil, 299},
		{"198.51.100.1:1", nil, 403},
		{"198.51.100.1:1", map[string]string{"X-Forwarded-For": "10.1.2.3"}, 403},
		{"198.51.100.1:1", map[string]string{"X-Real-IP": "10.1.2.3", "CF-Connecting-IP": "10.1.2.3"}, 403},
		{"198.51.100.1:1", map[string]string{"Forwarded": "for=10.1.2.3"}, 403},
	}
	for _, c := range cases {
		if w := serveRaw(router, sep, "GET", "/admin", c.remote, c.hdr); w.Code != c.want {
			t.Errorf("remote %s hdr %v = %d, want %d", c.remote, c.hdr, w.Code, c.want)
		}
	}

	//plain scope: deny only for a CIDR
	router, sep = pathRuleRouter(t, &PathRule{Pattern: "/", Action: PathRuleDeny, CIDRs: []string{"203.0.113.0/24"}})
	if w := serveRaw(router, sep, "GET", "/x", "203.0.113.7:1", nil); w.Code != 403 {
		t.Errorf("in scope got %d", w.Code)
	}
	if w := serveRaw(router, sep, "GET", "/x", "198.51.100.1:1", nil); w.Code != 299 {
		t.Errorf("out of scope got %d", w.Code)
	}
}

func TestPathRule_CountryScopeWithoutGeoDB(t *testing.T) {
	//Without a GeoIP database a country scope can not match: a plain scope does not apply, an inverted one does (deny)
	c := mustCompileRule(t, PathRule{Pattern: "/a", Action: PathRuleDeny, Countries: []string{"cn", "RU"}})
	if c.inScope(nil, "198.51.100.1") {
		t.Error("country scope matched without a geo database")
	}
	c = mustCompileRule(t, PathRule{Pattern: "/a", Action: PathRuleDeny, Countries: []string{"US"}, ScopeInvert: true})
	if !c.inScope(nil, "198.51.100.1") {
		t.Error("inverted country scope should apply when the country is unknown")
	}
}

func TestPathRule_RateLimit(t *testing.T) {
	router, sep := pathRuleRouter(t,
		&PathRule{Name: "login", Pattern: "/login", Action: PathRuleRateLimit, RateLimit: 1, RateBurst: 2},
	)
	hit := func(remote string, target string, hdr map[string]string) int {
		return serveRaw(router, sep, "POST", target, remote, hdr).Code
	}
	if c := hit("198.51.100.1:1", "/login", nil); c != 299 {
		t.Fatalf("first = %d", c)
	}
	if c := hit("198.51.100.1:2", "/login", nil); c != 299 {
		t.Fatalf("second (burst) = %d", c)
	}
	if c := hit("198.51.100.1:3", "/login", nil); c != 429 {
		t.Fatalf("third = %d, want 429", c)
	}
	//Path tricks do not get a fresh bucket or escape the limit
	if c := hit("198.51.100.1:4", "//login", nil); c != 429 {
		t.Fatalf("//login = %d, want 429", c)
	}
	if c := hit("198.51.100.1:4", "/%6cogin", nil); c != 429 {
		t.Fatalf("/%%6cogin = %d, want 429", c)
	}
	//Spoofed forwarded-for headers do not give a new bucket
	if c := hit("198.51.100.1:5", "/login", map[string]string{"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"}); c != 429 {
		t.Fatalf("spoofed headers = %d, want 429", c)
	}
	//Other client and other path are unaffected
	if c := hit("198.51.100.2:1", "/login", nil); c != 299 {
		t.Fatalf("other client = %d", c)
	}
	if c := hit("198.51.100.1:6", "/other", nil); c != 299 {
		t.Fatalf("other path = %d", c)
	}
}

func TestPathRule_RequireAuth(t *testing.T) {
	router, sep := pathRuleRouter(t, &PathRule{Pattern: "/public/secret", Action: PathRuleRequireAuth})
	//No provider on the endpoint: fail closed
	if w := serveRaw(router, sep, "GET", "/public/secret", "198.51.100.1:1", nil); w.Code != 403 {
		t.Fatalf("require_auth without a provider = %d, want 403", w.Code)
	}
	if w := serveRaw(router, sep, "GET", "/public/other", "198.51.100.1:1", nil); w.Code != 299 {
		t.Fatalf("unrelated path = %d", w.Code)
	}

	//Basic auth with a path exception for /public: require_auth overrides the exception for the secret path only
	sep.AuthenticationProvider = &AuthenticationProvider{
		AuthMethod:              AuthMethodBasic,
		BasicAuthCredentials:    []*BasicAuthCredentials{{Username: "u", PasswordHash: "00"}},
		BasicAuthExceptionRules: []*BasicAuthExceptionRule{{RuleType: AuthExceptionType_Paths, PathPrefix: "/public"}},
	}
	if w := serveRaw(router, sep, "GET", "/public/other", "198.51.100.1:1", nil); w.Code != 299 {
		t.Fatalf("exception path = %d, want 299", w.Code)
	}
	for _, target := range []string{"/public/secret", "//public/secret", "/public/%73ecret"} {
		if w := serveRaw(router, sep, "GET", target, "198.51.100.1:1", nil); w.Code != 401 {
			t.Errorf("%q = %d, want 401 (auth forced)", target, w.Code)
		}
	}
}

func TestPathRule_OffByDefaultAndFailClosed(t *testing.T) {
	router, sep := pathRuleRouter(t)
	if w := serveRaw(router, sep, "GET", "/anything", "198.51.100.1:1", nil); w.Code != 299 {
		t.Fatalf("no rules = %d", w.Code)
	}
	sep.PathRules = []*PathRule{{Pattern: "no-slash", Action: PathRuleDeny}}
	sep.initNetworkOptions()
	if w := serveRaw(router, sep, "GET", "/anything", "198.51.100.1:1", nil); w.Code != 503 {
		t.Fatalf("invalid rules = %d, want 503 (fail closed)", w.Code)
	}
}

var _ = http.StatusOK
