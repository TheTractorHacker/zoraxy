package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/auth/sso/forward"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

func exRule(mode, pattern string, nocase bool) *AuthExceptionRule {
	return &AuthExceptionRule{RuleType: AuthExceptionType_Paths, MatchMode: mode, PathPattern: pattern, CaseInsensitive: nocase}
}

func ipRule(cidr string) *AuthExceptionRule {
	return &AuthExceptionRule{RuleType: AuthExceptionType_CIDR, CIDR: cidr}
}

func reqFor(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.RequestURI = target
	return r
}

func TestCanonicalExceptionPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/", "/", true},
		{"/public", "/public", true},
		{"/public/", "/public", true},
		{"/public/a/b?x=../", "/public/a/b", true},
		{"/a%20b", "/a b", true},
		{"/public/../admin", "", false},
		{"/public/./x", "", false},
		{"//public", "", false},
		{"/public//x", "", false},
		{"/public/%2e%2e/admin", "", false},
		{"/public/%2E%2E/admin", "", false},
		{"/public%2f..%2fadmin", "", false},
		{"/public/%252e%252e/admin", "", false}, //double encoding
		{"/public/%25", "", false},              //literal percent
		{"/public\\..\\admin", "", false},
		{"/public/..;/admin", "", false}, //tomcat style path parameter
		{"/public;jsessionid=1/x", "", false},
		{"/public/\x00", "", false},
		{"/public/%00", "", false},
		{"/public/%0a", "", false},
		{"*", "", false},
		{"public", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := canonicalExceptionPath(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("canonicalExceptionPath(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestAuthExceptionPathMatching(t *testing.T) {
	type tc struct {
		rule   *AuthExceptionRule
		target string
		want   bool
	}
	cases := []tc{
		// prefix
		{exRule("prefix", "/public", false), "/public", true},
		{exRule("prefix", "/public", false), "/public/", true},
		{exRule("prefix", "/public", false), "/public/img/a.png?x=1", true},
		{exRule("prefix", "/public/", false), "/public/x", true}, //trailing slash in the rule is ignored
		{exRule("prefix", "/public", false), "/publicfoo", false},
		{exRule("prefix", "/public", false), "/publi", false},
		{exRule("prefix", "/public", false), "/other/public", false},
		{exRule("prefix", "/public", false), "/", false},
		// case
		{exRule("prefix", "/public", false), "/PUBLIC/x", false},
		{exRule("prefix", "/public", true), "/PuBlIc/x", true},
		{exRule("exact", "/Health", false), "/health", false},
		{exRule("exact", "/Health", true), "/health", true},
		// exact
		{exRule("exact", "/health", false), "/health", true},
		{exRule("exact", "/health", false), "/health/", true},
		{exRule("exact", "/health", false), "/health/x", false},
		{exRule("exact", "/health", false), "/healthz", false},
		// regex: full match of the normalised path only
		{exRule("regex", `/api/v[0-9]+/public/.*`, false), "/api/v2/public/x", true},
		{exRule("regex", `/api/v[0-9]+/public/.*`, false), "/x/api/v2/public/x", false},
		{exRule("regex", `/api/v[0-9]+/public/.*`, false), "/api/v2/public", false},
		{exRule("regex", `/public`, false), "/public/secret", false},
		{exRule("regex", `/public`, false), "/secret/public", false},
		{exRule("regex", `/Public`, true), "/public", true},
		{exRule("regex", `(`, false), "/anything", false}, //invalid regexp never matches
		// bypass attempts: every one must be refused (SSO check keeps running)
		{exRule("prefix", "/public", false), "/public/../admin", false},
		{exRule("prefix", "/public", false), "/public/%2e%2e/admin", false},
		{exRule("prefix", "/public", false), "/public/%2E%2E/admin", false},
		{exRule("prefix", "/public", false), "/public%2f..%2fadmin", false},
		{exRule("prefix", "/public", false), "/public/%252e%252e/admin", false},
		{exRule("prefix", "/public", false), "//public/x", false},
		{exRule("prefix", "/public", false), "/public//../admin", false},
		{exRule("prefix", "/public", false), "/public/..;/admin", false},
		{exRule("prefix", "/public", false), "/public\\..\\admin", false},
		{exRule("prefix", "/public", false), "/admin/../public/x", false}, //would be fine after normalising, but fail closed
		{exRule("prefix", "/public", false), "/public/./x", false},
		{exRule("regex", `/public/.*`, false), "/public/../admin", false},
		{exRule("regex", `.*`, false), "/a/../b", false},
		{exRule("exact", "/health", false), "/health/../admin", false},
		// degenerate rules
		{exRule("prefix", "", false), "/x", false},
		{exRule("prefix", "/", false), "/x", false},
	}
	for _, c := range cases {
		got := AuthExceptionMatched([]*AuthExceptionRule{c.rule}, reqFor(c.target), "198.51.100.1")
		if got != c.want {
			t.Errorf("rule %+v target %q = %v, want %v", *c.rule, c.target, got, c.want)
		}
	}
	// nil / empty safety
	if AuthExceptionMatched(nil, reqFor("/x"), "") || AuthExceptionMatched([]*AuthExceptionRule{nil}, reqFor("/x"), "") {
		t.Error("nil rules matched")
	}
}

func TestAuthExceptionCIDRMatching(t *testing.T) {
	cases := []struct {
		rule, ip string
		want     bool
	}{
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "11.0.0.1", false},
		{"192.0.2.7", "192.0.2.7", true},
		{"192.0.2.7", "192.0.2.8", false},
		{"2001:db8::/32", "2001:db8::1", true},
		{"2001:db8::/32", "2001:db9::1", false},
		{"10.0.0.0/8", "::ffff:10.1.1.1", true}, //mapped addresses compare as IPv4
		{"::ffff:10.0.0.0/104", "10.9.9.9", true},
		{"10.0.0.0/8", "", false},
		{"10.0.0.0/8", "not-an-ip", false},
		{"garbage", "10.0.0.1", false},
		{"10.0.0.0/33", "10.0.0.1", false},
		{"0.0.0.0/0", "10.0.0.1", true}, //validation refuses to store it, see TestValidateAuthExceptionRule
	}
	for _, c := range cases {
		got := AuthExceptionMatched([]*AuthExceptionRule{ipRule(c.rule)}, reqFor("/"), c.ip)
		if got != c.want {
			t.Errorf("rule %q ip %q = %v, want %v", c.rule, c.ip, got, c.want)
		}
	}
}

func TestValidateAuthExceptionRule(t *testing.T) {
	ok := []*AuthExceptionRule{
		exRule("", "/public", false), exRule("prefix", "/api/v1/", false), exRule("exact", "/health", true),
		exRule("regex", `/api/.*`, false), ipRule("10.0.0.0/8"), ipRule("192.0.2.1"), ipRule("2001:db8::/32"), ipRule("10.1.2.3/8"),
	}
	for _, r := range ok {
		if err := ValidateAuthExceptionRule(r); err != nil {
			t.Errorf("%+v rejected: %v", *r, err)
		}
	}
	bad := []*AuthExceptionRule{
		nil, exRule("prefix", "", false), exRule("prefix", "public", false), exRule("prefix", "/", false), exRule("prefix", "//", false),
		exRule("prefix", "/a/../b", false), exRule("prefix", "/a//b", false), exRule("prefix", "/a%2fb", false), exRule("prefix", "/a;b", false),
		exRule("prefix", "/a\\b", false), exRule("prefix", "/a*", false), exRule("prefix", "/a?x", false), exRule("exact", "/a/../b", false),
		exRule("regex", "(", false), exRule("regex", "", false), exRule("bogus", "/a", false), exRule("prefix", strings.Repeat("/a", 400), false),
		ipRule(""), ipRule("0.0.0.0/0"), ipRule("::/0"), ipRule("10.*.*.*"), ipRule("10.0.0.0/40"), ipRule("hello"),
		{RuleType: 99},
	}
	for _, r := range bad {
		if err := ValidateAuthExceptionRule(r); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	r := ipRule("10.1.2.3/8")
	ValidateAuthExceptionRule(r)
	if r.CIDR != "10.0.0.0/8" {
		t.Errorf("CIDR not normalised: %s", r.CIDR)
	}
	r = exRule("exact", "/health/", false)
	ValidateAuthExceptionRule(r)
	if r.PathPattern != "/health" {
		t.Errorf("trailing slash not trimmed: %q", r.PathPattern)
	}
}

// ---- end to end through handleAuthProviderRouting (Forward Auth) ----

type fakeAuth struct {
	srv   *httptest.Server
	calls atomic.Int32
}

func newFakeAuthServer(t *testing.T) *fakeAuth {
	f := &fakeAuth{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		http.Error(w, "denied", http.StatusUnauthorized)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newForwardAuthRouter(t *testing.T, address string) *forward.AuthRouter {
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "fwd.db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	lg, _ := logger.NewFmtLogger()
	o := &forward.AuthRouterOptions{Logger: lg, Database: db}
	ar := forward.NewAuthRouter(o)
	o.Address = address
	o.ResponseHeaders = []string{"X-Remote-User", "X-authentik-*"}
	return ar
}

func TestForwardAuthExceptionsEndToEnd(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	fa := newFakeAuthServer(t)
	router.Option.ForwardAuthRouter = newForwardAuthRouter(t, fa.srv.URL)
	sep.AuthenticationProvider = &AuthenticationProvider{
		AuthMethod: AuthMethodForward,
		ExternalAuthExceptionRules: []*AuthExceptionRule{
			exRule("prefix", "/public", false),
			exRule("exact", "/healthz", false),
			ipRule("203.0.113.0/24"),
		},
	}
	h := router.mux.(*ProxyHandler)

	do := func(target, remote string, hdr map[string]string) (handled bool, req *http.Request) {
		r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		r.RequestURI = target
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		return handleAuthProviderRouting(sep, w, r, h), r
	}

	// exempt path: not handled (request continues to the upstream), the auth server is never asked
	before := fa.calls.Load()
	handled, req := do("/public/logo.png", "198.51.100.9:1000", map[string]string{"X-Remote-User": "root", "X-Authentik-Username": "root"})
	if handled {
		t.Fatal("exempt path was handled")
	}
	if fa.calls.Load() != before {
		t.Fatal("auth server contacted for an exempt request")
	}
	if req.Header.Get("X-Remote-User") != "" || req.Header.Get("X-Authentik-Username") != "" {
		t.Fatalf("forged identity headers reached the upstream on an exempt request: %v", req.Header)
	}
	if handled, _ := do("/healthz", "198.51.100.9:1000", nil); handled {
		t.Fatal("exact path not exempted")
	}
	// exempt IP
	if handled, _ := do("/private", "203.0.113.50:1000", nil); handled {
		t.Fatal("exempt CIDR not honoured")
	}

	// everything else still goes through forward auth (which denies)
	for _, c := range []struct{ target, remote string }{
		{"/private", "198.51.100.9:1000"},
		{"/publicfoo", "198.51.100.9:1000"},
		{"/healthz/x", "198.51.100.9:1000"},
		{"/public/../private", "198.51.100.9:1000"},
		{"/public/%2e%2e/private", "198.51.100.9:1000"},
		{"/public%2f..%2fprivate", "198.51.100.9:1000"},
		{"/public/%252e%252e/private", "198.51.100.9:1000"},
		{"/public/..;/private", "198.51.100.9:1000"},
		{"//public/x", "198.51.100.9:1000"},
		{"/PUBLIC/x", "198.51.100.9:1000"},
	} {
		if handled, _ := do(c.target, c.remote, nil); !handled {
			t.Errorf("%s from %s bypassed forward auth", c.target, c.remote)
		}
	}

	// spoofed client IP headers from an untrusted peer do not satisfy a CIDR rule
	spoof := map[string]string{"X-Forwarded-For": "203.0.113.50", "X-Real-Ip": "203.0.113.50", "CF-Connecting-IP": "203.0.113.50", "Forwarded": "for=203.0.113.50"}
	if handled, _ := do("/private", "198.51.100.9:1000", spoof); !handled {
		t.Fatal("spoofed X-Forwarded-For bypassed forward auth (trust-proxy off)")
	}
	rule.TrustProxyHeadersOnly = true
	router.Option.AccessController.AddTrustedProxy("192.0.2.0/24", "proxy")
	if handled, _ := do("/private", "198.51.100.9:1000", spoof); !handled {
		t.Fatal("spoofed X-Forwarded-For from an untrusted peer bypassed forward auth (trust-proxy on)")
	}
	// a configured trusted proxy may forward the real client address
	if handled, _ := do("/private", "192.0.2.5:1000", spoof); handled {
		t.Fatal("client IP forwarded by a trusted proxy was not honoured")
	}
	// and that does not make the path rules weaker
	if handled, _ := do("/public/../private", "192.0.2.5:1000", map[string]string{"X-Forwarded-For": "198.51.100.77"}); !handled {
		t.Fatal("traversal through a trusted proxy bypassed forward auth")
	}

	// no rules at all: unchanged behaviour
	sep.AuthenticationProvider.ExternalAuthExceptionRules = nil
	if handled, _ := do("/public/x", "203.0.113.50:1000", nil); !handled {
		t.Fatal("request skipped forward auth without any rule")
	}
}
