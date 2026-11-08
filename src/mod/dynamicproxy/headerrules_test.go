package dynamicproxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveWithHeaders(router *Router, sep *ProxyEndpoint, path string, h map[string][]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
	r.RemoteAddr = "198.51.100.1:1000"
	for k, vs := range h {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	router.handleNonTLSRequest(w, r, sep)
	return w
}

func withHeaderRules(t *testing.T, rules ...*HeaderRule) (*Router, *ProxyEndpoint) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.HeaderRules = rules
	sep.initHeaderRules()
	if sep.headerRulesErr != nil {
		t.Fatal(sep.headerRulesErr)
	}
	return router, sep
}

func TestHeaderRuleEqualsAndRotation(t *testing.T) {
	router, sep := withHeaderRules(t, &HeaderRule{Name: "X-Edge-Key", Values: []string{"old-secret", "new-secret"}})
	cases := []struct {
		hdr  map[string][]string
		want int
	}{
		{nil, 403},
		{map[string][]string{"X-Edge-Key": {"old-secret"}}, 299},
		{map[string][]string{"x-edge-key": {"new-secret"}}, 299}, //header names are case insensitive
		{map[string][]string{"X-Edge-Key": {"wrong"}}, 403},
		{map[string][]string{"X-Edge-Key": {"old-secret "}}, 403},  //no trimming tricks
		{map[string][]string{"X-Edge-Key": {"OLD-SECRET"}}, 403},   //case sensitive value
		{map[string][]string{"X-Edge-Key": {"old-secre"}}, 403},    //prefix
		{map[string][]string{"X-Edge-Key": {"old-secret-x"}}, 403}, //extension
		{map[string][]string{"X-Edge-Key": {""}}, 403},             //empty
		{map[string][]string{"X-Edge-Key": {"nope", "new-secret"}}, 299},
		{map[string][]string{"X-Edge-Key": {strings.Repeat("a", 100000)}}, 403}, //oversized value is ignored, not matched
		{map[string][]string{"X-Edge-Key-2": {"old-secret"}}, 403},              //different header
	}
	for i, c := range cases {
		if w := serveWithHeaders(router, sep, "/", c.hdr); w.Code != c.want {
			t.Errorf("case %d: got %d want %d", i, w.Code, c.want)
		}
	}
	// an endpoint without rules is unchanged
	sep.HeaderRules = nil
	sep.initHeaderRules()
	if w := serveWithHeaders(router, sep, "/", nil); w.Code != 299 {
		t.Fatal("no rules must mean no change")
	}
}

func TestHeaderRuleRegexPresentAndAND(t *testing.T) {
	router, sep := withHeaderRules(t,
		&HeaderRule{Name: "X-Client", Match: "regex", Values: []string{`app/\d+\.\d+`, `internal-.*`}},
		&HeaderRule{Name: "X-Token", Match: "present"},
	)
	ok := map[string][]string{"X-Client": {"app/1.2"}, "X-Token": {"x"}}
	if w := serveWithHeaders(router, sep, "/", ok); w.Code != 299 {
		t.Fatalf("valid request refused: %d", w.Code)
	}
	for name, h := range map[string]map[string][]string{
		"regex not full match": {"X-Client": {"app/1.2-evil"}, "X-Token": {"x"}},
		"prefix only":          {"X-Client": {"xapp/1.2"}, "X-Token": {"x"}},
		"second rule missing":  {"X-Client": {"app/1.2"}},
		"empty present":        {"X-Client": {"app/1.2"}, "X-Token": {""}},
		"newline injection":    {"X-Client": {"app/1.2\nx"}, "X-Token": {"x"}},
	} {
		if w := serveWithHeaders(router, sep, "/", h); w.Code != 403 {
			t.Errorf("%s: got %d", name, w.Code)
		}
	}
}

func TestHeaderRuleCatastrophicRegexIsBounded(t *testing.T) {
	_, sep := withHeaderRules(t, &HeaderRule{Name: "X-A", Match: "regex", Values: []string{`(a+)+$`, `(a|aa)+$`, `(.*a){20}`}})
	rule := sep.headerRules[0]
	h := http.Header{"X-A": {strings.Repeat("a", 4000) + "!"}}
	// RE2 is linear: this must return immediately (the test timeout would catch a backtracking engine)
	for i := 0; i < 50; i++ {
		rule.satisfied(h)
	}
	// backtracking-only constructs and absurd sizes are rejected at config time
	for _, p := range []string{`(?=x)`, `(a)\1`, strings.Repeat("a", 201), `a{1001}`, `(`} {
		if err := ValidateHeaderRules([]*HeaderRule{{Name: "X-A", Match: "regex", Values: []string{p}}}); err == nil {
			t.Errorf("pattern %q accepted", p)
		}
	}
}

func TestHeaderRulePathScopeAndBypassAttempts(t *testing.T) {
	router, sep := withHeaderRules(t, &HeaderRule{Name: "X-Key", Values: []string{"k"}, PathPrefix: "/admin"})
	for _, p := range []string{"/", "/public", "/administrator", "/adminx/y"} {
		if w := serveWithHeaders(router, sep, p, nil); w.Code != 299 {
			t.Errorf("%s must be outside the scope, got %d", p, w.Code)
		}
	}
	for _, p := range []string{"/admin", "/admin/", "/admin/x", "/%61dmin/x", "/./admin", "//admin", "/foo/../admin", "/admin;x=1/y", "/%2e/admin", "/ADMIN"} {
		code := serveWithHeaders(router, sep, p, nil).Code
		if p == "/ADMIN" {
			continue //case sensitive match like path rules: an upstream that folds case is configured with a case insensitive path rule
		}
		if code != 403 {
			t.Errorf("path %q bypassed the header rule (%d)", p, code)
		}
	}
	if w := serveWithHeaders(router, sep, "/admin", map[string][]string{"X-Key": {"k"}}); w.Code != 299 {
		t.Fatal("valid key refused")
	}
}

func TestHeaderRuleActionsAndSecretNotLogged(t *testing.T) {
	router, sep := withHeaderRules(t, &HeaderRule{Name: "X-Key", Values: []string{"super-secret"}, Action: "notfound"})
	w := serveWithHeaders(router, sep, "/", map[string][]string{"X-Key": {"guess-attempt-123"}})
	if w.Code != 404 {
		t.Fatalf("notfound action: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "guess-attempt-123") || strings.Contains(w.Body.String(), "super-secret") {
		t.Fatal("secret or presented value reflected in the response")
	}
	sep.HeaderRules[0].Action = "drop"
	sep.initHeaderRules()
	srv, cli := net.Pipe()
	defer cli.Close()
	hw := &hijackRecorder{httptest.NewRecorder(), srv}
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r.RemoteAddr = "198.51.100.1:1"
	router.handleNonTLSRequest(hw, r, sep)
	buf := make([]byte, 1)
	if n, err := cli.Read(buf); n != 0 || err == nil || hw.Body.Len() != 0 {
		t.Fatal("drop action must close without a response")
	}
}

func TestHeaderRuleValidationAndFailClosed(t *testing.T) {
	bad := []*HeaderRule{
		{Name: "", Values: []string{"a"}},
		{Name: "Bad Name", Values: []string{"a"}},
		{Name: "X:Y", Values: []string{"a"}},
		{Name: "Host", Values: []string{"a"}},
		{Name: "X-A"},                       //equals without values
		{Name: "X-A", Values: []string{""}}, //empty secret would match absent headers' empty value
		{Name: "X-A", Values: []string{strings.Repeat("x", 513)}},
		{Name: "X-A", Match: "bogus", Values: []string{"a"}},
		{Name: "X-A", Values: []string{"a"}, Action: "bogus"},
		{Name: "X-A", Values: []string{"a"}, PathPrefix: "no-slash"},
	}
	for i, r := range bad {
		if err := ValidateHeaderRules([]*HeaderRule{r}); err == nil {
			t.Errorf("bad rule %d accepted", i)
		}
	}
	// an invalid stored config refuses requests instead of silently opening the endpoint
	router, sep, _ := newNonTLSTestRouter(t)
	sep.HeaderRules = []*HeaderRule{{Name: "X-A"}}
	sep.initHeaderRules()
	if w := serveWithHeaders(router, sep, "/", map[string][]string{"X-A": {"anything"}}); w.Code != 503 {
		t.Fatalf("misconfigured rules must fail closed, got %d", w.Code)
	}
}

func TestHeaderRuleDuplicatedHeaderValuesAreCapped(t *testing.T) {
	router, sep := withHeaderRules(t, &HeaderRule{Name: "X-Key", Values: []string{"k"}})
	many := make([]string, 0, 50)
	for i := 0; i < 49; i++ {
		many = append(many, "junk")
	}
	many = append(many, "k") //the real value hidden beyond the cap is not accepted (bounded work)
	if w := serveWithHeaders(router, sep, "/", map[string][]string{"X-Key": many}); w.Code != 403 {
		t.Fatalf("got %d", w.Code)
	}
}
