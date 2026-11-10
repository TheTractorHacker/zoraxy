package ruleset

import (
	"crypto/tls"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mkReq(method, target string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		if strings.EqualFold(k, "host") {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	return r
}

func testLists() map[string]*List {
	office := &List{Name: "office", Type: ListIP, Items: []string{"203.0.113.0/24", "2001:db8::/32", "198.51.100.7"}}
	bad := &List{Name: "badcountries", Type: ListCountry, Items: []string{"CN", "RU"}}
	hosts := &List{Name: "hosts", Type: ListString, Items: []string{"a.example.com", "b.example.com"}}
	for _, l := range []*List{office, bad, hosts} {
		if err := l.Validate(); err != nil {
			panic(err)
		}
	}
	return map[string]*List{"office": office, "badcountries": bad, "hosts": hosts}
}

func compile(t *testing.T, src string) *Expr {
	t.Helper()
	x, err := Parse(src)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	if err := x.Link(testLists()); err != nil {
		t.Fatalf("link %q: %v", src, err)
	}
	return x
}

func evalOn(t *testing.T, src string, r *http.Request, ip, country string) bool {
	t.Helper()
	x := compile(t, src)
	env := &Env{R: r, ClientIP: ip, Country: func(string) string { return country }}
	b := &budget{left: RuleBudget}
	got := evalExpr(x.Root, env, b, nil)
	if b.exceeded {
		t.Fatalf("budget exceeded for %q", src)
	}
	return got
}

func TestFieldsAndOperators(t *testing.T) {
	r := mkReq("POST", "http://App.Example.com:8080/Admin/./x/../users;jsessionid=1?id=42&q=a%20b&dup=1&dup=2", map[string]string{
		"User-Agent":   "Mozilla/5.0 SQLMap",
		"Referer":      "https://other.example/",
		"Content-Type": "Application/JSON; charset=utf-8",
		"X-Api-Key":    "k-123",
		"Cookie":       "session=abc; Theme=dark",
		"X-Multi":      "one",
	})
	r.Header.Add("X-Multi", "two")
	r.ContentLength = 5000
	cases := []struct {
		src  string
		want bool
	}{
		{`http.host == "app.example.com"`, true}, // lower case, port removed
		{`http.host == "App.Example.com"`, false},
		{`http.path == "/Admin/users"`, true}, // normalised: dot segments and ;params resolved, case kept
		{`http.path starts_with "/admin"`, false},
		{`lower(http.path) starts_with "/admin"`, true},
		{`http.raw_path contains ";jsessionid"`, true},
		{`http.query contains "id=42"`, true},
		{`http.method == "POST"`, true},
		{`http.method in ["GET", "HEAD"]`, false},
		{`http.scheme == "http"`, true},
		{`http.version == "HTTP/1.1"`, true},
		{`lower(http.user_agent) contains "sqlmap"`, true},
		{`http.user_agent contains "sqlmap"`, false},
		{`http.referer starts_with "https://other"`, true},
		{`lower(http.content_type) starts_with "application/json"`, true},
		{`http.header["X-API-KEY"] == "k-123"`, true}, // header names are case-insensitive
		{`http.header["x-multi"] == "one, two"`, true},
		{`http.header["x-missing"] exists`, false},
		{`http.header["x-missing"] not exists`, true},
		{`http.header["x-missing"] != "x"`, true},
		{`http.header["x-api-key"] exists`, true},
		{`http.cookie["session"] == "abc"`, true},
		{`http.cookie["Session"] exists`, false}, // cookie names are case-sensitive
		{`http.cookie["Theme"] == "dark"`, true},
		{`http.query_arg["id"] matches "^[0-9]+$"`, true},
		{`http.query_arg["q"] == "a b"`, true},
		{`http.query_arg["dup"] == "1"`, true},
		{`http.query_arg["nope"] exists`, false},
		{`ip.src == "203.0.113.9"`, true},
		{`ip.src in $office`, true},
		{`ip.src in ["203.0.113.0/24"]`, true},
		{`ip.src not in ["10.0.0.0/8"]`, true},
		{`ip.country == "DE"`, true},
		{`ip.country in $badcountries`, false},
		{`ip.country not in ["US", "CA"]`, true},
		{`ip.is_private`, false},
		{`ip.is_private == false`, true},
		{`not ip.is_private`, true},
		{`req.size > 1000`, true},
		{`req.size >= 5000 and req.size <= 5000`, true},
		{`req.size < 5000`, false},
		{`req.size != 0`, true},
		{`req.size eq 5000`, true},
		{`tls.sni == ""`, true},
		{`tls.version == ""`, true},
		{`http.path matches "^/Admin/(users|groups)$"`, true},
		{`http.path not matches "^/api"`, true},
		{`http.path ends_with "users"`, true},
		{`http.path not ends_with "users"`, false},
		{`http.path not contains "zzz"`, true},
		{`http.path not starts_with "/Admin"`, false},
		{`http.host in $hosts`, false},
		{`http.query_arg["id"] > 5`, false}, // type error caught below, so unused
	}
	for _, c := range cases {
		if strings.Contains(c.src, `["id"] > 5`) {
			if _, err := Parse(c.src); err == nil {
				t.Errorf("%s: expected a type error", c.src)
			}
			continue
		}
		if got := evalOn(t, c.src, r, "203.0.113.9", "DE"); got != c.want {
			t.Errorf("%s = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestPrivateAndIPv6(t *testing.T) {
	r := mkReq("GET", "/", nil)
	for ip, want := range map[string]bool{"10.1.2.3": true, "127.0.0.1": true, "192.168.0.1": true, "169.254.1.1": true, "100.64.0.1": true, "8.8.8.8": false, "::1": true, "fd00::1": true, "2001:db8::1": false, "::ffff:10.0.0.1": true, "garbage": false} {
		if got := evalOn(t, `ip.is_private`, r, ip, ""); got != want {
			t.Errorf("is_private(%s) = %v", ip, got)
		}
	}
	if !evalOn(t, `ip.src in $office`, r, "2001:db8::5", "") || evalOn(t, `ip.src in $office`, r, "2001:db9::5", "") {
		t.Error("ipv6 list matching")
	}
	if !evalOn(t, `ip.src in $office`, r, "198.51.100.7", "") || evalOn(t, `ip.src in $office`, r, "198.51.100.8", "") {
		t.Error("single address list entry")
	}
	if !evalOn(t, `ip.src in $office`, r, "::ffff:203.0.113.1", "") {
		t.Error("v4-mapped address should match the v4 network")
	}
	if !evalOn(t, `ip.src in $office`, r, "203.0.113.1:5555", "") {
		t.Error("host:port client address")
	}
	// unknown country is XX
	if !evalOn(t, `ip.country == "XX"`, r, "10.0.0.1", "") {
		t.Error("unknown country should be XX")
	}
}

func TestTLSFields(t *testing.T) {
	r := mkReq("GET", "https://x.example/", nil)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, ServerName: "Sni.Example"}
	if !evalOn(t, `tls.version == "TLSv1.2" and tls.sni == "sni.example" and http.scheme == "https"`, r, "1.1.1.1", "") {
		t.Error("tls fields")
	}
}

func TestPathNormalisationDefeatsTricks(t *testing.T) {
	for _, target := range []string{"/admin", "//admin", "/./admin", "/x/../admin", "/admin/", "/admin;x=1", "/admin%00.png", "/%61dmin", "/x/%2e%2e/admin", "/admin/."} {
		r := httptest.NewRequest("GET", target, nil)
		if !evalOn(t, `http.path == "/admin"`, r, "1.1.1.1", "") {
			t.Errorf("%q should normalise to /admin, got %q", target, NormalizePath(r))
		}
	}
	// backslash read as slash
	r := httptest.NewRequest("GET", "/", nil)
	r.URL.Path = `\admin\users`
	if NormalizePath(r) != "/admin/users" {
		t.Errorf("backslash: %q", NormalizePath(r))
	}
}

func TestParseErrorsHavePositions(t *testing.T) {
	cases := map[string]string{
		`http.path starts_with`:                 "expected a value",
		`http.path = "x"`:                       `use "=="`,
		`http.nope == "x"`:                      "unknown field",
		`ip.asn == 13335`:                       "no ASN data",
		`http.header == "x"`:                    "needs a name",
		`http.path["x"] == "a"`:                 "does not take a name",
		`http.path == 5`:                        "needs a quoted string",
		`req.size == "5"`:                       "needs a number",
		`req.size contains "5"`:                 "cannot be used",
		`ip.country == "us"`:                    "upper case",
		`ip.src == "nonsense"`:                  "valid IP",
		`http.path matches "("`:                 "invalid regular expression",
		`http.path matches "(?=a)"`:             "invalid regular expression",
		`http.path matches "\\1(a)"`:            "invalid regular expression",
		`http.path == "a" &&  http.host == "b"`: "write \"and\"",
		`http.path == "a" and`:                  "expected a field name",
		`(http.path == "a"`:                     `expected ")"`,
		`http.path == "a")`:                     "unexpected",
		`http.path == "unterminated`:            "unterminated",
		`http.path == "a" http.host == "b"`:     "unexpected",
		`lower(req.size) > 1`:                   "text fields",
		`lower http.path == "a"`:                "is a function",
		`foo(http.path) == "a"`:                 "expected an operator",
		`http.path in "a"`:                      "list",
		`http.path in []`:                       "at least one",
		`http.path in $Bad`:                     "invalid list name",
		`http.path == http.host`:                "cannot be compared with each other",
		`ip.is_private contains true`:           "cannot be used",
		`http.path == "\q"`:                     "unknown escape",
		`http.path == "\x80"`:                   "00-7f",
		"http.path == \"a\u200bb\"":             "invisible",
		"http.path\u00a0== \"a\"":               "unexpected character U+00A0",
		"http.path == \u201ca\u201d":            "unexpected character",
		"http.path == \"a\x01\"":                "invisible or control",
		`http.header["bad name"] == "x"`:        "not a valid header name",
		`http.path`:                             "expected an operator",
		``:                                      "empty",
		`http.cookie["a"] exists true`:          "unexpected",
	}
	for src, want := range cases {
		_, err := Parse(src)
		if err == nil {
			t.Errorf("%q: expected an error containing %q", src, want)
			continue
		}
		if !strings.Contains(err.Msg, want) {
			t.Errorf("%q: error %q does not contain %q", src, err.Msg, want)
		}
		if err.Pos < 0 || err.End < err.Pos || err.End > len(src)+1 {
			t.Errorf("%q: bad position %d-%d", src, err.Pos, err.End)
		}
	}
	// the position points at the problem
	_, err := Parse(`http.path == "a" and http.nope == "b"`)
	if err == nil || err.Pos != 21 {
		t.Errorf("position: %+v", err)
	}
}

func TestCanonicalText(t *testing.T) {
	cases := map[string]string{
		`http.path   starts_with   "/admin"  AND`:                    "", // uppercase AND is not a keyword
		`http.path starts_with "/admin" and ip.country != "US"`:      `http.path starts_with "/admin" and ip.country != "US"`,
		`http.path eq "/a" or http.path ne "/b" and req.size ge 1`:   `http.path == "/a" or http.path != "/b" and req.size >= 1`,
		`(http.path == "/a" or http.path == "/b") and ip.is_private`: `(http.path == "/a" or http.path == "/b") and ip.is_private == true`,
		`not (http.path == "/a")`:                                    `not (http.path == "/a")`,
		`not http.path == "/a"`:                                      `not (http.path == "/a")`,
		`((http.path == "/a"))`:                                      `http.path == "/a"`,
		`(http.path == "/a" and http.host == "b") and ip.is_private`: `(http.path == "/a" and http.host == "b") and ip.is_private == true`,
		`http.path == "/a" and (http.host == "b" and ip.is_private)`: `http.path == "/a" and (http.host == "b" and ip.is_private == true)`,
		`http.header['x'] exists`:                                    "",
		`http.header["x"]exists`:                                     `http.header["x"] exists`,
		`http.cookie["a"] not  exists`:                               `http.cookie["a"] not exists`,
		`lower( http.path ) not contains "x"`:                        `lower(http.path) not contains "x"`,
		`http.path in [ "a" , "b" ]`:                                 `http.path in ["a", "b"]`,
		`ip.src not in $office`:                                      `ip.src not in $office`,
		"http.path == \"tab\\there\\n\\x01\\u200b\"":                 `http.path == "tab\there\n\x01\u200b"`,
	}
	for src, want := range cases {
		x, err := Parse(src)
		if want == "" {
			if err == nil {
				t.Errorf("%q should not parse", src)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", src, err)
			continue
		}
		if got := x.Text(); got != want {
			t.Errorf("%q\n  got  %s\n  want %s", src, got, want)
		}
		// the canonical text is a fixed point
		y, err := Parse(x.Text())
		if err != nil || y.Text() != x.Text() {
			t.Errorf("%q: not a fixed point: %v", src, err)
		}
	}
}

func TestTreeRoundTrip(t *testing.T) {
	src := `(http.path starts_with "/admin" or lower(http.header["x-test"]) in ["a", "b"]) and not (ip.country in $badcountries) and req.size > 10 and ip.src not in $office and http.cookie["s"] not exists and ip.is_private == false`
	x := compile(t, src)
	js, err := json.Marshal(x.Tree())
	if err != nil {
		t.Fatal(err)
	}
	tn, err := ParseTreeJSON(js)
	if err != nil {
		t.Fatal(err)
	}
	y, perr := FromTree(tn)
	if perr != nil {
		t.Fatal(perr)
	}
	if y.Text() != x.Text() {
		t.Errorf("tree round trip\n got %s\nwant %s", y.Text(), x.Text())
	}
	js2, _ := json.Marshal(y.Tree())
	if string(js) != string(js2) {
		t.Error("tree is not a fixed point")
	}
}

func TestTreeErrors(t *testing.T) {
	cases := map[string]string{
		`{"type":"and","children":[]}`: "empty",
		`{"type":"not","children":[{"type":"cond","field":"ip.is_private","op":"eq","value":true},{"type":"cond","field":"ip.is_private","op":"eq","value":true}]}`: "exactly one",
		`{"type":"xor","children":[]}`:                                                     "unknown node type",
		`{"type":"cond","field":"http.path","op":"matches","value":"("}`:                   "regular expression",
		`{"type":"cond","field":"http.path","op":"zzz","value":"a"}`:                       "unknown operator",
		`{"type":"cond","field":"http.path","op":"eq","value":1.5}`:                        "whole",
		`{"type":"cond","field":"http.path","op":"eq","value":{"x":1}}`:                    "unsupported",
		`{"type":"cond","field":"http.path","op":"eq","value":"a","transform":"upper"}`:    "transform",
		`{"type":"and","children":[{"type":"cond","field":"nope","op":"eq","value":"a"}]}`: "children[0]",
		`{"type":"cond","field":"http.path","op":"in","value":{"list":"Bad Name"}}`:        "invalid list name",
	}
	for js, want := range cases {
		tn, err := ParseTreeJSON([]byte(js))
		if err != nil {
			t.Errorf("%s: decode: %v", js, err)
			continue
		}
		_, perr := FromTree(tn)
		if perr == nil || !strings.Contains(perr.Error(), want) {
			t.Errorf("%s: got %v, want %q", js, perr, want)
		}
	}
	if _, err := ParseTreeJSON([]byte(`{"type":"cond","bogus":1}`)); err == nil {
		t.Error("unknown members must be rejected")
	}
	// singleton groups collapse
	tn, _ := ParseTreeJSON([]byte(`{"type":"and","children":[{"type":"or","children":[{"field":"ip.is_private","op":"eq","value":true}]}]}`))
	x, perr := FromTree(tn)
	if perr != nil || x.Text() != "ip.is_private == true" {
		t.Errorf("collapse: %v %v", perr, x)
	}
}

// randomExpr builds a random valid tree
func randomTree(rng *rand.Rand, depth int) *TreeNode {
	if depth <= 0 || rng.Intn(3) == 0 {
		return randomCond(rng)
	}
	switch rng.Intn(3) {
	case 0, 1:
		typ := "and"
		if rng.Intn(2) == 0 {
			typ = "or"
		}
		n := 2 + rng.Intn(3)
		t := &TreeNode{Type: typ}
		for i := 0; i < n; i++ {
			t.Children = append(t.Children, randomTree(rng, depth-1))
		}
		return t
	}
	return &TreeNode{Type: "not", Children: []*TreeNode{randomTree(rng, depth-1)}}
}

var nasty = []string{"", "a", "/admin", `quo"te`, `back\slash`, "tab\t", "nl\n", "caf\u00e9", "\u202eevil", "zero\u200bwidth", "\x00nul", "emoji\U0001F600", "$dollar", "[x]", "and", "(", "\u00a0"}

func randomCond(rng *rand.Rand) *TreeNode {
	switch rng.Intn(8) {
	case 0:
		return &TreeNode{Type: "cond", Field: "req.size", Op: []string{"eq", "ne", "lt", "gt", "le", "ge"}[rng.Intn(6)], Value: int64(rng.Intn(2000) - 100)}
	case 1:
		return &TreeNode{Type: "cond", Field: "ip.is_private", Op: []string{"eq", "ne"}[rng.Intn(2)], Value: rng.Intn(2) == 0}
	case 2:
		return &TreeNode{Type: "cond", Field: "ip.src", Op: []string{"in", "not_in"}[rng.Intn(2)], Value: []string{"10.0.0.0/8", "192.0.2.1", "2001:db8::/32"}[:1+rng.Intn(3)]}
	case 3:
		return &TreeNode{Type: "cond", Field: "ip.country", Op: "in", Value: []string{"US", "DE"}}
	case 4:
		return &TreeNode{Type: "cond", Field: "http.header", Key: []string{"x-a", "User-Agent", "X-Long-Name"}[rng.Intn(3)], Op: []string{"exists", "not_exists"}[rng.Intn(2)]}
	case 5:
		return &TreeNode{Type: "cond", Field: "http.path", Op: "matches", Value: []string{"^/a+$", "(?i)admin|root", `\d{3}`}[rng.Intn(3)]}
	case 6:
		return &TreeNode{Type: "cond", Field: "http.host", Op: "in", Value: map[string]string{"list": "hosts"}}
	}
	fields := []string{"http.path", "http.query", "http.user_agent", "http.referer", "http.method"}
	ops := []string{"eq", "ne", "contains", "not_contains", "starts_with", "not_starts_with", "ends_with", "not_ends_with"}
	t := &TreeNode{Type: "cond", Field: fields[rng.Intn(len(fields))], Op: ops[rng.Intn(len(ops))], Value: nasty[rng.Intn(len(nasty))]}
	if rng.Intn(3) == 0 {
		t.Transform = "lower"
	}
	return t
}

func TestRoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	lists := testLists()
	for i := 0; i < 3000; i++ {
		tr := randomTree(rng, 4)
		x, perr := FromTree(tr)
		if perr != nil {
			t.Fatalf("random tree rejected: %v\n%+v", perr, tr)
		}
		x.Link(lists)
		text := x.Text()
		y, err := Parse(text)
		if err != nil {
			t.Fatalf("canonical text does not parse: %v\n%s", err, text)
		}
		if y.Text() != text {
			t.Fatalf("text not stable:\n%s\n%s", text, y.Text())
		}
		a, _ := json.Marshal(x.Tree())
		b, _ := json.Marshal(y.Tree())
		if string(a) != string(b) {
			t.Fatalf("tree differs after text round trip:\n%s\n%s\n%s", text, a, b)
		}
		// and back through JSON decoding
		tn, jerr := ParseTreeJSON(a)
		if jerr != nil {
			t.Fatal(jerr)
		}
		z, perr := FromTree(tn)
		if perr != nil || z.Text() != text {
			t.Fatalf("json round trip: %v", perr)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{`http.path starts_with "/admin" and ip.country != "US"`, `not (a)`, `http.header["x"] exists`, `ip.src in $office or req.size > 5`, "\"\\u202e\"", `((((`, `http.path matches "(a+)+$"`} {
		f.Add(s)
	}
	lists := testLists()
	f.Fuzz(func(t *testing.T, src string) {
		x, err := Parse(src)
		if err != nil {
			return
		}
		text := x.Text()
		y, err := Parse(text)
		if err != nil {
			t.Fatalf("canonical text of %q does not parse: %v\n%s", src, err, text)
		}
		if y.Text() != text {
			t.Fatalf("not stable: %q -> %q -> %q", src, text, y.Text())
		}
		if x.Link(lists) == nil {
			r := httptest.NewRequest("GET", "/x?a=b", nil)
			env := &Env{R: r, ClientIP: "1.2.3.4"}
			evalExpr(x.Root, env, &budget{left: RuleBudget}, nil)
		}
	})
}

func TestAdversarialExpressions(t *testing.T) {
	// too long
	if _, err := Parse(`http.path == "` + strings.Repeat("a", MaxExprLen) + `"`); err == nil || !strings.Contains(err.Msg, "too long") {
		t.Errorf("long expression: %v", err)
	}
	// very long literal within the length limit
	if _, err := Parse(`http.path == "` + strings.Repeat("a", MaxLiteralLen+10) + `"`); err == nil {
		t.Error("literal over the limit")
	}
	// deep nesting
	if _, err := Parse(strings.Repeat("(", 500) + `ip.is_private` + strings.Repeat(")", 500)); err == nil {
		t.Error("deep parentheses")
	}
	if _, err := Parse(strings.Repeat("not ", 400) + `ip.is_private`); err == nil {
		t.Error("deep not chain")
	}
	// many nodes
	many := strings.TrimSuffix(strings.Repeat(`req.size>1 and `, 130), " and ")
	if _, err := Parse(many); err == nil || !strings.Contains(err.Msg, "complex") {
		t.Errorf("node count: %v", err)
	}
	// regex limits
	if _, err := Parse(`http.path matches "` + strings.Repeat("a", MaxRegexLen+1) + `"`); err == nil {
		t.Error("long regex")
	}
	if _, err := Parse(`http.path matches "(a{1000}){1000}"`); err == nil {
		t.Error("exploding regex repeat")
	}
	if _, err := Parse(`http.path matches "((((a{100}){100}){100}){100})"`); err == nil {
		t.Error("exploding nested repeat")
	}
	if _, err := Parse(`http.path matches "[a-z]{1000}[a-z]{1000}"`); err == nil {
		t.Error("two big repeats must exceed the compiled size limit")
	}
	// inline list limit
	items := make([]string, MaxInlineList+1)
	for i := range items {
		items[i] = `"a"`
	}
	if _, err := Parse(`http.path in [` + strings.Join(items, ",") + `]`); err == nil {
		t.Error("inline list limit")
	}
	// catastrophic regex is linear (RE2): 20k input of a classic ReDoS pattern completes at once
	x := compile(t, `http.query matches "^(a+)+$"`)
	r := httptest.NewRequest("GET", "/?"+strings.Repeat("a", 20000)+"!", nil)
	start := time.Now()
	if x.Eval(&Env{R: r, ClientIP: "1.1.1.1"}) {
		t.Error("should not match")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("regex took %v", d)
	}
	if len(x.Warnings) == 0 || !strings.Contains(x.Warnings[0], "nested repetition") {
		t.Errorf("expected an expensive-regex warning, got %v", x.Warnings)
	}
	// unicode tricks: bidi override, zero width, homoglyph keyword, NBSP, BOM
	for _, s := range []string{"\u202e", "\u200b", "\ufeff", "\u00a0", "\u2028", "\u2066", "\u0000"} {
		if _, err := Parse(`http.path == "a` + s + `b"`); err == nil {
			t.Errorf("raw %U inside a string must be rejected", []rune(s)[0])
		}
		if _, err := Parse(`http.path ` + s + `== "ab"`); err == nil {
			t.Errorf("raw %U outside a string must be rejected", []rune(s)[0])
		}
	}
	if _, err := Parse("http.path == \"caf\u00e9\""); err != nil {
		t.Errorf("plain non-ASCII letters are fine in strings: %v", err)
	}
	if _, err := Parse(`http.path == "\u202e"`); err != nil {
		t.Errorf("escaped bidi is allowed: %v", err)
	}
	if _, err := Parse(`http.pаth == "a"`); err == nil { // Cyrillic a
		t.Error("homoglyph field name")
	}
	if _, err := Parse("http.path == \"\xff\""); err == nil {
		t.Error("invalid UTF-8")
	}
	// the printer escapes what the parser refuses to read raw
	y, _ := Parse(`http.path == "\u202e\x00\u200b"`)
	if strings.ContainsAny(y.Text(), "\u202e\x00\u200b") {
		t.Errorf("printer leaked raw invisible characters: %q", y.Text())
	}
	// the only function is lower()
	for _, s := range []string{`upper(http.path) == "A"`, `len(http.path) > 1`, `system("id")`, `http.path.__proto__ == "x"`, `http.path == lower("a")`, `[1,2][0] == 1`, `http.path == "a" ? 1 : 2`, `http.path == 1+1`, `http.path == "a" +`, "a;b"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%q must not parse", s)
		}
	}
}

func TestBudgetEnforced(t *testing.T) {
	x := compile(t, `http.path matches "^/a" and http.path matches "b" and http.path matches "c"`)
	r := httptest.NewRequest("GET", "/"+strings.Repeat("a", 5000), nil)
	env := &Env{R: r, ClientIP: "1.1.1.1"}
	b := &budget{left: 5}
	evalExpr(x.Root, env, b, nil)
	if !b.exceeded {
		t.Error("a tiny budget must be exceeded")
	}
	if x.Eval(env) {
		// full budget: the rule runs (no match because of "c"? path has only a)
		t.Error("unexpected match")
	}

	// engine: a rule that exhausts the per rule budget does not match and is counted as an error
	e := NewMemory()
	e.ruleBudget = 3
	if _, err := e.Create("", RuleInput{Name: "heavy", Expression: `http.path matches "a" and http.path matches "b" and http.path matches "c"`, Action: Action{Type: ActBlock}, DryRun: boolp(false)}, -1); err != nil {
		t.Fatal(err)
	}
	run := e.Begin(&Env{R: r, ClientIP: "1.1.1.1"}, "")
	if run == nil || run.Next() != nil {
		t.Fatal("budget exhausted: no match expected")
	}
	if got := e.Rules("")[0].Stats.Errors; got != 1 {
		t.Errorf("error counter = %d", got)
	}
	// request budget stops later rules
	e2 := NewMemory()
	e2.reqBudget = 6
	for i := 0; i < 5; i++ {
		e2.Create("", RuleInput{Name: "r", Expression: `http.path starts_with "/zzz" or http.path starts_with "/yyy"`, Action: Action{Type: ActLog}, DryRun: boolp(false)}, -1)
	}
	run = e2.Begin(&Env{R: r, ClientIP: "1.1.1.1"}, "")
	run.Next()
	if !run.stopped {
		t.Error("the request budget should stop the walk")
	}
}

func boolp(b bool) *bool { return &b }

func TestWarnings(t *testing.T) {
	cases := map[string]string{
		`lower(http.path) == "/Admin"`:            "can never match",
		`http.method == "get"`:                    "upper case",
		`http.host == "Example.com"`:              "lower case",
		`http.scheme == "ftp"`:                    "never",
		`http.path starts_with "admin"`:           "always starts with /",
		`http.path == "/a/"`:                      "trailing slash",
		`http.path == "/a" and http.path == "/b"`: "cannot equal both",
		`http.path == "/a" and http.path != "/a"`: "both equal and not equal",
		`http.path contains ""`:                   "always true",
		`http.query matches "(a+)+"`:              "nested repetition",
		`http.path matches "admin"`:               "not anchored",
		`tls.version == "TLS1.3"`:                 "never",
		`req.size == 0`:                           "chunked",
	}
	for src, want := range cases {
		x, err := Parse(src)
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		found := false
		for _, w := range x.Warnings {
			found = found || strings.Contains(w, want)
		}
		if !found {
			t.Errorf("%s: warnings %v do not mention %q", src, x.Warnings, want)
		}
	}
	x, _ := Parse(`http.path starts_with "/admin" and ip.country != "US"`)
	if len(x.Warnings) != 0 {
		t.Errorf("clean expression has warnings: %v", x.Warnings)
	}
	if strings.Join(x.Fields, ",") != "http.path,ip.country" {
		t.Errorf("fields: %v", x.Fields)
	}
}

func TestLinkErrors(t *testing.T) {
	for src, want := range map[string]string{
		`ip.src in $nothing`:         "unknown list",
		`ip.src in $hosts`:           "needs an ip list",
		`http.path in $office`:       "ip list",
		`http.path in $badcountries`: "only be used with ip.country",
	} {
		x, err := Parse(src)
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		if err := x.Link(testLists()); err == nil || !strings.Contains(err.Msg, want) {
			t.Errorf("%s: %v, want %q", src, err, want)
		}
	}
}
