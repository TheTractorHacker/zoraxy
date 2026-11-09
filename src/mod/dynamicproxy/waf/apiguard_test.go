package waf

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// guardFor builds a guard in the given mode with the limits (and optional allow-list)
func guardFor(t *testing.T, mode string, lim *APILimits, allow ...APIAllowRule) (*Guard, *Manager) {
	t.Helper()
	m := NewManager()
	g, err := m.NewGuard(&APIConfig{Mode: mode, Limits: lim, AllowList: allow})
	if err != nil || g == nil {
		t.Fatalf("NewGuard: %v %v", g, err)
	}
	return g, m
}

type result struct {
	blocked bool
	status  int
	code    string
	body    []byte // what the request body still yields afterwards
}

func run(t *testing.T, g *Guard, m *Manager, req *http.Request) result {
	t.Helper()
	rec := httptest.NewRecorder()
	before := len(m.RecentEvents(1000, ""))
	blocked := g.Inspect(rec, req, RequestInfo{Endpoint: "t", ClientIP: "192.0.2.1:1", Source: "test"})
	res := result{blocked: blocked}
	if blocked {
		res.status = rec.Code
	}
	if evs := m.RecentEvents(1000, ""); len(evs) > before {
		res.code = evs[0].Violation
		if evs[0].Kind != EventKindAPI {
			t.Errorf("event kind %q", evs[0].Kind)
		}
	}
	if req.Body != nil {
		res.body, _ = io.ReadAll(req.Body)
	}
	return res
}

func post(path, ct, body string) *http.Request {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	return r
}

func nested(open, close string, n int) string {
	return strings.Repeat(open, n) + strings.Repeat(close, n)
}

func TestGuardJSONLimits(t *testing.T) {
	obj := func(n int) string {
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"k%d":1`, i)
		}
		return b.String() + "}"
	}
	arr := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat("1,", n), ",") + "]" }
	str := func(n int) string { return `{"a":"` + strings.Repeat("x", n) + `"}` }
	cases := []struct {
		name string
		lim  APILimits
		body string
		code string
	}{
		{"depth at limit", APILimits{JSONMaxDepth: 5}, nested("[", "]", 5), ""},
		{"depth above limit", APILimits{JSONMaxDepth: 5}, nested("[", "]", 6), codeJSONDepth},
		{"default depth 20 ok", APILimits{}, nested("[", "]", 20), ""},
		{"default depth 21 rejected", APILimits{}, nested("[", "]", 21), codeJSONDepth},
		{"object depth", APILimits{JSONMaxDepth: 3}, `{"a":{"b":{"c":{"d":1}}}}`, codeJSONDepth},
		{"keys below", APILimits{JSONMaxKeys: 3}, obj(2), ""},
		{"keys at", APILimits{JSONMaxKeys: 3}, obj(3), ""},
		{"keys above", APILimits{JSONMaxKeys: 3}, obj(4), codeJSONKeys},
		{"array below", APILimits{JSONMaxArrayLen: 3}, arr(2), ""},
		{"array at", APILimits{JSONMaxArrayLen: 3}, arr(3), ""},
		{"array above", APILimits{JSONMaxArrayLen: 3}, arr(4), codeJSONArrayLen},
		{"string below", APILimits{JSONMaxStringLen: 10}, str(9), ""},
		{"string at", APILimits{JSONMaxStringLen: 10}, str(10), ""},
		{"string above", APILimits{JSONMaxStringLen: 10}, str(11), codeJSONStringLen},
		{"unlimited string", APILimits{JSONMaxStringLen: -1}, str(200000), ""},
		{"dup keys allowed by default", APILimits{}, `{"a":1,"a":2}`, ""},
		{"dup keys rejected", APILimits{RejectDuplicateKeys: true}, `{"a":1,"a":2}`, codeJSONDupKey},
		{"dup keys via escape", APILimits{RejectDuplicateKeys: true}, `{"a":1,"a":2}`, codeJSONDupKey},
		{"same key different objects", APILimits{RejectDuplicateKeys: true}, `{"a":{"x":1},"b":{"x":2}}`, ""},
		{"invalid utf8 allowed by default", APILimits{}, "{\"a\":\"\xff\xfe\"}", ""},
		{"invalid utf8 rejected", APILimits{RejectInvalidUTF8: true}, "{\"a\":\"\xff\xfe\"}", codeJSONUTF8},
		{"valid utf8 ok", APILimits{RejectInvalidUTF8: true}, `{"a":"héllo ☃"}`, ""},
		{"not json", APILimits{}, `hello world`, codeSyntax},
		{"truncated", APILimits{}, `{"a":[1,2`, codeSyntax},
		{"trailing garbage", APILimits{}, `{"a":1} x`, codeSyntax},
		{"bad escape", APILimits{}, `{"a":"\q"}`, codeSyntax},
		{"bad number", APILimits{}, `[01]`, codeSyntax},
		{"scalar ok", APILimits{}, `"x"`, ""},
		{"empty ok", APILimits{}, ``, ""},
		{"mismatch tolerated", APILimits{AllowContentTypeMismatch: true}, `hello`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lim := c.lim
			g, m := guardFor(t, APIModeBlock, &lim)
			res := run(t, g, m, post("/x", "application/json", c.body))
			if res.code != c.code {
				t.Fatalf("code %q want %q", res.code, c.code)
			}
			if (c.code != "") != res.blocked {
				t.Fatalf("blocked=%v for code %q", res.blocked, c.code)
			}
			if c.code != "" && res.status != 400 {
				t.Fatalf("status %d", res.status)
			}
			if c.code == "" && string(res.body) != c.body {
				t.Fatalf("body not replayed")
			}
		})
	}
}

func TestGuardJSONContentTypeVariants(t *testing.T) {
	g, m := guardFor(t, APIModeBlock, &APILimits{JSONMaxDepth: 2})
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "application/vnd.api+json", "APPLICATION/JSON", "application/merge-patch+json"} {
		if res := run(t, g, m, post("/x", ct, "[[[1]]]")); !res.blocked || res.code != codeJSONDepth {
			t.Errorf("%s: %+v", ct, res)
		}
	}
	// Other types are not parsed as JSON
	if res := run(t, g, m, post("/x", "text/plain", "[[[1]]]")); res.blocked {
		t.Error("text/plain parsed as JSON")
	}
}

func TestGuardHugeNestedPayloadBounded(t *testing.T) {
	payload := strings.Repeat("[", 10<<20) // 10 MiB of opening brackets
	g, m := guardFor(t, APIModeBlock, &APILimits{MaxBodyBytes: 16 << 20})
	var ms1, ms2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms1)
	start := time.Now()
	req := httptest.NewRequest("POST", "/x", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	req2 := req
	_ = req2
	if !g.Inspect(rec, req, RequestInfo{}) || rec.Code != 400 {
		t.Fatalf("not rejected: %d", rec.Code)
	}
	runtime.ReadMemStats(&ms2)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
	// The body buffer (10 MiB) is allowed; building a tree would cost far more
	if alloc := ms2.TotalAlloc - ms1.TotalAlloc; alloc > 40<<20 {
		t.Errorf("allocated %d MiB", alloc>>20)
	}
	// The scanner alone touches almost nothing
	allocs := testing.AllocsPerRun(3, func() { checkJSON([]byte(payload), DefaultAPILimits()) })
	if allocs > 5 {
		t.Errorf("checkJSON allocs %v", allocs)
	}
	// Deep nesting with the depth limit disabled hits the hard recursion cap, not the stack
	if v := checkJSON([]byte(payload), APILimits{JSONMaxDepth: 0}.withUnlimitedDepth()); v == nil || v.Code != codeJSONDepth {
		t.Errorf("unlimited depth: %v", v)
	}
	_ = m
}

func (l APILimits) withUnlimitedDepth() APILimits {
	e := (&l).Effective()
	e.JSONMaxDepth = 0
	return e
}

// endless yields bytes forever and counts how many were read
type endless struct{ n int64 }

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	e.n += int64(len(p))
	return len(p), nil
}

func TestGuardBodyReadIsBounded(t *testing.T) {
	src := &endless{}
	r := httptest.NewRequest("POST", "/x", io.NopCloser(src))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/octet-stream")
	g, m := guardFor(t, APIModeBlock, &APILimits{MaxBodyBytes: 4096})
	rec := httptest.NewRecorder()
	if !g.Inspect(rec, r, RequestInfo{}) || rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", rec.Code)
	}
	if src.n > 4096+8192 {
		t.Fatalf("read %d bytes from an endless body with a 4096 limit", src.n)
	}
	_ = m
}

func TestGuardBodySize(t *testing.T) {
	g, m := guardFor(t, APIModeBlock, &APILimits{MaxBodyBytes: 10})
	for _, c := range []struct {
		n    int
		want bool
	}{{9, false}, {10, false}, {11, true}} {
		res := run(t, g, m, post("/x", "text/plain", strings.Repeat("a", c.n)))
		if res.blocked != c.want || (c.want && res.status != 413) {
			t.Errorf("n=%d %+v", c.n, res)
		}
	}
	// chunked / unknown length
	r := post("/x", "text/plain", strings.Repeat("a", 11))
	r.ContentLength = -1
	if res := run(t, g, m, r); !res.blocked || res.status != 413 {
		t.Errorf("chunked %+v", res)
	}
	// log mode: nothing blocked and the whole body is replayed
	gl, ml := guardFor(t, APIModeLog, &APILimits{MaxBodyBytes: 10})
	r = post("/x", "text/plain", strings.Repeat("a", 5000))
	r.ContentLength = -1
	res := run(t, gl, ml, r)
	if res.blocked || res.code != codeBodySize || len(res.body) != 5000 {
		t.Errorf("log mode %+v len=%d", res, len(res.body))
	}
}

func TestGuardXML(t *testing.T) {
	xe := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	laughs := `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>`
	attrs := func(n int) string {
		var b strings.Builder
		b.WriteString("<a")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, ` a%d="1"`, i)
		}
		return b.String() + "/>"
	}
	cases := []struct {
		name string
		lim  APILimits
		body string
		code string
	}{
		{"plain", APILimits{}, `<?xml version="1.0" encoding="ISO-8859-1"?><a><b x="1">t</b></a>`, ""},
		{"xxe", APILimits{}, xe, codeXMLDoctype},
		{"billion laughs", APILimits{}, laughs, codeXMLDoctype},
		{"parameter entity", APILimits{}, `<!DOCTYPE a [<!ENTITY % p SYSTEM "http://x/e.dtd">%p;]><a/>`, codeXMLDoctype},
		{"doctype allowed, no entity", APILimits{AllowDoctype: true}, `<!DOCTYPE a><a/>`, ""},
		{"doctype allowed, entity still rejected", APILimits{AllowDoctype: true}, xe, codeXMLDoctype},
		{"lowercase entity decl", APILimits{AllowDoctype: true}, `<!DOCTYPE a [<!entity x "y">]><a/>`, codeXMLDoctype},
		{"depth at", APILimits{XMLMaxDepth: 3}, nested("<a>", "</a>", 3), ""},
		{"depth above", APILimits{XMLMaxDepth: 3}, nested("<a>", "</a>", 4), codeXMLDepth},
		{"elements at", APILimits{XMLMaxElements: 3}, `<a><b/><c/></a>`, ""},
		{"elements above", APILimits{XMLMaxElements: 3}, `<a><b/><c/><d/></a>`, codeXMLElements},
		{"attrs at", APILimits{XMLMaxAttrs: 3}, attrs(3), ""},
		{"attrs above", APILimits{XMLMaxAttrs: 3}, attrs(4), codeXMLAttrs},
		{"malformed", APILimits{}, `<a><b></a>`, codeSyntax},
		{"unclosed", APILimits{}, `<a><b>`, codeSyntax},
		{"unknown entity", APILimits{}, `<a>&nope;</a>`, codeSyntax},
		{"not xml", APILimits{}, `{"a":1}`, codeSyntax},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lim := c.lim
			g, m := guardFor(t, APIModeBlock, &lim)
			for _, ct := range []string{"application/xml", "text/xml; charset=utf-8", "application/soap+xml"} {
				res := run(t, g, m, post("/x", ct, c.body))
				if res.code != c.code || res.blocked != (c.code != "") {
					t.Fatalf("%s: %+v want %q", ct, res, c.code)
				}
			}
		})
	}
}

func TestGuardForms(t *testing.T) {
	fields := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("f%d=v", i)
		}
		return strings.Join(parts, "&")
	}
	g, m := guardFor(t, APIModeBlock, &APILimits{FormMaxFields: 3, QueryMaxParamLen: 20})
	form := "application/x-www-form-urlencoded"
	for _, c := range []struct {
		body string
		code string
	}{
		{fields(2), ""}, {fields(3), ""}, {fields(4), codeFormFields},
		{"a=" + strings.Repeat("x", 18), ""}, {"a=" + strings.Repeat("x", 19), codeQueryParamLen},
		{"&&&", ""},
	} {
		if res := run(t, g, m, post("/x", form, c.body)); res.code != c.code {
			t.Errorf("%q: %q want %q", c.body, res.code, c.code)
		}
	}

	mp := func(fieldsN, filesN int) (string, string) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		for i := 0; i < fieldsN; i++ {
			w.WriteField(fmt.Sprintf("f%d", i), "v")
		}
		for i := 0; i < filesN; i++ {
			fw, _ := w.CreateFormFile("file", fmt.Sprintf("f%d.txt", i))
			fw.Write([]byte("data"))
		}
		w.Close()
		return w.FormDataContentType(), buf.String()
	}
	g2, m2 := guardFor(t, APIModeBlock, &APILimits{MultipartMaxParts: 5, MultipartMaxFiles: 2, FormMaxFields: 4})
	for _, c := range []struct {
		fields, files int
		code          string
	}{
		{1, 1, ""}, {3, 2, ""}, {2, 3, codeMultipartFiles}, {4, 2, codeMultipartParts}, {5, 0, codeFormFields}, {0, 0, ""},
	} {
		ct, body := mp(c.fields, c.files)
		if res := run(t, g2, m2, post("/x", ct, body)); res.code != c.code {
			t.Errorf("fields=%d files=%d: %q want %q", c.fields, c.files, res.code, c.code)
		}
	}
	// malformed multipart / missing boundary = content type mismatch
	if res := run(t, g2, m2, post("/x", "multipart/form-data; boundary=xyz", "garbage")); res.code != codeSyntax {
		t.Errorf("garbage multipart: %q", res.code)
	}
	if res := run(t, g2, m2, post("/x", "multipart/form-data", "garbage")); res.code != codeSyntax {
		t.Errorf("no boundary: %q", res.code)
	}
}

func TestGuardURLQueryHeaders(t *testing.T) {
	g, m := guardFor(t, APIModeBlock, &APILimits{URLMaxLen: 50, QueryMaxParams: 3, QueryMaxParamLen: 10, HeaderMaxCount: 5, HeaderMaxSize: 40})
	get := func(target string) *http.Request { return httptest.NewRequest("GET", target, nil) }
	cases := []struct {
		name   string
		req    *http.Request
		code   string
		status int
	}{
		{"url ok", get("/" + strings.Repeat("a", 40)), "", 0},
		{"url too long", get("/" + strings.Repeat("a", 60)), codeURLLen, 414},
		{"params at", get("/?a=1&b=2&c=3"), "", 0},
		{"params above", get("/?a=1&b=2&c=3&d=4"), codeQueryParams, 400},
		{"param len at", get("/?a=12345678"), "", 0},
		{"param len above", get("/?a=123456789"), codeQueryParamLen, 400},
	}
	h5 := get("/")
	for i := 0; i < 6; i++ {
		h5.Header.Set(fmt.Sprintf("X-H%d", i), "v")
	}
	cases = append(cases, struct {
		name   string
		req    *http.Request
		code   string
		status int
	}{"header count above", h5, codeHeaderCount, 431})
	hs := get("/")
	hs.Header.Set("X-Big", strings.Repeat("v", 41))
	cases = append(cases, struct {
		name   string
		req    *http.Request
		code   string
		status int
	}{"header size above", hs, codeHeaderSize, 431})
	hs2 := get("/")
	hs2.Header.Set("X-Big", strings.Repeat("v", 30))
	cases = append(cases, struct {
		name   string
		req    *http.Request
		code   string
		status int
	}{"header size ok", hs2, "", 0})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := run(t, g, m, c.req)
			if res.code != c.code || res.status != c.status {
				t.Fatalf("%+v", res)
			}
		})
	}
}

func TestGuardAllowListPrefixBoundaries(t *testing.T) {
	g, m := guardFor(t, APIModeBlock, nil,
		APIAllowRule{Path: "/api", Methods: []string{"GET", "POST"}, ContentTypes: []string{"application/json"}},
		APIAllowRule{Path: "/api/admin", Methods: []string{"GET"}},
		APIAllowRule{Path: "/raw*", Methods: []string{"GET"}},
		APIAllowRule{Path: "/files/", Methods: []string{"GET"}},
	)
	req := func(method, path, ct, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		return r
	}
	cases := []struct {
		name string
		r    *http.Request
		code string
	}{
		{"exact prefix GET", req("GET", "/api", "", ""), ""},
		{"sub path POST json", req("POST", "/api/users", "application/json", `{}`), ""},
		{"sub path DELETE", req("DELETE", "/api/users", "", ""), codeAllowMethod},
		{"apix is not /api", req("DELETE", "/apix", "", ""), ""},
		{"api2 is not /api", req("DELETE", "/api2/x", "", ""), ""},
		{"content type not allowed", req("POST", "/api/users", "text/plain", "hi"), codeAllowContentType},
		{"content type with params", req("POST", "/api/users", "application/json; charset=utf-8", `{}`), ""},
		{"missing content type with body", req("POST", "/api/users", "", "hi"), codeAllowContentType},
		{"no body no content type check", req("GET", "/api/users", "", ""), ""},
		{"longest prefix wins", req("POST", "/api/admin/x", "application/json", `{}`), codeAllowMethod},
		{"admin boundary", req("POST", "/api/administrator", "application/json", `{}`), ""},
		{"star prefix matches raw", req("POST", "/rawdata", "", ""), codeAllowMethod},
		{"star prefix exact", req("POST", "/raw", "", ""), codeAllowMethod},
		{"trailing slash rule", req("POST", "/files/a", "", ""), codeAllowMethod},
		{"trailing slash rule needs slash", req("POST", "/files", "", ""), ""},
		{"case insensitive", req("DELETE", "/API/users", "", ""), codeAllowMethod},
		{"dot segments", req("DELETE", "/x/../api/users", "", ""), codeAllowMethod},
		{"double slash", req("DELETE", "//api/users", "", ""), codeAllowMethod},
		{"unrelated path", req("DELETE", "/other", "", ""), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := run(t, g, m, c.r)
			if res.code != c.code {
				t.Fatalf("code %q want %q", res.code, c.code)
			}
			if c.code == codeAllowMethod && res.status != 405 || c.code == codeAllowContentType && res.status != 415 {
				t.Fatalf("status %d", res.status)
			}
		})
	}
	// Allow header on 405
	rec := httptest.NewRecorder()
	g.Inspect(rec, req("DELETE", "/api/admin", "", ""), RequestInfo{})
	if rec.Header().Get("Allow") != "GET" {
		t.Errorf("Allow = %q", rec.Header().Get("Allow"))
	}
}

func TestGuardContentTypeMatchesBody(t *testing.T) {
	g, m := guardFor(t, APIModeBlock, nil)
	for _, c := range []struct{ ct, body string }{
		{"application/json", "<xml/>"}, {"application/xml", `{"a":1}`}, {"multipart/form-data; boundary=b", "x=y"},
	} {
		if res := run(t, g, m, post("/x", c.ct, c.body)); res.code != codeSyntax || !res.blocked {
			t.Errorf("%s: %+v", c.ct, res)
		}
	}
	// Unknown / missing content types are not judged
	if res := run(t, g, m, post("/x", "", "<xml/>")); res.blocked {
		t.Error("no content type")
	}
	if res := run(t, g, m, post("/x", "application/octet-stream", "<xml/>")); res.blocked {
		t.Error("octet-stream")
	}
}

func TestGuardLogModeDoesNotBlock(t *testing.T) {
	g, m := guardFor(t, APIModeLog, &APILimits{JSONMaxDepth: 2})
	body := nested("[", "]", 5)
	res := run(t, g, m, post("/x", "application/json", body))
	if res.blocked || res.code != codeJSONDepth || string(res.body) != body {
		t.Fatalf("%+v", res)
	}
	ev := m.RecentEvents(1, "")[0]
	if ev.Action != "detected" || ev.Kind != EventKindAPI || len(ev.Rules) != 1 || ev.Rules[0].ID != 800030 {
		t.Fatalf("event %+v", ev)
	}
	st := m.Stats()
	if st.API != 1 || st.APIBlocked != 0 || st.PerViolation[codeJSONDepth] != 1 {
		t.Fatalf("stats %+v", st)
	}
	gb, mb := guardFor(t, APIModeBlock, &APILimits{JSONMaxDepth: 2})
	run(t, gb, mb, post("/x", "application/json", body))
	if st := mb.Stats(); st.APIBlocked != 1 || st.Blocked != 1 {
		t.Fatalf("stats %+v", st)
	}
	// Filter
	if n := len(mb.QueryEvents(EventFilter{Kind: "api"})); n != 1 {
		t.Errorf("kind filter api: %d", n)
	}
	if n := len(mb.QueryEvents(EventFilter{Kind: "waf"})); n != 0 {
		t.Errorf("kind filter waf: %d", n)
	}
}

func TestGuardEventsAreNotSensitive(t *testing.T) {
	g, m := guardFor(t, APIModeBlock, &APILimits{JSONMaxDepth: 2})
	run(t, g, m, post("/x", "application/json", `{"password":"hunter2","a":[[[1]]]}`))
	ev := m.RecentEvents(1, "")[0]
	if b := fmt.Sprintf("%+v", ev); strings.Contains(b, "hunter2") {
		t.Fatalf("event leaks body: %s", b)
	}
}

func TestGuardBypassesGRPCAndUpgrade(t *testing.T) {
	g, m := guardFor(t, APIModeBlock, &APILimits{URLMaxLen: 5})
	r := httptest.NewRequest("POST", "/very/long/path", nil)
	r.Header.Set("Content-Type", "application/grpc")
	if res := run(t, g, m, r); res.blocked {
		t.Error("grpc inspected")
	}
	r = httptest.NewRequest("GET", "/very/long/path", nil)
	r.Header.Set("Upgrade", "websocket")
	if res := run(t, g, m, r); res.blocked {
		t.Error("websocket inspected")
	}
}

// upstreamHash serves a guard in front of a handler that returns the sha256 of the body it received.
func guardServer(t *testing.T, g *Guard, inner http.Handler) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.Inspect(w, r, RequestInfo{Endpoint: "t", ClientIP: r.RemoteAddr}) {
			return
		}
		inner.ServeHTTP(w, r)
	}))
}

var hashHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	fmt.Fprintf(w, "%x", sha256.Sum256(b))
})

func TestGuardReplayByteIdentical(t *testing.T) {
	jsonBody := []byte(`{"name":"x","items":[1,2,3],"nested":{"a":"é☃"}}` + strings.Repeat(" ", 3000))
	big := bytes.Repeat([]byte("0123456789abcdef"), 100000) // 1.6 MB, above the default 1 MiB limit
	for _, mode := range []string{APIModeLog, APIModeBlock} {
		g, _ := guardFor(t, mode, &APILimits{MaxBodyBytes: 1 << 20, AllowContentTypeMismatch: true})
		srv := guardServer(t, g, hashHandler)
		defer srv.Close()
		type tc struct {
			name    string
			body    []byte
			ct      string
			chunked bool
			expect  bool
			allowed bool
		}
		cases := []tc{
			{"json", jsonBody, "application/json", false, false, true},
			{"json chunked", jsonBody, "application/json", true, false, true},
			{"json expect-continue", jsonBody, "application/json", false, true, true},
			{"json chunked expect-continue", jsonBody, "application/json", true, true, true},
			{"binary", big[:5000], "application/octet-stream", true, false, true},
			{"empty", nil, "application/json", false, false, true},
		}
		if mode == APIModeLog {
			cases = append(cases, tc{"oversize in log mode", big, "application/octet-stream", true, false, true})
		}
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				var rd io.Reader = bytes.NewReader(c.body)
				if c.chunked {
					rd = io.MultiReader(rd) // hides the length: chunked transfer encoding
				}
				req, _ := http.NewRequest("POST", srv.URL+"/x", rd)
				req.Header.Set("Content-Type", c.ct)
				if c.expect {
					req.Header.Set("Expect", "100-continue")
				}
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				got, _ := io.ReadAll(resp.Body)
				want := fmt.Sprintf("%x", sha256.Sum256(c.body))
				if resp.StatusCode != 200 || string(got) != want {
					t.Fatalf("status %d hash %s want %s", resp.StatusCode, got, want)
				}
			})
		}
	}
}

func TestGuardExpectContinueRejectedBeforeBody(t *testing.T) {
	g, _ := guardFor(t, APIModeBlock, &APILimits{MaxBodyBytes: 100})
	srv := guardServer(t, g, hashHandler)
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/x", bytes.NewReader(bytes.Repeat([]byte("a"), 5000)))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Expect", "100-continue")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "Request Entity Too Large") || strings.Contains(string(b), "100") && strings.Contains(string(b), "limit") {
		t.Errorf("body %q", b)
	}
}

func TestGuardConcurrent(t *testing.T) {
	g, m := guardFor(t, APIModeBlock, &APILimits{JSONMaxDepth: 3, RejectDuplicateKeys: true})
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				body := `{"a":1}`
				want := false
				if j%2 == 0 {
					body, want = `{"a":1,"a":2}`, true
				}
				rec := httptest.NewRecorder()
				if got := g.Inspect(rec, post("/x", "application/json", body), RequestInfo{}); got != want {
					t.Errorf("got %v want %v", got, want)
					return
				}
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	_ = m
}

func FuzzCheckJSON(f *testing.F) {
	for _, s := range []string{`{"a":[1,2,{"b":null}]}`, `[[[[`, `{"a":"é"}`, "", `{"a":1,"a":2}`, "\xff"} {
		f.Add([]byte(s))
	}
	l := APILimits{RejectDuplicateKeys: true, RejectInvalidUTF8: true}
	lim := l.Effective()
	f.Fuzz(func(t *testing.T, b []byte) { checkJSON(b, lim) })
}

func FuzzCheckXML(f *testing.F) {
	for _, s := range []string{`<a b="1"><c/></a>`, `<!DOCTYPE a [<!ENTITY x "y">]><a/>`, `<a>`, ""} {
		f.Add([]byte(s))
	}
	lim := DefaultAPILimits()
	f.Fuzz(func(t *testing.T, b []byte) { checkXML(b, lim) })
}
