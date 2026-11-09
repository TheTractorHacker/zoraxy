package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const petSpecYAML = `
openapi: 3.0.3
info: {title: Pets, version: "1.2"}
servers:
  - url: https://api.example.com/v1
paths:
  /pets:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 100}}
        - {name: X-Trace, in: header, required: true, schema: {type: string, minLength: 3}}
      responses: {"200": {description: ok}}
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name, age]
              additionalProperties: false
              properties:
                name: {type: string, minLength: 1}
                age: {type: integer, minimum: 0}
                tags: {type: array, items: {type: string}, maxItems: 3}
      responses: {"201": {description: created}}
  /pets/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses: {"200": {description: ok}}
`

func oaGuard(t *testing.T, mode string, oa OpenAPIConfig) (*Guard, *Manager) {
	t.Helper()
	m := NewManager()
	g, err := m.NewGuard(&APIConfig{Mode: mode, OpenAPI: &oa})
	if err != nil || g == nil {
		t.Fatalf("NewGuard %v %v", g, err)
	}
	return g, m
}

func TestOpenAPIRequests(t *testing.T) {
	g, m := oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: petSpecYAML})
	if g.SpecError() != "" {
		t.Fatal(g.SpecError())
	}
	mk := func(method, target, body string, hdr ...string) *http.Request {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	cases := []struct {
		name   string
		r      *http.Request
		code   string
		status int
	}{
		{"valid get", mk("GET", "/v1/pets?limit=5", "", "X-Trace", "abc"), "", 0},
		{"valid post", mk("POST", "/v1/pets", `{"name":"rex","age":3,"tags":["a"]}`), "", 0},
		{"valid path param", mk("GET", "/v1/pets/42", ""), "", 0},
		{"unknown path", mk("GET", "/v1/owners", ""), codeOpenAPIPath, 404},
		{"outside server base path", mk("GET", "/pets", ""), codeOpenAPIPath, 404},
		{"wrong method", mk("DELETE", "/v1/pets", ""), codeOpenAPIMethod, 405},
		{"missing required header", mk("GET", "/v1/pets", ""), codeOpenAPIParam, 400},
		{"param constraint max", mk("GET", "/v1/pets?limit=101", "", "X-Trace", "abc"), codeOpenAPIParam, 400},
		{"param constraint min", mk("GET", "/v1/pets?limit=0", "", "X-Trace", "abc"), codeOpenAPIParam, 400},
		{"param wrong type", mk("GET", "/v1/pets?limit=abc", "", "X-Trace", "abc"), codeOpenAPIParam, 400},
		{"header constraint", mk("GET", "/v1/pets", "", "X-Trace", "ab"), codeOpenAPIParam, 400},
		{"path param wrong type", mk("GET", "/v1/pets/abc", ""), codeOpenAPIParam, 400},
		{"missing required field", mk("POST", "/v1/pets", `{"name":"rex"}`), codeOpenAPIBody, 400},
		{"wrong field type", mk("POST", "/v1/pets", `{"name":"rex","age":"three"}`), codeOpenAPIBody, 400},
		{"extra field", mk("POST", "/v1/pets", `{"name":"rex","age":3,"admin":true}`), codeOpenAPIBody, 400},
		{"array too long", mk("POST", "/v1/pets", `{"name":"rex","age":3,"tags":["a","b","c","d"]}`), codeOpenAPIBody, 400},
		{"missing body", mk("POST", "/v1/pets", ""), codeOpenAPIBody, 400},
		{"empty name", mk("POST", "/v1/pets", `{"name":"","age":3}`), codeOpenAPIBody, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := run(t, g, m, c.r)
			if res.code != c.code || res.status != c.status {
				t.Fatalf("%+v want %q/%d", res, c.code, c.status)
			}
		})
	}
}

func TestOpenAPIBodyReplayedAndRequestUntouched(t *testing.T) {
	g, m := oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: petSpecYAML})
	body := `{"name":"rex","age":3}`
	r := httptest.NewRequest("POST", "/v1/pets", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	res := run(t, g, m, r)
	if res.blocked || string(res.body) != body {
		t.Fatalf("%+v", res)
	}
}

func TestOpenAPIOptions(t *testing.T) {
	// unknown paths allowed
	g, m := oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: petSpecYAML, AllowUnknownPaths: true})
	if res := run(t, g, m, httptest.NewRequest("GET", "/v1/owners", nil)); res.blocked {
		t.Error("unknown path blocked despite AllowUnknownPaths")
	}
	// skip body
	g, m = oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: petSpecYAML, SkipBody: true})
	r := httptest.NewRequest("POST", "/v1/pets", strings.NewReader(`{"bad":1}`))
	r.Header.Set("Content-Type", "application/json")
	if res := run(t, g, m, r); res.blocked {
		t.Error("body validated despite SkipBody")
	}
	// log mode never blocks
	g, m = oaGuard(t, APIModeLog, OpenAPIConfig{Spec: petSpecYAML})
	res := run(t, g, m, httptest.NewRequest("GET", "/v1/owners", nil))
	if res.blocked || res.code != codeOpenAPIPath {
		t.Errorf("log mode %+v", res)
	}
	// non-JSON bodies are not validated against schemas
	g, m = oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: petSpecYAML})
	r = httptest.NewRequest("POST", "/v1/pets", strings.NewReader("a=b"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if res := run(t, g, m, r); res.blocked {
		t.Errorf("form body: %+v", res)
	}
}

func TestOpenAPIJSONSpec(t *testing.T) {
	spec := `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/ping":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	g, m := oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: spec})
	if res := run(t, g, m, httptest.NewRequest("GET", "/ping", nil)); res.blocked {
		t.Error("valid blocked")
	}
	if res := run(t, g, m, httptest.NewRequest("GET", "/pong", nil)); !res.blocked {
		t.Error("unknown path allowed")
	}
}

func TestOpenAPISpecRejectedAtSave(t *testing.T) {
	cases := map[string]string{
		"not a document": "just some words",
		"swagger 2":      `{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`,
		"no paths":       "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths: {}\n",
		"missing info":   "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      responses: {'200': {description: ok}}\n",
		"bad ref":        "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      responses:\n        '200': {$ref: '#/components/responses/Nope'}\n",
		"bad yaml":       "openapi: 3.0.0\n  info: [unclosed",
		"invalid type":   "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      parameters:\n        - {name: x, in: query, schema: {type: bogus}}\n      responses: {'200': {description: ok}}\n",
		"external ref":   "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      responses:\n        '200': {$ref: 'file:///etc/passwd'}\n",
		"http ref":       "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      responses:\n        '200': {$ref: 'http://127.0.0.1:1/x.yaml#/a'}\n",
		"bad pattern":    "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      parameters:\n        - {name: x, in: query, schema: {type: string, pattern: '(['}}\n      responses: {'200': {description: ok}}\n",
		"binary":         "\x00\x01\x02\xff\xfe",
		"json array":     "[1,2,3]",
		"openapi 4":      "openapi: 4.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      responses: {'200': {description: ok}}\n",
		"path without /": "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  a:\n    get:\n      responses: {'200': {description: ok}}\n",
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			c := &APIConfig{Mode: APIModeBlock, OpenAPI: &OpenAPIConfig{Spec: spec}}
			err := c.Validate()
			if err == nil {
				t.Fatalf("accepted")
			}
			if len(err.Error()) < 10 || len(err.Error()) > 600 {
				t.Errorf("odd message %q", err)
			}
			t.Log(err)
		})
	}
}

func TestOpenAPISpecTooLarge(t *testing.T) {
	spec := "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths: {}\n# " + strings.Repeat("x", MaxOpenAPISpecBytes)
	if err := (&APIConfig{Mode: APIModeLog, OpenAPI: &OpenAPIConfig{Spec: spec}}).Validate(); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v", err)
	}
	// at the limit is parsed (and fails for another reason, not size)
	if _, err := CompileOpenAPI(spec[:MaxOpenAPISpecBytes]); err != nil && strings.Contains(err.Error(), "too large") {
		t.Fatal("limit is off by one")
	}
}

func TestOpenAPIAdversarialSpecsDoNotPanic(t *testing.T) {
	deep := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	aliasBomb := "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\nf: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\ng: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\nh: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]\nopenapi: 3.0.0\n"
	selfRef := "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/A'}\n      responses: {'200': {description: ok}}\ncomponents:\n  schemas:\n    A: {$ref: '#/components/schemas/A'}\n"
	recursive := "openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/Node'}\n      responses: {'200': {description: ok}}\ncomponents:\n  schemas:\n    Node:\n      type: object\n      properties:\n        child: {$ref: '#/components/schemas/Node'}\n"
	specs := []string{
		deep, "{" + strings.Repeat(`"a":{`, 3000) + strings.Repeat("}", 3001), aliasBomb, selfRef,
		"openapi: 3.0.0\ninfo: null\npaths: null\n", "openapi: [1]\n", "~", "!!binary x", "openapi: 3.0.0\npaths:\n  /a:\n    get: null\n",
		"openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /{a}/{a}:\n    get:\n      responses: {'200': {description: ok}}\n",
		"openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      parameters: [null]\n      responses: {'200': {description: ok}}\n",
		"openapi: 3.0.0\ninfo: {title: t, version: '1'}\nservers: [{url: '{x}'}, {url: ':::'}, null]\npaths:\n  /a:\n    get:\n      responses: {'200': {description: ok}}\n",
	}
	for i, s := range specs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("spec %d panicked: %v", i, r)
				}
			}()
			rt, err := CompileOpenAPI(s)
			if err == nil && rt != nil {
				// whatever compiled must also survive requests
				g, m := oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: s})
				r := httptest.NewRequest("POST", "/a", strings.NewReader(`{"child":{"child":{}}}`))
				r.Header.Set("Content-Type", "application/json")
				run(t, g, m, r)
			}
		}()
	}
	// Recursive schemas are legal and validate
	g, m := oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: recursive})
	r := httptest.NewRequest("POST", "/a", strings.NewReader(`{"child":{"child":{"child":1}}}`))
	r.Header.Set("Content-Type", "application/json")
	if res := run(t, g, m, r); !res.blocked || res.code != codeOpenAPIBody {
		t.Errorf("recursive schema: %+v", res)
	}
}

func TestOpenAPIFailOpenAndClosed(t *testing.T) {
	// A spec that does not compile reaches the guard only through a stored config (e.g. after an upgrade).
	bad := "this is not a spec"
	g, m := oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: bad})
	if g.SpecError() == "" {
		t.Fatal("no spec error recorded")
	}
	if res := run(t, g, m, httptest.NewRequest("GET", "/anything", nil)); res.blocked {
		t.Error("bad spec blocked traffic (should fail open)")
	}
	g, m = oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: bad, BlockUnknown: true})
	res := run(t, g, m, httptest.NewRequest("GET", "/anything", nil))
	if !res.blocked || res.code != codeOpenAPIError {
		t.Errorf("BlockUnknown: %+v", res)
	}
	// ...but the other protections keep working when the spec is bad
	g, m = oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: bad})
	g.lim.URLMaxLen = 10
	if res := run(t, g, m, httptest.NewRequest("GET", "/"+strings.Repeat("a", 50), nil)); !res.blocked {
		t.Error("limits disabled by bad spec")
	}
}

func TestOpenAPISummary(t *testing.T) {
	rt, err := CompileOpenAPI(petSpecYAML)
	if err != nil {
		t.Fatal(err)
	}
	s := rt.Summary
	if s.Paths != 2 || s.Operations != 3 || s.Title != "Pets" || s.Version != "1.2" || !strings.HasPrefix(s.OpenAPI, "3.0") {
		t.Fatalf("%+v", s)
	}
}

func TestOpenAPIEventDoesNotLeakValues(t *testing.T) {
	g, m := oaGuard(t, APIModeBlock, OpenAPIConfig{Spec: petSpecYAML})
	r := httptest.NewRequest("POST", "/v1/pets", strings.NewReader(`{"name":"rex","age":"s3cr3t-value"}`))
	r.Header.Set("Content-Type", "application/json")
	run(t, g, m, r)
	ev := m.RecentEvents(1, "")[0]
	if b := ev.Rules[0].Data + ev.Rules[0].Message; strings.Contains(b, "s3cr3t") {
		t.Fatalf("leak: %s", b)
	}
	t.Log(ev.Rules[0].Data)
}
