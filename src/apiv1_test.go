package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/csrf"
	"gopkg.in/yaml.v3"
	"imuslab.com/zoraxy/mod/apitoken"
)

type v1KV struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (k *v1KV) NewTable(string) error { return nil }
func (k *v1KV) Write(_, key string, v interface{}) error {
	b, _ := json.Marshal(v)
	k.mu.Lock()
	k.m[key] = b
	k.mu.Unlock()
	return nil
}
func (k *v1KV) Delete(_, key string) error { delete(k.m, key); return nil }
func (k *v1KV) ListTable(string) ([][][]byte, error) {
	out := [][][]byte{}
	for key, v := range k.m {
		out = append(out, [][]byte{[]byte(key), v})
	}
	return out, nil
}

type v1Capture struct {
	path   string
	method string
	form   url.Values
	query  url.Values
}

func v1TestSetup(t *testing.T) (*apitoken.Manager, http.Handler, *v1Capture, string, string) {
	t.Helper()
	mgr, err := apitoken.NewManager(&v1KV{m: map[string][]byte{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cap := &v1Capture{}
	stub := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			*cap = v1Capture{path: r.URL.Path, method: r.Method, form: r.PostForm, query: r.URL.Query()}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(body))
		}
	}
	b := v1Backend{
		ProxyList: stub(`[{"RootOrMatchingDomain":"a.example.com","UpstreamOrigins":[]}]`),
		ProxyAdd:  stub(`"OK"`), ProxyEdit: stub(`"OK"`), ProxyToggle: stub(`"OK"`),
		ProxyDelete: stub(`{"error":"proxy rule not found"}`),
		AccessList:  stub(`[]`), RedirectList: stub(`[]`), CertList: stub(`[]`), StatsSummary: stub(`{}`), WAF: stub(`[]`), StatsBlocked: stub(`{}`),
		RulesetRules: stub(`[]`), RulesetLists: stub(`[]`),
	}
	h := newAPIv1Handler(mgr, b, func(next http.Handler) http.Handler { return next })
	ro, _, _ := mgr.Create("ro", apitoken.ScopeRead, 0, nil)
	rw, _, _ := mgr.Create("rw", apitoken.ScopeReadWrite, 0, nil)
	return mgr, h, cap, ro, rw
}

func v1Do(h http.Handler, method, path, tok, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "10.0.0.9:1234"
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAPIv1ReadWriteScopes(t *testing.T) {
	_, h, cap, ro, rw := v1TestSetup(t)

	if w := v1Do(h, "GET", "/api/v1/proxy-rules", ro, ""); w.Code != 200 || cap.path != "/api/proxy/list" || cap.query.Get("type") != "host" {
		t.Fatalf("list: %d %+v", w.Code, cap)
	}
	for _, c := range [][2]string{{"POST", "/api/v1/proxy-rules"}, {"PATCH", "/api/v1/proxy-rules/a"}, {"DELETE", "/api/v1/proxy-rules/a"}, {"POST", "/api/v1/proxy-rules/a/enable"}} {
		if w := v1Do(h, c[0], c[1], ro, `{"x":1}`); w.Code != 403 {
			t.Errorf("read token %s %s: %d", c[0], c[1], w.Code)
		}
	}
	// create: JSON -> form, default type
	*cap = v1Capture{}
	w := v1Do(h, "POST", "/api/v1/proxy-rules", rw, `{"rootname":"n.example.com","ep":"127.0.0.1:80","tls":false,"ratenum":5}`)
	if w.Code != 201 || cap.path != "/api/proxy/add" || cap.method != "POST" || cap.form.Get("type") != "host" ||
		cap.form.Get("rootname") != "n.example.com" || cap.form.Get("tls") != "false" || cap.form.Get("ratenum") != "5" {
		t.Fatalf("create: %d %+v", w.Code, cap)
	}
	// edit injects rootname from path, path wins over body
	v1Do(h, "PATCH", "/api/v1/proxy-rules/a.example.com", rw, `{"rootname":"evil","rate":true}`)
	if cap.path != "/api/proxy/edit" || cap.form.Get("rootname") != "a.example.com" || cap.form.Get("rate") != "true" {
		t.Fatalf("edit: %+v", cap)
	}
	v1Do(h, "POST", "/api/v1/proxy-rules/a.example.com/disable", rw, "")
	if cap.path != "/api/proxy/toggle" || cap.form.Get("ep") != "a.example.com" || cap.form.Get("enable") != "false" {
		t.Fatalf("disable: %+v", cap)
	}
	// legacy {"error":...} mapped to a status code
	if w := v1Do(h, "DELETE", "/api/v1/proxy-rules/zzz", rw, ""); w.Code != 404 {
		t.Fatalf("delete error mapping: %d", w.Code)
	}
	if w := v1Do(h, "POST", "/api/v1/proxy-rules", rw, `not json`); w.Code != 400 {
		t.Fatalf("bad json: %d", w.Code)
	}
	// single get comes from the sanitised list
	if w := v1Do(h, "GET", "/api/v1/proxy-rules/A.example.com", ro, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "a.example.com") {
		t.Fatalf("get one: %d %s", w.Code, w.Body.String())
	}
	if w := v1Do(h, "GET", "/api/v1/proxy-rules/none", ro, ""); w.Code != 404 {
		t.Fatalf("get missing: %d", w.Code)
	}
	for _, p := range []string{"access-rules", "redirects", "certificates", "stats/summary", "waf/coverage", "ruleset/rules", "ruleset/lists", "health"} {
		if w := v1Do(h, "GET", "/api/v1/"+p, ro, ""); w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func TestAPIv1AuthRequiredAndDocsPublic(t *testing.T) {
	_, h, _, _, _ := v1TestSetup(t)
	if w := v1Do(h, "GET", "/api/v1/proxy-rules", "", ""); w.Code != 401 {
		t.Fatal("no token must be 401")
	}
	if w := v1Do(h, "GET", "/api/v1/nonexistent", "", ""); w.Code != 401 {
		t.Fatal("unknown route without token must be 401")
	}
	if w := v1Do(h, "GET", "/api/v1/openapi.yaml", "", ""); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "openapi:") {
		t.Fatalf("openapi.yaml: %d", w.Code)
	}
	if w := v1Do(h, "GET", "/api/v1/openapi.json", "", ""); w.Code != 200 || !json.Valid(w.Body.Bytes()) {
		t.Fatalf("openapi.json: %d", w.Code)
	}
	if w := v1Do(h, "GET", "/api/v1/docs", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "openapi.json") {
		t.Fatalf("docs: %d", w.Code)
	}
}

// Mirrors main(): cookie/CSRF stack on "/", token API mounted beside it.
func TestAPIv1NoCSRFOnlyForTokensAndCookiePathsUnchanged(t *testing.T) {
	mgr, v1, cap, ro, rw := v1TestSetup(t)
	apiTokenManager = mgr
	defer func() { apiTokenManager = nil }()

	panelHit := 0
	panel := http.NewServeMux()
	for _, p := range []string{"/api/proxy/add", "/api/apitoken/create", "/api/apitoken/revoke"} {
		panel.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { panelHit++ })
	}
	csrfMW := csrf.Protect([]byte("0123456789abcdef0123456789abcdef"), csrf.Secure(false))
	entry := http.NewServeMux()
	entry.Handle("/", csrfMW(panel))
	entry.Handle(apiV1Prefix, v1)

	// token API: write with token and no CSRF works
	*cap = v1Capture{}
	if w := v1Do(entry, "POST", "/api/v1/proxy-rules/a.example.com/enable", rw, ""); w.Code != 200 || cap.path == "" {
		t.Fatalf("token write without csrf: %d", w.Code)
	}
	// read-only still blocked
	if w := v1Do(entry, "POST", "/api/v1/proxy-rules/a.example.com/enable", ro, ""); w.Code != 403 {
		t.Fatalf("ro write: %d", w.Code)
	}
	// Bearer on cookie routes never bypasses CSRF / reaches the handler
	for _, tok := range []string{rw, ro} {
		for _, p := range []string{"/api/proxy/add", "/api/apitoken/create", "/api/apitoken/revoke"} {
			if w := v1Do(entry, "POST", p, tok, ""); w.Code != 403 || panelHit != 0 {
				t.Fatalf("bearer on %s: code %d hit %d", p, w.Code, panelHit)
			}
		}
	}
	// token management is not part of /api/v1
	if w := v1Do(entry, "POST", "/api/v1/apitoken/create", rw, ""); w.Code == 200 {
		t.Fatal("token management reachable through v1")
	}
	// cookie only (no token) on v1 is rejected
	r := httptest.NewRequest("GET", "/api/v1/proxy-rules", nil)
	r.AddCookie(&http.Cookie{Name: "Zoraxy", Value: "session"})
	r.RemoteAddr = "10.0.0.9:1"
	w := httptest.NewRecorder()
	entry.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("cookie on v1: %d", w.Code)
	}
}

func TestAPIv1OpenAPIMatchesRoutes(t *testing.T) {
	var spec struct {
		OpenAPI string `yaml:"openapi"`
		Paths   map[string]map[string]yaml.Node
	}
	if err := yaml.Unmarshal(apiV1OpenAPI, &spec); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.0") || len(spec.Paths) == 0 {
		t.Fatal("not an OpenAPI 3.0 document")
	}
	documented := []string{}
	for p, ops := range spec.Paths {
		for m := range ops {
			switch m {
			case "get", "post", "put", "patch", "delete":
				documented = append(documented, strings.ToUpper(m)+" "+p)
			}
		}
	}
	sort.Strings(documented)
	registered := v1RoutePatterns()
	if strings.Join(documented, "\n") != strings.Join(registered, "\n") {
		t.Fatalf("spec and routes differ\nspec:\n%s\nroutes:\n%s", strings.Join(documented, "\n"), strings.Join(registered, "\n"))
	}
}
