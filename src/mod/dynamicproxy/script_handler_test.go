package dynamicproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestScriptHandlerServesWithoutUpstream(t *testing.T) {
	var hits atomic.Int32
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("upstream")) })
	router, sep := newOpsTestRouter(t, be)
	sep.Script = &ScriptConfig{Enabled: true, Mode: ScriptModeHandler, Code: `
response.headers["Content-Type"] = "text/plain"
response.body = "User-agent: *\nDisallow: /\n" .. request.path
`}
	w := serveOps(router, "GET", "/robots.txt", nil)
	if w.Code != 200 || w.Body.String() != "User-agent: *\nDisallow: /\n/robots.txt" || hits.Load() != 0 {
		t.Fatalf("got %d %q hits=%d", w.Code, w.Body.String(), hits.Load())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", w.Header())
	}
	//HEAD has no body
	w = serveOps(router, "HEAD", "/robots.txt", nil)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %q", w.Code, w.Body.String())
	}
}

func TestScriptPathPrefixLetsOthersThrough(t *testing.T) {
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("upstream:" + r.URL.Path)) })
	router, sep := newOpsTestRouter(t, be)
	sep.Script = &ScriptConfig{Enabled: true, PathPrefix: "/lua", Code: `respond(200, "lua")`}
	if w := serveOps(router, "GET", "/lua/x", nil); w.Body.String() != "lua" {
		t.Fatal(w.Body.String())
	}
	if w := serveOps(router, "GET", "/luax", nil); w.Body.String() != "upstream:/luax" {
		t.Fatalf("prefix must respect segment boundary: %q", w.Body.String())
	}
	if w := serveOps(router, "GET", "/other", nil); w.Body.String() != "upstream:/other" {
		t.Fatal(w.Body.String())
	}
}

func TestScriptHookModifiesRequestAndCanBlock(t *testing.T) {
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("user=" + r.Header.Get("X-User") + " cookie=" + r.Header.Get("Cookie")))
	})
	router, sep := newOpsTestRouter(t, be)
	sep.Script = &ScriptConfig{Enabled: true, Mode: ScriptModeHook, Code: `
if request.headers["x-block"] then respond(403, "blocked by script") end
request_header_set("X-User", "bob")
request_header_del("Cookie")
`}
	w := serveOps(router, "GET", "/", map[string]string{"Cookie": "s=1"})
	if w.Body.String() != "user=bob cookie=" {
		t.Fatalf("hook did not change the upstream request: %q", w.Body.String())
	}
	w = serveOps(router, "GET", "/", map[string]string{"X-Block": "1"})
	if w.Code != 403 || w.Body.String() != "blocked by script" {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	//A client cannot forge what the script sets
	w = serveOps(router, "GET", "/", map[string]string{"X-User": "mallory"})
	if w.Body.String() != "user=bob cookie=" {
		t.Fatalf("client header survived: %q", w.Body.String())
	}
}

func TestScriptErrorsAreOpaque(t *testing.T) {
	router, sep := newOpsTestRouter(t, "127.0.0.1:1")
	secret := "SUPER_SECRET_TOKEN_123"
	sep.Script = &ScriptConfig{Enabled: true, Code: `local tok = "` + secret + `" error("boom " .. tok)`}
	w := serveOps(router, "GET", "/", map[string]string{"X-Request-Id": "req-abc"})
	if w.Code != 500 || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "boom") || !strings.Contains(w.Body.String(), "req-abc") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	sep.Script = &ScriptConfig{Enabled: true, Code: `while true do end`, TimeoutMs: 50}
	w = serveOps(router, "GET", "/", nil)
	if w.Code != 500 {
		t.Fatalf("timeout must be a 500, got %d", w.Code)
	}
	sep.Script = &ScriptConfig{Enabled: true, Code: `x = (`}
	w = serveOps(router, "GET", "/", nil)
	if w.Code != 500 || strings.Contains(w.Body.String(), "(") && strings.Contains(w.Body.String(), "syntax") {
		t.Fatalf("broken script: %d %q", w.Code, w.Body.String())
	}
}

func TestScriptDisabledByDefault(t *testing.T) {
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("upstream")) })
	router, sep := newOpsTestRouter(t, be)
	if w := serveOps(router, "GET", "/", nil); w.Body.String() != "upstream" {
		t.Fatal("no script configured must pass through")
	}
	sep.Script = &ScriptConfig{Enabled: false, Code: `respond(200, "lua")`}
	if w := serveOps(router, "GET", "/", nil); w.Body.String() != "upstream" {
		t.Fatal("disabled script must not run")
	}
}

func TestScriptBodyAvailableToHandler(t *testing.T) {
	router, sep := newOpsTestRouter(t, "127.0.0.1:1")
	sep.Script = &ScriptConfig{Enabled: true, Code: `local d = json.decode(request.body) response.body = d.name .. "/" .. request.method`}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"zed"}`))
	r.Host = "app.example.com"
	r.RequestURI = "/"
	router.mux.ServeHTTP(w, r)
	if w.Body.String() != "zed/POST" {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", 70000)))
	r.Host = "app.example.com"
	r.RequestURI = "/"
	router.mux.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("oversized body: %d", w.Code)
	}
}

func TestScriptConfigValidation(t *testing.T) {
	for name, c := range map[string]*ScriptConfig{
		"mode":    {Mode: "weird", Code: "x=1"},
		"prefix":  {PathPrefix: "lua", Code: "x=1"},
		"timeout": {TimeoutMs: 5000, Code: "x=1"},
		"conc":    {Concurrency: 100, Code: "x=1"},
		"syntax":  {Enabled: true, Code: "x = ("},
		"empty":   {Enabled: true, Code: "  "},
		"huge":    {Enabled: true, Code: strings.Repeat("x=1\n", 40000)},
	} {
		if c.Validate() == nil {
			t.Errorf("%s: should be invalid", name)
		}
	}
	if (&ScriptConfig{Enabled: true, Code: "x=1"}).Validate() != nil {
		t.Error("valid config rejected")
	}
	var nilCfg *ScriptConfig
	if nilCfg.Validate() != nil {
		t.Error("nil config must be valid")
	}
}

func TestScriptRoundTripsThroughEndpointCopy(t *testing.T) {
	sep := &ProxyEndpoint{Script: &ScriptConfig{Enabled: true, Mode: ScriptModeHook, Code: "x=1", TimeoutMs: 200}}
	cp := CopyEndpoint(sep)
	if cp.Script == nil || cp.Script.Code != "x=1" || cp.Script.TimeoutMs != 200 || !cp.Script.Enabled {
		t.Fatalf("lost in copy: %+v", cp.Script)
	}
	b, _ := json.Marshal(&ProxyEndpoint{})
	if strings.Contains(string(b), "Script") {
		t.Fatal("unset script must not appear in saved configs")
	}
}

func TestRunScriptTest(t *testing.T) {
	res := RunScriptTest(&ScriptConfig{Enabled: true, Code: `response.status = 202 response.body = request.method .. request.args.q .. request.headers["x-a"] log("hi")`},
		"rule", ScriptTestRequest{Method: "post", Query: "q=7", Headers: map[string]string{"X-A": "z"}})
	if res.Error != "" || res.Status != 202 || res.Body != "POST7z" || len(res.Logs) != 1 {
		t.Fatalf("%+v", res)
	}
	res = RunScriptTest(&ScriptConfig{Enabled: true, Code: `error("x")`}, "rule", ScriptTestRequest{})
	if res.Error == "" {
		t.Fatal("error not reported")
	}
}
