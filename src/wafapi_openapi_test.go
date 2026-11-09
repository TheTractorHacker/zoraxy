package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

const apiTestSpec = `openapi: 3.0.0
info: {title: T, version: "1"}
paths:
  /a:
    get: {responses: {"200": {description: ok}}}
  /b:
    post: {responses: {"200": {description: ok}}}
`

func apiGet(t *testing.T, scope, name string) wafAPIView {
	t.Helper()
	var v wafAPIView
	wafGet(t, HandleWAFAPIGet, "/api/waf/api/get?scope="+scope+"&name="+url.QueryEscape(name), &v)
	return v
}

func TestWAFAPIProtectionAPIs(t *testing.T) {
	router := setupWAFCentralTest(t)
	app := "app.example.com"
	set := func(scope, name string, cfg interface{}) string {
		js, _ := json.Marshal(cfg)
		return wafPost(t, HandleWAFAPISet, url.Values{"scope": {scope}, "name": {name}, "config": {string(js)}})
	}

	// policy
	pol := waf.APIConfig{Mode: "log", Limits: &waf.APILimits{JSONMaxDepth: 7}, AllowList: []waf.APIAllowRule{{Path: "/api", Methods: []string{"GET"}}}}
	if r := set("policy", "", pol); !isOK(r) {
		t.Fatalf("policy: %s", r)
	}
	if got := router.WAFState().Policy.API; got == nil || got.Limits.JSONMaxDepth != 7 {
		t.Fatalf("policy not applied: %+v", got)
	}
	v := apiGet(t, "policy", "")
	if v.Config == nil || v.Config.Mode != "log" || v.Defaults.JSONMaxDepth != 20 || len(v.Kinds) < 20 {
		t.Fatalf("get policy: %+v", v)
	}
	if _, err := os.Stat(CONF_WAF_CENTRAL); err != nil {
		t.Fatal("policy not persisted")
	}
	st, err := loadWAFCentralState(CONF_WAF_CENTRAL)
	if err != nil || st.Policy.API == nil || st.Policy.API.AllowList[0].Path != "/api" {
		t.Fatalf("reload: %v %+v", err, st.Policy.API)
	}

	// rejected inputs change nothing
	for name, cfg := range map[string]interface{}{
		"mode":   waf.APIConfig{Mode: "enforce"},
		"limit":  waf.APIConfig{Limits: &waf.APILimits{URLMaxLen: -7}},
		"allow":  waf.APIConfig{AllowList: []waf.APIAllowRule{{Path: "nope"}}},
		"spec":   waf.APIConfig{OpenAPI: &waf.OpenAPIConfig{Spec: "nonsense"}},
		"spec 2": waf.APIConfig{OpenAPI: &waf.OpenAPIConfig{Spec: "openapi: 2.0\n"}},
	} {
		if r := set("policy", "", cfg); isOK(r) {
			t.Errorf("%s accepted", name)
		}
	}
	if r := wafPost(t, HandleWAFAPISet, url.Values{"scope": {"policy"}, "config": {"{broken"}}); isOK(r) {
		t.Error("garbage accepted")
	}
	if r := wafPost(t, HandleWAFAPISet, url.Values{"scope": {"galaxy"}, "config": {"{}"}}); isOK(r) {
		t.Error("bad scope accepted")
	}
	if router.WAFState().Policy.API.Limits.JSONMaxDepth != 7 {
		t.Fatal("rejected request changed the policy")
	}

	// endpoint, with a spec
	ep := waf.APIConfig{Mode: "block", OpenAPI: &waf.OpenAPIConfig{Spec: apiTestSpec}}
	if r := set("endpoint", app, ep); !isOK(r) {
		t.Fatalf("endpoint: %s", r)
	}
	v = apiGet(t, "endpoint", app)
	if v.Config == nil || v.Spec == nil || v.Spec.Paths != 2 || v.Spec.Operations != 2 {
		t.Fatalf("endpoint view: %+v", v)
	}
	if v.Effective == nil || v.Effective.Mode != "block" {
		t.Fatalf("effective: %+v", v.Effective)
	}
	saved, err := os.ReadFile(filepath.Join(CONF_HTTP_PROXY, app+".config"))
	if err != nil || !strings.Contains(string(saved), `"WAFAPI"`) || !strings.Contains(string(saved), "openapi: 3.0.0") {
		t.Fatalf("endpoint config not persisted: %v", err)
	}
	var cov []struct{ APIMode string }
	wafGet(t, HandleWAFCoverage, "/api/waf/coverage", &cov)
	if len(cov) != 1 || cov[0].APIMode != "block" {
		t.Fatalf("coverage: %+v", cov)
	}
	// endpoint WAF changes through the other API keep the API settings
	if r := wafPost(t, HandleWAFEndpointSet, url.Values{"rootname": {app}, "source": {"detection_only"}}); !isOK(r) {
		t.Fatalf("endpoint set: %s", r)
	}
	if apiGet(t, "endpoint", app).Config == nil {
		t.Fatal("WAF endpoint save cleared the API protection")
	}
	// clearing
	if r := wafPost(t, HandleWAFAPISet, url.Values{"scope": {"endpoint"}, "name": {app}, "config": {""}}); !isOK(r) {
		t.Fatalf("clear: %s", r)
	}
	if apiGet(t, "endpoint", app).Config != nil {
		t.Fatal("not cleared")
	}
	if r := set("endpoint", "missing.example.com", ep); isOK(r) {
		t.Error("unknown endpoint accepted")
	}

	// profile
	prof, _ := json.Marshal(waf.Profile{Name: "Shop", Mode: waf.ModeBlock})
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {string(prof)}, "create": {"true"}}); !isOK(r) {
		t.Fatalf("profile: %s", r)
	}
	if r := set("profile", "shop", waf.APIConfig{Mode: "block"}); !isOK(r) {
		t.Fatalf("profile api: %s", r)
	}
	if r := set("profile", "Strict", waf.APIConfig{Mode: "block"}); isOK(r) {
		t.Error("built-in profile edited")
	}
	if r := set("profile", "ghost", waf.APIConfig{Mode: "block"}); isOK(r) {
		t.Error("missing profile edited")
	}
	// A profile save from a client that does not send the API field keeps it
	if r := wafPost(t, HandleWAFProfileSave, url.Values{"profile": {string(prof)}}); !isOK(r) {
		t.Fatalf("profile resave: %s", r)
	}
	if apiGet(t, "profile", "Shop").Config == nil {
		t.Fatal("profile re-save cleared the API protection")
	}
}

func TestWAFAPISpecValidationAPI(t *testing.T) {
	setupWAFCentralTest(t)
	r := wafPost(t, HandleWAFAPISpec, url.Values{"spec": {apiTestSpec}})
	var s waf.SpecSummary
	if err := json.Unmarshal([]byte(r), &s); err != nil || s.Paths != 2 || s.Operations != 2 {
		t.Fatalf("%s %v", r, err)
	}
	r = wafPost(t, HandleWAFAPISpec, url.Values{"spec": {"openapi: 3.0.0\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      responses: {'200': {$ref: '#/nope'}}\n"}})
	if !strings.Contains(r, "error") {
		t.Fatalf("bad spec accepted: %s", r)
	}
	huge := strings.Repeat("x", waf.MaxOpenAPISpecBytes+1)
	r = wafPost(t, HandleWAFAPISpec, url.Values{"spec": {huge}})
	if !strings.Contains(r, "too large") {
		t.Fatalf("huge spec: %.200s", r)
	}
}
