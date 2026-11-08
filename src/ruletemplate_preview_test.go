package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func postTemplatePreview(t *testing.T, tpl string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"template": {tpl}}
	r := httptest.NewRequest(http.MethodPost, "/api/proxy/templates/preview", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	HandleRuleTemplatePreview(w, r)
	var out any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	m, _ := out.(map[string]any)
	return w.Code, m
}

func TestRuleTemplatePreviewListsChanges(t *testing.T) {
	_, out := postTemplatePreview(t, `{"Name":"My tpl","HSTSMaxAge":31536000,"RateLimit":20,"Tags":["a","b"],"WAFSource":"block"}`)
	changes, ok := out["changes"].([]any)
	if !ok || len(changes) < 4 {
		t.Fatalf("expected the changes against a fresh rule, got %v", out)
	}
	fields := map[string]bool{}
	for _, c := range changes {
		fields[c.(map[string]any)["Field"].(string)] = true
	}
	for _, f := range []string{"HSTS max age", "Rate limit (req/s)", "Tags", "WAF source"} {
		if !fields[f] {
			t.Errorf("missing change %q in %v", f, fields)
		}
	}
	if !strings.Contains(out["against"].(string), "default") {
		t.Errorf("against = %v", out["against"])
	}
}

func TestRuleTemplatePreviewSurfacesValidationErrors(t *testing.T) {
	for name, tpl := range map[string]string{
		"bad name":      `{"Name":"-bad"}`,
		"hsts range":    `{"Name":"x","HSTSMaxAge":999999999999}`,
		"waf profile":   `{"Name":"x","WAFSource":"profile"}`,
		"header name":   `{"Name":"x","Headers":[{"Key":"Bad Header","Value":"1"}]}`,
		"not json":      `nope`,
		"forbidden hdr": `{"Name":"x","Headers":[{"Key":"Host","Value":"1"}]}`,
	} {
		code, out := postTemplatePreview(t, tpl)
		if e, _ := out["error"].(string); e == "" {
			t.Errorf("%s: no error surfaced: %v (status %d)", name, out, code)
		}
	}
}

func TestRuleTemplatePreviewUnknownRule(t *testing.T) {
	form := url.Values{"template": {`{"Name":"ok"}`}, "rule": {"missing.example.com"}}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	HandleRuleTemplatePreview(w, r)
	if !strings.Contains(w.Body.String(), "error") {
		t.Fatalf("got %s", w.Body.String())
	}
}
