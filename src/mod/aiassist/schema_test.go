package aiassist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExplainSchemaRejections(t *testing.T) {
	ok := `{"verdict":"unclear","explanation":"Short.","actions":[{"type":"no_action"}]}`
	if _, err := ParseExplain([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	long := strings.TrimSpace(strings.Repeat("word ", 121))
	bad := map[string]string{
		"extra top field":     `{"verdict":"unclear","explanation":"x","actions":[],"run":"rm -rf /"}`,
		"extra action field":  `{"verdict":"unclear","explanation":"x","actions":[{"type":"no_action","cmd":"x"}]}`,
		"unknown verdict":     `{"verdict":"definitely","explanation":"x","actions":[]}`,
		"unknown action":      `{"verdict":"unclear","explanation":"x","actions":[{"type":"disable_waf"}]}`,
		"action type missing": `{"verdict":"unclear","explanation":"x","actions":[{}]}`,
		"wrong type":          `{"verdict":"unclear","explanation":5,"actions":[]}`,
		"rule id string":      `{"verdict":"unclear","explanation":"x","actions":[{"type":"exclude_variable","rule_id":"942100"}]}`,
		"too many words":      `{"verdict":"unclear","explanation":"` + long + `","actions":[]}`,
		"empty explanation":   `{"verdict":"unclear","explanation":"  ","actions":[]}`,
		"control chars":       `{"verdict":"unclear","explanation":"a\u0000b","actions":[]}`,
		"bidi":                `{"verdict":"unclear","explanation":"a‮b","actions":[]}`,
		"too many actions":    `{"verdict":"unclear","explanation":"x","actions":[{"type":"no_action"},{"type":"no_action"},{"type":"no_action"},{"type":"no_action"}]}`,
		"trailing data":       ok + ` {"x":1}`,
		"not json":            `hello`,
		"oversized":           `{"verdict":"unclear","explanation":"` + strings.Repeat("a", 70000) + `","actions":[]}`,
		"array":               `[]`,
	}
	for name, in := range bad {
		if _, err := ParseExplain([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestProposalAndPlanValidation(t *testing.T) {
	good := `{"proposals":[{"name":"n","description":"d","reason":"r","expression":"(a eq 1)","action":"log"}]}`
	p, err := ParseProposals([]byte(good), 3)
	if err != nil || p[0].Mode != ModeLogOnly {
		t.Fatalf("%v %+v", err, p)
	}
	for name, in := range map[string]string{
		"unknown action": strings.Replace(good, `"log"`, `"exec"`, 1),
		"mode field":     strings.Replace(good, `"action"`, `"mode":"block","action"`, 1),
		"multiline expr": strings.Replace(good, "(a eq 1)", `(a\nb)`, 1),
		"huge expr":      strings.Replace(good, "(a eq 1)", strings.Repeat("a", 501), 1),
		"empty name":     strings.Replace(good, `"n"`, `""`, 1),
	} {
		if _, err := ParseProposals([]byte(in), 3); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParsePlan([]byte(`{"summary":"s","steps":[{"priority":9,"title":"t","why":"w","how":"h"}]}`), nil); err == nil {
		t.Error("priority 9 accepted")
	}
	if _, err := ParsePlan([]byte(`{"summary":"s","steps":[{"priority":1,"title":"t","why":"w","how":"h","extra":1}]}`), nil); err == nil {
		t.Error("extra plan field accepted")
	}
}

func TestExtractJSONObject(t *testing.T) {
	got, ok := extractJSONObject("Here you go:\n```json\n{\"a\":\"}\",\"b\":{\"c\":1}}\n```\nbye {not}")
	if !ok || string(got) != `{"a":"}","b":{"c":1}}` {
		t.Fatalf("%q %v", got, ok)
	}
	if _, ok := extractJSONObject("no json"); ok {
		t.Fatal("found json in prose")
	}
	if _, ok := extractJSONObject(`{"a":`); ok {
		t.Fatal("unbalanced accepted")
	}
}

// Anthropic Messages API client against a mock: field names, headers, tool use parsing.
func TestAnthropicClientAgainstMock(t *testing.T) {
	var gotBody map[string]any
	var gotHdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHdr = r.Header.Clone()
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte(`{"stop_reason":"tool_use","content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"t1","name":"explain_event","input":{"verdict":"unclear","explanation":"x","actions":[]}}],"usage":{"input_tokens":11,"output_tokens":7}}`))
	}))
	defer srv.Close()
	o := &Outbound{Feature: FeatureExplain, System: "sys", User: "usr", ToolName: "explain_event", ToolDesc: "d", Schema: explainSchema(), MaxTokens: 500}
	resp, err := callAnthropic(context.Background(), newGuardedClient(true, 5e9), srv.URL, fakeKey, "claude-sonnet-5-5", o)
	if err != nil {
		t.Fatal(err)
	}
	if resp.InputTokens != 11 || resp.OutputTokens != 7 {
		t.Fatalf("%+v", resp)
	}
	if _, err := ParseExplain(resp.JSON); err != nil {
		t.Fatal(err)
	}
	if gotHdr.Get("x-api-key") != fakeKey || gotHdr.Get("anthropic-version") != "2023-06-01" || !strings.Contains(gotHdr.Get("User-Agent"), "zoraxy") {
		t.Fatalf("headers %v", gotHdr)
	}
	if gotBody["model"] != "claude-sonnet-5-5" || gotBody["system"] != "sys" || gotBody["max_tokens"].(float64) != 500 {
		t.Fatalf("body %v", gotBody)
	}
	tools := gotBody["tools"].([]any)
	if tools[0].(map[string]any)["name"] != "explain_event" || tools[0].(map[string]any)["input_schema"] == nil {
		t.Fatalf("tools %v", tools)
	}
	if gotBody["tool_choice"].(map[string]any)["type"] != "auto" {
		t.Fatal("tool_choice")
	}
	for _, k := range []string{"temperature", "thinking", "top_p", "stream"} {
		if _, has := gotBody[k]; has {
			t.Errorf("unexpected %s", k)
		}
	}
	// no tool_use block, refusal and truncation are errors
	for _, reply := range []string{`{"stop_reason":"end_turn","content":[{"type":"text","text":"{}"}]}`, `{"stop_reason":"refusal","content":[]}`, `{"stop_reason":"max_tokens","content":[]}`} {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(reply)) }))
		if _, err := callAnthropic(context.Background(), newGuardedClient(true, 5e9), bad.URL, fakeKey, "m", o); err == nil {
			t.Errorf("accepted %s", reply)
		}
		bad.Close()
	}
	// HTTP errors carry the status, never the key
	e429 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"slow down"}}`))
	}))
	defer e429.Close()
	_, err = callAnthropic(context.Background(), newGuardedClient(true, 5e9), e429.URL, fakeKey, "m", o)
	if err == nil || !strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), fakeKey) {
		t.Fatalf("%v", err)
	}
}

func TestResponseSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", maxResponseBytes+10)))
	}))
	defer srv.Close()
	if _, _, err := doJSON(context.Background(), newGuardedClient(true, 5e9), srv.URL, nil, map[string]int{}); err == nil {
		t.Fatal("oversized reply accepted")
	}
}
