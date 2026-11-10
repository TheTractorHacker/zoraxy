package aiassist

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/blocklog"
)

// Finding 1: the stored key never follows a changed destination.
func TestKeyClearedWhenDestinationChanges(t *testing.T) {
	s := newTestService(t, nil, nil)
	base := DefaultSettings()
	base.Enabled = true
	if _, err := s.Save(SettingsUpdate{Settings: base, APIKey: fakeKey}); err != nil {
		t.Fatal(err)
	}
	same := base
	same.Model = "claude-haiku-5-5"
	if v, err := s.Save(SettingsUpdate{Settings: same}); err != nil || !v.KeySet {
		t.Fatalf("an unrelated change must keep the key: %+v %v", v, err)
	}
	evil := same
	evil.Endpoint = "https://attacker.example"
	if v, err := s.Save(SettingsUpdate{Settings: evil}); err != nil || v.KeySet {
		t.Fatalf("endpoint change must clear the key: %+v %v", v, err)
	}
	if _, ok, _ := s.vault.Get(); ok {
		t.Fatal("key still in the vault")
	}
	// a new key may come with the change
	if v, err := s.Save(SettingsUpdate{Settings: evil, APIKey: fakeKey}); err != nil || !v.KeySet {
		t.Fatalf("%+v %v", v, err)
	}
	// provider change
	oa := localSettings("https://models.example/v1")
	oa.LocalModel = false
	if v, err := s.Save(SettingsUpdate{Settings: oa}); err != nil || v.KeySet {
		t.Fatalf("provider change must clear the key: %+v %v", v, err)
	}
}

// Finding 2: addresses inside paths and agents are masked, real version numbers are kept.
func TestIPsInPathsAndAgentsAreMasked(t *testing.T) {
	r := &Redactor{P: Policy{SendPaths: true}, Pseudo: func(k, v string) string { return k + "-X" }}
	for _, in := range []string{"/proxy/203.0.113.9/admin", "/a/ip-203.0.113.9", "/go/http://203.0.113.9:8080/", "Mozilla/203.0.113.9", "/x;203.0.113.9"} {
		if out := r.Path(in); strings.Contains(out, "203.0.113.9") {
			t.Errorf("Path(%q) leaked: %q", in, out)
		}
		if out := r.Text(in, 200); strings.Contains(out, "203.0.113.9") {
			t.Errorf("Text(%q) leaked: %q", in, out)
		}
		if err := r.Verify(in); err == nil {
			t.Errorf("Verify accepted %q", in)
		}
	}
	if out := r.Text("Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36", 200); !strings.Contains(out, "Chrome/120.0.0.0") {
		t.Errorf("browser version was masked: %q", out)
	}
}

// Findings 3 and 4: the verdict and the address are checked in code, not only in the prompt.
func TestActionsEnforceVerdictAndSafeAddresses(t *testing.T) {
	mk := func(v string) *ExplainResult {
		return &ExplainResult{Verdict: v, Actions: []ExplainAction{
			{Type: ActExcludeVariable, RuleID: 942100, Variable: "ARGS:q"},
			{Type: ActExcludeRuleForPath, RuleID: 942100},
			{Type: ActBlocklistProposal},
		}}
	}
	in := EventInput{WAF: wafEvent()}
	for _, v := range []string{VerdictAttack, VerdictUnclear} {
		acts, _ := resolveActions(mk(v), in)
		for _, a := range acts {
			if a.Type == ActExcludeVariable || a.Type == ActExcludeRuleForPath {
				t.Errorf("verdict %s offered %s", v, a.Type)
			}
		}
	}
	acts, dropped := resolveActions(mk(VerdictFalsePositive), in)
	if len(acts) != 1 || acts[0].Type != ActExcludeVariable || dropped != 2 { // the whole-path form of a SQLi rule is refused
		t.Fatalf("false positive: %+v dropped=%d", acts, dropped)
	}
	acts, _ = resolveActions(mk(VerdictAttack), in)
	if len(acts) != 1 || acts[0].Type != ActBlocklistProposal || acts[0].IP != "203.0.113.77" {
		t.Fatalf("attack: %+v", acts)
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1", "::1", "0.0.0.0", "fe80::1", "::ffff:10.1.1.1"} {
		e := *wafEvent()
		e.ClientIP = ip
		if acts, _ := resolveActions(mk(VerdictAttack), EventInput{WAF: &e}); len(acts) != 0 {
			t.Errorf("%s must not be proposed: %+v", ip, acts)
		}
	}
	if acts, _ := resolveActions(mk(VerdictAttack), EventInput{Block: &blocklog.Entry{IP: "127.0.0.1"}}); len(acts) != 0 {
		t.Errorf("blocked entry loopback: %+v", acts)
	}
}

// Finding 5: Save and Ack never overwrite each other.
func TestConcurrentSaveAndAckDoNotLoseUpdates(t *testing.T) {
	s := newTestService(t, nil, nil)
	base := localSettings("http://127.0.0.1:1/v1")
	if _, err := s.Save(SettingsUpdate{Settings: base, APIKey: fakeKey}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = s.Ack(FeatureExplain) }()
		go func() {
			defer wg.Done()
			n := base
			n.Enabled = i%2 == 0
			n.Model = "m" + itoa(int64(i))
			_, _ = s.Save(SettingsUpdate{Settings: n})
		}()
		wg.Wait()
		got := s.store.Load()
		if got.Model != "m"+itoa(int64(i)) || got.Enabled != (i%2 == 0) {
			t.Fatalf("round %d: save was reverted: %+v", i, got)
		}
	}
}

// Finding 6: a failed call (wrong key) is not charged against the monthly budget.
func TestFailedCallsDoNotChargeTheBudget(t *testing.T) {
	m := newMock(t, func(int64, string) (int, string) { return 401, `{"error":{"message":"bad key"}}` })
	s := setup(t, m, nil)
	for i := 0; i < 3; i++ {
		if _, err := s.Explain(context.Background(), EventInput{WAF: wafEvent()}); err == nil {
			t.Fatal("expected an error")
		}
	}
	if u := s.Usage(); u.Tokens != 0 {
		t.Fatalf("failed calls were charged: %+v", u)
	}
}

type openAIRun struct {
	resp *Response
	err  error
	n    int64
	auth map[string]bool
}

func runOpenAI(t *testing.T, h http.HandlerFunc) openAIRun {
	t.Helper()
	o := &Outbound{Feature: FeatureExplain, System: "s", User: "u", ToolName: "t", ToolDesc: "d", Schema: explainSchema(), MaxTokens: 100}
	var n atomic.Int64
	var mu sync.Mutex
	auth := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		mu.Lock()
		auth[r.Header.Get("Authorization")] = true
		mu.Unlock()
		h(w, r)
	}))
	defer srv.Close()
	resp, err := callOpenAI(context.Background(), newGuardedClient(true, 5e9), srv.URL, "", "m", o)
	return openAIRun{resp, err, n.Load(), auth}
}

func replyWith(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }
}

// Finding 7: the OpenAI-compatible client.
func TestOpenAIClient(t *testing.T) {
	t.Run("string content, key-less server", func(t *testing.T) {
		r := runOpenAI(t, replyWith(`{"choices":[{"finish_reason":"stop","message":{"content":"{\"a\":1}"}}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`))
		if r.err != nil || string(r.resp.JSON) != `{"a":1}` || r.resp.InputTokens != 5 || r.resp.OutputTokens != 3 {
			t.Fatalf("%+v", r)
		}
		if len(r.auth) != 1 || !r.auth[""] {
			t.Fatalf("no Authorization header may be sent without a key: %v", r.auth)
		}
	})
	t.Run("fenced json", func(t *testing.T) {
		r := runOpenAI(t, replyWith(`{"choices":[{"message":{"content":"Here:\n`+"```json\\n"+`{\"a\":1}`+"\\n```"+`"}}]}`))
		if r.err != nil || string(r.resp.JSON) != `{"a":1}` {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("content as parts", func(t *testing.T) {
		r := runOpenAI(t, replyWith(`{"choices":[{"message":{"content":[{"type":"text","text":"{\"a\":"},{"type":"text","text":"2}"}]}}]}`))
		if r.err != nil || string(r.resp.JSON) != `{"a":2}` {
			t.Fatalf("%+v", r)
		}
	})
	for name, body := range map[string]string{
		"no choices":   `{"choices":[]}`,
		"null content": `{"choices":[{"message":{"content":null}}]}`,
		"not json":     `<html>`,
		"prose only":   `{"choices":[{"message":{"content":"sorry"}}]}`,
		"length":       `{"choices":[{"finish_reason":"length","message":{"content":"{\"a\":1"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := runOpenAI(t, replyWith(body))
			if r.err == nil || (r.resp != nil && r.resp.JSON != nil) {
				t.Fatalf("accepted: %+v", r)
			}
		})
	}
	t.Run("schema 400 falls back to json_object once", func(t *testing.T) {
		r := runOpenAI(t, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(req.Body)
			if strings.Contains(string(b), `"type":"json_schema"`) {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":{"message":"response_format json_schema is not supported"}}`))
				return
			}
			w.Write([]byte(`{"choices":[{"message":{"content":"{\"a\":3}"}}]}`))
		})
		if r.err != nil || r.n != 2 || string(r.resp.JSON) != `{"a":3}` {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("unrelated 400 is not re-sent", func(t *testing.T) {
		r := runOpenAI(t, func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":{"message":"model not found"}}`))
		})
		if r.err == nil || r.n != 1 {
			t.Fatalf("%+v", r)
		}
	})
}
