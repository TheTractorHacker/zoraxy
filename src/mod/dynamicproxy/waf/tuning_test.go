package waf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func inspectHandler(in *Instance) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if in.Inspect(w, r, RequestInfo{Endpoint: "test", ClientIP: "203.0.113.7"}) {
			return
		}
		w.WriteHeader(200)
	})
}

// hitsOf runs one request through a detection-only WAF and returns the rule hits that were recorded
func hitsOf(t *testing.T, method, target string, body []byte, hdr map[string]string) []RuleHit {
	t.Helper()
	h, m := newTestHandler(t, &Config{Mode: ModeDetectionOnly})
	do(h, method, target, body, hdr)
	evs := m.RecentEvents(1, "")
	if len(evs) == 0 {
		return nil
	}
	var out []RuleHit
	for _, r := range evs[0].Rules {
		if r.ID != anomalyEvaluationRuleID {
			out = append(out, r)
		}
	}
	return out
}

func TestRuleHitCapturesVariable(t *testing.T) {
	cases := []struct {
		name, method, target string
		body                 []byte
		hdr                  map[string]string
		wantVar, wantNorm    string
		wantRule             int
	}{
		{"cookie", "GET", "/", nil, map[string]string{"Cookie": postHogCookie}, "REQUEST_COOKIES:ph_phc_abc123_posthog", "REQUEST_COOKIES:ph_phc_abc123_posthog", 942290},
		{"query arg", "GET", "/s?Q=%27%20OR%201%3D1--", nil, nil, "ARGS:Q", "ARGS:q", 942100},
		{"form arg", "POST", "/s", []byte("Name=%27%20OR%201%3D1--"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "ARGS:Name", "ARGS:name", 942100},
		{"json arg", "POST", "/s", []byte(`{"a":{"b":["' OR 1=1--"]}}`), map[string]string{"Content-Type": "application/json"}, "ARGS:json.a.b.0", "ARGS:json.a.b.0", 942100},
		{"header", "GET", "/", nil, map[string]string{"Referer": "http://x/?a=' OR 1=1--"}, "REQUEST_HEADERS:Referer", "REQUEST_HEADERS:referer", 942100},
	}
	for _, c := range cases {
		found := false
		for _, h := range hitsOf(t, c.method, c.target, c.body, c.hdr) {
			if h.ID == c.wantRule {
				found = true
				if h.Variable != c.wantVar || h.VarNorm != c.wantNorm {
					t.Errorf("%s: variable %q / %q, want %q / %q", c.name, h.Variable, h.VarNorm, c.wantVar, c.wantNorm)
				}
				if h.Data == "" {
					t.Errorf("%s: Data must still be filled", c.name)
				}
			}
		}
		if !found {
			t.Errorf("%s: rule %d did not match", c.name, c.wantRule)
		}
	}
}

// excludeFor builds variable exclusions that cover every rule hit of the request on the given collection
func excludeFor(t *testing.T, hits []RuleHit, path string, exact bool) []TargetExclusion {
	t.Helper()
	var out []TargetExclusion
	for _, h := range hits {
		if h.VarNorm == "" {
			continue
		}
		tgt, ok := TargetForVariable(h.Variable, false)
		if !ok {
			continue
		}
		out = append(out, TargetExclusion{RuleIDs: []string{fmt.Sprint(h.ID)}, Target: tgt, Path: path, Exact: exact})
	}
	return out
}

func TestTargetExclusionScope(t *testing.T) {
	evil := "/s?q=%27%20OR%201%3D1--%20-"
	evilOther := "/s?other=%27%20OR%201%3D1--%20-"
	if len(hitsOf(t, "GET", evil, nil, nil)) == 0 {
		t.Fatal("test payload is not detected")
	}
	ex := excludeFor(t, hitsOf(t, "GET", evil, nil, nil), "", false)
	if len(ex) == 0 {
		t.Fatal("no exclusion derived")
	}
	for _, te := range ex {
		if te.Target != "ARGS:q" {
			t.Fatalf("unexpected target %q", te.Target)
		}
	}
	h, _ := newTestHandler(t, &Config{Mode: ModeBlock, TargetExclusions: ex})
	if rec := do(h, "GET", evil, nil, nil); rec.Code != 200 {
		t.Fatalf("excluded argument still blocked: %d", rec.Code)
	}
	for name, target := range map[string]string{
		"same payload in another argument": evilOther,
		"in another argument plus q":       evil + "&other=%27%20OR%201%3D1--%20-",
	} {
		if rec := do(h, "GET", target, nil, nil); rec.Code != 403 {
			t.Errorf("%s: want 403, got %d", name, rec.Code)
		}
	}
	// the same payload in a cookie or header is not covered by the ARGS exclusion either
	if rec := do(h, "GET", "/s", nil, map[string]string{"Cookie": "q=' OR 1=1-- -"}); rec.Code != 403 {
		t.Errorf("cookie named q: want 403, got %d", rec.Code)
	}
	if rec := do(h, "GET", "/s", nil, map[string]string{"X-Q": "' OR 1=1-- -", "Referer": "http://a/?q=' OR 1=1-- -"}); rec.Code != 403 {
		t.Errorf("header: want 403, got %d", rec.Code)
	}
}

func TestTargetExclusionPathScope(t *testing.T) {
	evil := "%27%20OR%201%3D1--%20-"
	ex := excludeFor(t, hitsOf(t, "GET", "/search?q="+evil, nil, nil), "/search", true)
	h, _ := newTestHandler(t, &Config{Mode: ModeBlock, TargetExclusions: ex})
	if rec := do(h, "GET", "/search?q="+evil, nil, nil); rec.Code != 200 {
		t.Fatalf("path scoped exclusion does not apply on its path: %d", rec.Code)
	}
	for name, target := range map[string]string{
		"other path":          "/other?q=" + evil,
		"prefix of the path":  "/search/more?q=" + evil,
		"other arg same path": "/search?z=" + evil,
	} {
		if rec := do(h, "GET", target, nil, nil); rec.Code != 403 {
			t.Errorf("%s: want 403, got %d", name, rec.Code)
		}
	}
	// prefix match when Exact is false
	for i := range ex {
		ex[i].Exact = false
	}
	h2, _ := newTestHandler(t, &Config{Mode: ModeBlock, TargetExclusions: ex})
	if rec := do(h2, "GET", "/search/more?q="+evil, nil, nil); rec.Code != 200 {
		t.Errorf("prefix path scoped exclusion does not apply below the path: %d", rec.Code)
	}
	if rec := do(h2, "GET", "/other?q="+evil, nil, nil); rec.Code != 403 {
		t.Errorf("prefix path scope leaks to another path: %d", rec.Code)
	}
}

func TestTargetExclusionRegexAndCookie(t *testing.T) {
	h, _ := newTestHandler(t, &Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{
		{RuleIDs: []string{"942290"}, Target: `REQUEST_COOKIES:/^ph_.+_posthog$/`},
	}})
	if rec := do(h, "GET", "/", nil, map[string]string{"Cookie": postHogCookie}); rec.Code != 200 {
		t.Fatalf("PostHog cookie still blocked: %d", rec.Code)
	}
	// another cookie carrying the same value, and another rule on the PostHog cookie, are still caught
	other := strings.Replace(postHogCookie, "ph_phc_abc123_posthog", "session", 1)
	if rec := do(h, "GET", "/", nil, map[string]string{"Cookie": other}); rec.Code != 403 {
		t.Errorf("same value in another cookie: want 403, got %d", rec.Code)
	}
	if rec := do(h, "GET", "/", nil, map[string]string{"Cookie": "ph_phc_abc123_posthog=' UNION SELECT password FROM users-- -"}); rec.Code != 403 {
		t.Errorf("SQL injection in the PostHog cookie must still be caught by the other rules: %d", rec.Code)
	}
}

func TestTargetExclusionJSONArg(t *testing.T) {
	body := []byte(`{"comment":"' OR 1=1-- -","other":"fine"}`)
	hdr := map[string]string{"Content-Type": "application/json"}
	ex := excludeFor(t, hitsOf(t, "POST", "/api", body, hdr), "", false)
	if len(ex) == 0 || ex[0].Target != "ARGS:json.comment" {
		t.Fatalf("expected an ARGS:json.comment exclusion, got %+v", ex)
	}
	h, _ := newTestHandler(t, &Config{Mode: ModeBlock, TargetExclusions: ex})
	if rec := do(h, "POST", "/api", body, hdr); rec.Code != 200 {
		t.Fatalf("excluded JSON member still blocked: %d", rec.Code)
	}
	if rec := do(h, "POST", "/api", []byte(`{"other":"' OR 1=1-- -"}`), hdr); rec.Code != 403 {
		t.Fatalf("other JSON member must stay protected: %d", rec.Code)
	}
}

func TestTargetExclusionValidation(t *testing.T) {
	good := []string{
		"ARGS", "ARGS:q", "ARGS:json.items[0].name", "ARGS:/^json\\.items\\.\\d+\\.name$/", "ARGS_NAMES:x", "REQUEST_COOKIES:/^ph_.+_posthog$/",
		"REQUEST_COOKIES_NAMES", "REQUEST_HEADERS:Referer", "REQUEST_URI", "REQUEST_FILENAME", "REQUEST_BODY", "XML:/*", "XML", "ARGS:a_b-c.d",
	}
	for _, tg := range good {
		te := TargetExclusion{RuleIDs: []string{"942100", "942200-942299"}, Target: tg, Path: "/x"}
		if err := (&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{te}}).Validate(); err != nil {
			t.Errorf("%q rejected: %v", tg, err)
		}
	}
	bad := map[string]string{
		"quote injection":    `ARGS:x" "id:1,pass`,
		"quote":              `ARGS:x"`,
		"single quote":       `ARGS:x'`,
		"newline":            "ARGS:x\nSecRule",
		"carriage return":    "ARGS:x\rfoo",
		"semicolon":          "ARGS:x;ARGS:y",
		"comma":              "ARGS:x,ctl:ruleEngine=Off",
		"backslash newline":  "ARGS:x\\\ny",
		"action in regex":    `ARGS:/a",ctl:ruleEngine=Off,"/`,
		"macro":              "ARGS:%{tx.x}",
		"unknown collection": "TX:anomaly_score",
		"lowercase coll":     "args:x",
		"empty":              "",
		"empty selector":     "ARGS:",
		"selector on URI":    "REQUEST_URI:x",
		"bad regex":          "ARGS:/(/",
		"regex too long":     "ARGS:/" + strings.Repeat("a", 200) + "/",
		"trailing backslash": `ARGS:/abc\/`,
		"unterminated rx":    "ARGS:/abc",
		"space in name":      "ARGS:a b",
		"nul":                "ARGS:a\x00b",
		"non ascii":          "ARGS:ä",
		"ruleEngine ctl":     "ARGS:x;ctl:ruleEngine=Off",
	}
	for name, tg := range bad {
		te := TargetExclusion{RuleIDs: []string{"942100"}, Target: tg}
		if err := (&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{te}}).Validate(); err == nil {
			t.Errorf("%s: %q accepted", name, tg)
		}
		if _, err := NewManager().Get(&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{te}}); err == nil {
			t.Errorf("%s: %q compiled", name, tg)
		}
	}
	for name, te := range map[string]TargetExclusion{
		"no rule ids":    {Target: "ARGS:x"},
		"junk rule id":   {RuleIDs: []string{`942100"`}, Target: "ARGS:x"},
		"rule id name":   {RuleIDs: []string{"abc"}, Target: "ARGS:x"},
		"path no slash":  {RuleIDs: []string{"1"}, Target: "ARGS:x", Path: "x"},
		"path quote":     {RuleIDs: []string{"1"}, Target: "ARGS:x", Path: `/x" "id:1`},
		"path newline":   {RuleIDs: []string{"1"}, Target: "ARGS:x", Path: "/x\ny"},
		"path backslash": {RuleIDs: []string{"1"}, Target: "ARGS:x", Path: `/x\`},
		"path semicolon": {RuleIDs: []string{"1"}, Target: "ARGS:x", Path: "/x;y"},
	} {
		if err := (&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{te}}).Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// the policy, profile and endpoint overrides validate the field as well
	badEx := []TargetExclusion{{RuleIDs: []string{"1"}, Target: `ARGS:x" "id:1`}}
	if _, err := NewState(Policy{DefaultMode: ModeBlock, TargetExclusions: badEx}, nil); err == nil {
		t.Error("policy accepted an invalid target")
	}
	if _, err := NewState(DefaultPolicy(), []Profile{{Name: "p", Mode: ModeBlock, TargetExclusions: badEx}}); err == nil {
		t.Error("profile accepted an invalid target")
	}
	st := EmptyState()
	if err := st.ValidateSetting(Setting{Source: SourceInherit, Extra: &Overrides{TargetExclusions: badEx}}); err == nil {
		t.Error("overrides accepted an invalid target")
	}
	if err := st.ValidateSetting(Setting{Source: SourceInherit, Extra: &Overrides{TargetExclusions: []TargetExclusion{{RuleIDs: []string{"1"}, Target: "ARGS:x"}}}}); err != nil {
		t.Errorf("overrides rejected a valid target: %v", err)
	}
}

func TestTargetExclusionDirectivesAndHash(t *testing.T) {
	n := (&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{
		{RuleIDs: []string{"942290", "942100-942199"}, Target: "REQUEST_COOKIES:/^ph_.+_posthog$/"},
		{RuleIDs: []string{"942100"}, Target: "ARGS:q", Path: "/s", Exact: true},
	}}).Normalize()
	d, err := buildDirectives(n)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ctl:ruleRemoveTargetById=942290;REQUEST_COOKIES:/^ph_.+_posthog$/,ctl:ruleRemoveTargetById=942100-942199;REQUEST_COOKIES:/^ph_.+_posthog$/`,
		`SecRule REQUEST_FILENAME "@streq /s" "id:`,
	} {
		if !strings.Contains(d, want) {
			t.Errorf("directives miss %q", want)
		}
	}
	if strings.Index(d, "ruleRemoveTargetById") > strings.Index(d, "Include ") {
		t.Error("exclusions must come before the CRS includes")
	}
	a := (&Config{Mode: ModeBlock}).Hash()
	b := (&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{{RuleIDs: []string{"1"}, Target: "ARGS:x"}}}).Hash()
	c := (&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{{RuleIDs: []string{"1"}, Target: "ARGS:y"}}}).Hash()
	d2 := (&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{{RuleIDs: []string{"1"}, Target: "ARGS:y", Path: "/p"}}}).Hash()
	if a == b || b == c || c == d2 {
		t.Error("Hash must include the variable exclusions")
	}
	m := NewManager()
	i1, _ := m.Get(&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{{RuleIDs: []string{"1"}, Target: "ARGS:x"}}})
	i2, _ := m.Get(&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{{RuleIDs: []string{"1"}, Target: "ARGS:y"}}})
	if i1 == i2 {
		t.Error("instances with different variable exclusions must not share a compiled WAF")
	}
}

func TestTargetExclusionCentralMerge(t *testing.T) {
	pol := Policy{Enabled: true, DefaultMode: ModeBlock, TargetExclusions: []TargetExclusion{{RuleIDs: []string{"942290"}, Target: "ARGS:a"}}}
	prof := Profile{Name: "p", Mode: ModeBlock, TargetExclusions: []TargetExclusion{{RuleIDs: []string{"942100"}, Target: "ARGS:a"}, {RuleIDs: []string{"1"}, Target: "ARGS:b"}}}
	st, err := NewState(pol, []Profile{prof})
	if err != nil {
		t.Fatal(err)
	}
	extra := &Overrides{TargetExclusions: []TargetExclusion{{RuleIDs: []string{"942290", "2"}, Target: "ARGS:a"}, {RuleIDs: []string{"3"}, Target: "ARGS:c", Path: "/x"}}}
	r := st.Resolve(Setting{Source: SourceProfile, Profile: "p", Extra: extra})
	if r.Config == nil {
		t.Fatal("no config")
	}
	got := map[string]string{}
	for _, te := range r.Config.TargetExclusions {
		got[te.Target+"|"+te.Path] = strings.Join(te.RuleIDs, ",")
	}
	if len(r.Config.TargetExclusions) != 3 || got["ARGS:a|"] != "942290,942100,2" || got["ARGS:b|"] != "1" || got["ARGS:c|/x"] != "3" {
		t.Fatalf("merge wrong: %+v", r.Config.TargetExclusions)
	}
	if len(pol.TargetExclusions[0].RuleIDs) != 1 || len(extra.TargetExclusions[0].RuleIDs) != 2 {
		t.Fatal("merge modified its inputs")
	}
	// Policy JSON round trip
	js, _ := json.Marshal(st.Policy)
	var back Policy
	if err := json.Unmarshal(js, &back); err != nil || len(back.TargetExclusions) != 1 || back.TargetExclusions[0].Target != "ARGS:a" {
		t.Fatalf("round trip: %v %s", err, js)
	}
	// old files without the field still load, and the field is omitted when empty
	var old Policy
	if err := json.Unmarshal([]byte(`{"Enabled":true,"DefaultMode":"block"}`), &old); err != nil || len(old.TargetExclusions) != 0 {
		t.Fatal(err)
	}
	js, _ = json.Marshal(Policy{})
	if strings.Contains(string(js), "TargetExclusions") {
		t.Error("empty field must be omitted")
	}
}

/* aggregation */

func mkEvent(ep, ip, path string, ago time.Duration, wouldBlock bool, hits ...RuleHit) Event {
	return Event{Time: time.Now().Add(-ago), TransactionID: "tx-" + ip + path, Endpoint: ep, ClientIP: ip, Method: "GET", Path: path, URI: path,
		Action: "detected", WouldBlock: wouldBlock, Mode: ModeDetectionOnly, Rules: hits}
}

func TestTuningGroupingAndNormalisation(t *testing.T) {
	ph := func(id string) RuleHit {
		return RuleHit{ID: 942290, Message: "Finds basic MongoDB SQL injection attempt", Severity: "critical", Data: `{"distinct_id":"` + id + `"`,
			Variable: "REQUEST_COOKIES:ph_phc_" + id + "_posthog", VarNorm: "REQUEST_COOKIES:ph_phc_" + id + "_posthog"}
	}
	evs := []Event{
		mkEvent("a.example.com", "10.0.0.1", "/", 3*time.Minute, true, ph("aaa111"), RuleHit{ID: 949110, Message: "Inbound Anomaly Score Exceeded", Severity: "critical"}),
		mkEvent("a.example.com", "10.0.0.2", "/blog", 2*time.Minute, true, ph("bbb222")),
		mkEvent("a.example.com", "10.0.0.2", "/shop", 1*time.Minute, false, ph("ccc333")),
		// same rule on another endpoint is its own group
		mkEvent("b.example.com", "10.0.0.9", "/", 1*time.Minute, true, ph("ddd444")),
	}
	rep := BuildTuningReport(evs, "", 24)
	if rep.EventsScanned != 4 || len(rep.Items) != 2 {
		t.Fatalf("want 2 groups, got %d: %+v", len(rep.Items), rep.Items)
	}
	it := rep.Items[0]
	if it.Endpoint != "a.example.com" || it.RuleID != 942290 || it.Variable != "REQUEST_COOKIES:ph_*_posthog" {
		t.Fatalf("group wrong: %+v", it)
	}
	if it.Count != 3 || it.Clients != 2 || it.WouldBlock != 2 || it.PathCount != 3 {
		t.Errorf("counts wrong: %+v", it)
	}
	if !it.FirstSeen.Before(it.LastSeen) {
		t.Error("first/last seen wrong")
	}
	if it.Sample.Variable != "REQUEST_COOKIES:ph_phc_ccc333_posthog" || it.Sample.Data == "" {
		t.Errorf("sample should be the newest event: %+v", it.Sample)
	}
	s := it.Suggestion
	if s.Kind != "variable" || s.Target != "REQUEST_COOKIES:/^ph_.+_posthog$/" || s.Path != "" || len(s.RuleIDs) != 1 || s.RuleIDs[0] != "942290" {
		t.Errorf("suggestion wrong: %+v", s)
	}
	if it.LooksLikeAttack || it.Risk != "low" {
		t.Errorf("analytics cookie must not look like an attack: %+v", it)
	}
	if err := (TargetExclusion{RuleIDs: s.RuleIDs, Target: s.Target}).Validate(); err != nil {
		t.Errorf("suggestion does not validate: %v", err)
	}
	// the endpoint filter is applied before grouping by the manager; BuildTuningReport on one endpoint's events
	if rep := BuildTuningReport(evs[3:], "b.example.com", 24); len(rep.Items) != 1 || rep.Items[0].Endpoint != "b.example.com" {
		t.Errorf("endpoint report wrong: %+v", rep.Items)
	}
}

func TestTuningNormalizeName(t *testing.T) {
	cases := []struct{ coll, name, display, sel string }{
		{"REQUEST_COOKIES", "ph_phc_x_posthog", "ph_*_posthog", "/^ph_.+_posthog$/"},
		{"REQUEST_COOKIES", "_ga_ab12cd", "_ga_*", "/^_ga_.+$/"},
		{"REQUEST_COOKIES", "session", "session", "session"},
		{"ARGS", "json.items.12.name", "json.items.*.name", `/^json\.items\.\d+\.name$/`},
		{"ARGS", "items[3]", "items[*]", `/^items\[\d+\]$/`},
		{"ARGS", "q", "q", "q"},
		{"ARGS", "tok_0123456789abcdef", "tok_*", `/^tok_[0-9a-f]+$/`},
		{"ARGS", "a b", "a?b", "/^a.b$/"},
		{"ARGS", `x",ctl:ruleEngine=Off,"`, "x?", ""},
	}
	for _, c := range cases {
		d, sel, _ := normalizeName(c.coll, c.name)
		if c.sel == "" {
			// anything built from hostile input must still validate
			if err := ValidateTarget(c.coll + ":" + sel); err != nil {
				t.Errorf("%q: hostile name produced an invalid selector %q: %v", c.name, sel, err)
			}
			continue
		}
		if d != c.display || sel != c.sel {
			t.Errorf("%s %q: got %q / %q, want %q / %q", c.coll, c.name, d, sel, c.display, c.sel)
		}
		if err := ValidateTarget(c.coll + ":" + sel); err != nil {
			t.Errorf("%q: selector %q invalid: %v", c.name, sel, err)
		}
	}
	// the generated regex really matches the rotating names and not others
	_, sel, _ := normalizeName("ARGS", "json.items.12.name")
	if tg, ok := TargetForVariable("ARGS:json.items.7.name", true); !ok || tg != "ARGS:"+sel {
		t.Errorf("TargetForVariable collapse: %q %v", tg, ok)
	}
	if tg, ok := TargetForVariable("ARGS:json.items.7.name", false); !ok || tg != "ARGS:json.items.7.name" {
		t.Errorf("TargetForVariable exact: %q %v", tg, ok)
	}
	if tg, ok := TargetForVariable("ARGS_GET:Q", false); !ok || tg != "ARGS:q" {
		t.Errorf("TargetForVariable ARGS_GET: %q %v", tg, ok)
	}
	if _, ok := TargetForVariable("REQUEST_METHOD", false); ok {
		t.Error("REQUEST_METHOD is not excludable")
	}
	if _, ok := TargetForVariable("TX:anomaly", false); ok {
		t.Error("TX is not excludable")
	}
}

func TestTuningSuggestionsAndRisk(t *testing.T) {
	arg := func(id int, sev, name, data string) RuleHit {
		return RuleHit{ID: id, Message: "m", Severity: sev, Data: data, Variable: "ARGS:" + name, VarNorm: "ARGS:" + strings.ToLower(name)}
	}
	// single path, argument -> path scoped variable exclusion
	rep := BuildTuningReport([]Event{
		mkEvent("e", "1.1.1.1", "/search", time.Minute, true, arg(942100, "critical", "Q", "a b")),
		mkEvent("e", "1.1.1.1", "/search", time.Minute, true, arg(942100, "critical", "Q", "a c")),
	}, "", 24)
	s := rep.Items[0].Suggestion
	if s.Kind != "variable" || s.Target != "ARGS:q" || s.Path != "/search" || !s.Exact {
		t.Errorf("single path argument: %+v", s)
	}
	// several paths -> everywhere
	rep = BuildTuningReport([]Event{
		mkEvent("e", "1.1.1.1", "/a", time.Minute, true, arg(942100, "critical", "q", "x")),
		mkEvent("e", "1.1.1.2", "/b", time.Minute, true, arg(942100, "critical", "q", "x")),
	}, "", 24)
	if s := rep.Items[0].Suggestion; s.Path != "" || s.Target != "ARGS:q" {
		t.Errorf("several paths: %+v", s)
	}
	// a cookie is never path scoped, even if only one path was seen
	rep = BuildTuningReport([]Event{
		mkEvent("e", "1.1.1.1", "/", time.Minute, true, RuleHit{ID: 942290, Severity: "critical", Variable: "REQUEST_COOKIES:foo", VarNorm: "REQUEST_COOKIES:foo"}),
	}, "", 24)
	if s := rep.Items[0].Suggestion; s.Path != "" || s.Target != "REQUEST_COOKIES:foo" {
		t.Errorf("cookie: %+v", s)
	}
	// never a whole-rule suggestion while a variable is known
	for _, it := range rep.Items {
		if it.Suggestion.Kind == "rule" {
			t.Error("whole rule suggested for a known variable")
		}
	}
	// no variable, one path: path-rule; none: rule
	rep = BuildTuningReport([]Event{mkEvent("e", "1.1.1.1", "/p", time.Minute, true, RuleHit{ID: 920420, Severity: "critical"})}, "", 24)
	if s := rep.Items[0].Suggestion; s.Kind != "path-rule" || s.Path != "/p" {
		t.Errorf("path-rule: %+v", s)
	}
	rep = BuildTuningReport([]Event{
		mkEvent("e", "1.1.1.1", "/p", time.Minute, true, RuleHit{ID: 920420, Severity: "critical"}),
		mkEvent("e", "1.1.1.1", "/q", time.Minute, true, RuleHit{ID: 920420, Severity: "critical"}),
	}, "", 24)
	if s := rep.Items[0].Suggestion; s.Kind != "rule" || rep.Items[0].Risk != "high" {
		t.Errorf("rule: %+v risk %s", s, rep.Items[0].Risk)
	}
	// a variable that exists but cannot be excluded on its own falls back to the path
	rep = BuildTuningReport([]Event{mkEvent("e", "1.1.1.1", "/p", time.Minute, true, RuleHit{ID: 920180, Severity: "notice", Variable: "REQUEST_METHOD", VarNorm: "REQUEST_METHOD"})}, "", 24)
	if s := rep.Items[0].Suggestion; s.Kind != "path-rule" {
		t.Errorf("REQUEST_METHOD: %+v", s)
	}

	// attack heuristics
	rce := RuleHit{ID: 932100, Severity: "critical", Data: "; cat /etc/passwd", Variable: "ARGS:cmd", VarNorm: "ARGS:cmd"}
	rep = BuildTuningReport([]Event{mkEvent("e", "9.9.9.9", "/", time.Minute, true, rce)}, "", 24)
	if it := rep.Items[0]; !it.LooksLikeAttack || it.Risk != "high" || !strings.Contains(it.RiskNote, "command execution") {
		t.Errorf("critical RCE must look like an attack: %+v", it)
	}
	var many []Event
	payloads := []string{"' OR 1=1--", "1 UNION SELECT a,b", "admin'/*", "x; DROP TABLE y", "\" or \"\"=\""}
	for i, p := range payloads {
		many = append(many, mkEvent("e", fmt.Sprintf("8.8.8.%d", i), "/login", time.Minute, true, arg(942100, "critical", "user", p)))
	}
	if it := BuildTuningReport(many, "", 24).Items[0]; !it.LooksLikeAttack || it.Clients != 5 || it.Shapes < 3 {
		t.Errorf("many clients with different payloads must look like an attack: %+v", it)
	}
	// many clients with the same payload structure (an analytics cookie with ids) do not
	var same []Event
	for i := 0; i < 6; i++ {
		same = append(same, mkEvent("e", fmt.Sprintf("7.7.7.%d", i), fmt.Sprintf("/p%d", i), time.Minute, true,
			RuleHit{ID: 942290, Severity: "critical", Data: fmt.Sprintf(`{"distinct_id":"%08x-1234"`, i*7919+4096), Variable: "REQUEST_COOKIES:session_id", VarNorm: "REQUEST_COOKIES:session_id"}))
	}
	if it := BuildTuningReport(same, "", 24).Items[0]; it.LooksLikeAttack || it.Clients != 6 {
		t.Errorf("same-shaped payloads from many clients are not an attack signal: %+v", it)
	}
	// sorting: likely false positives come first
	mix := append(many, mkEvent("e", "1.1.1.1", "/z", time.Minute, true, arg(942100, "critical", "z", "v")))
	if first := BuildTuningReport(mix, "", 24).Items[0]; first.LooksLikeAttack {
		t.Errorf("attacks must sort after probable false positives: %+v", first)
	}
}

func TestTuningSampleIsTruncated(t *testing.T) {
	long := strings.Repeat("a", 500)
	rep := BuildTuningReport([]Event{mkEvent("e", "1.1.1.1", "/"+long, time.Minute, true, RuleHit{ID: 942100, Severity: "critical", Data: long, Variable: "ARGS:q", VarNorm: "ARGS:q"})}, "", 24)
	smp := rep.Items[0].Sample
	if len(smp.Data) > 130 || len(smp.Path) > 210 {
		t.Errorf("sample not truncated: %d %d", len(smp.Data), len(smp.Path))
	}
	// the path is too long to be used as a scope, so the suggestion must still validate
	if s := rep.Items[0].Suggestion; (TargetExclusion{RuleIDs: s.RuleIDs, Target: s.Target, Path: s.Path}).Validate() != nil {
		t.Errorf("suggestion does not validate: %+v", s)
	}
}

// The real false positive: the PostHog cookie trips CRS rule 942290. The tuning assistant must propose the
// variable scoped exclusion and applying it must make the request pass without opening anything else.
func TestTuningFixesPostHogFalsePositive(t *testing.T) {
	m := NewManager()
	in, err := m.Get(&Config{Mode: ModeBlock})
	if err != nil {
		t.Fatal(err)
	}
	h := inspectHandler(in)
	if rec := do(h, "GET", "/blog", nil, map[string]string{"Cookie": postHogCookie}); rec.Code != 403 {
		t.Fatalf("PostHog cookie not blocked (%d): the test no longer reproduces the false positive", rec.Code)
	}
	rep := m.Tuning(time.Now().Add(-time.Hour), "", 1)
	var it *TuningItem
	for i := range rep.Items {
		if rep.Items[i].RuleID == 942290 {
			it = &rep.Items[i]
		}
	}
	if it == nil {
		t.Fatalf("no suggestion for rule 942290: %+v", rep.Items)
	}
	if it.Variable != "REQUEST_COOKIES:ph_*_posthog" || it.Suggestion.Kind != "variable" || it.Suggestion.Target != "REQUEST_COOKIES:/^ph_.+_posthog$/" || it.Suggestion.Path != "" {
		t.Fatalf("unexpected suggestion: %+v", it)
	}
	if it.LooksLikeAttack || it.WouldBlock != 1 {
		t.Errorf("unexpected assessment: %+v", it)
	}
	s := it.Suggestion
	fixed, err := NewManager().Get(&Config{Mode: ModeBlock, TargetExclusions: []TargetExclusion{{RuleIDs: s.RuleIDs, Target: s.Target, Path: s.Path, Exact: s.Exact}}})
	if err != nil {
		t.Fatal(err)
	}
	fh := inspectHandler(fixed)
	if rec := do(fh, "GET", "/blog", nil, map[string]string{"Cookie": postHogCookie}); rec.Code != 200 {
		t.Fatalf("applying the suggestion did not fix the request: %d", rec.Code)
	}
	if rec := do(fh, "GET", "/blog?x=%27%20OR%201%3D1--%20-", nil, map[string]string{"Cookie": postHogCookie}); rec.Code != 403 {
		t.Fatalf("an SQL injection in an argument must still be blocked: %d", rec.Code)
	}
}
