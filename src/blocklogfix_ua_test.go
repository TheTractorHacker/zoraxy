package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/dynamicproxy"
)

func botEntry(env *fixEnv, ua string) blocklog.Entry {
	return env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonBot, RuleID: "bot:http_library", UA: ua,
		Detail: "http_library (challenge, no CAPTCHA, acted as block)"})
}

func explainPattern(t *testing.T, seq uint64, pattern string) blockExplanation {
	t.Helper()
	var ex blockExplanation
	jsonGet(t, HandleBlockedExplain, "/api/blocked/explain?seq="+itoa(seq)+"&pattern="+url.QueryEscape(pattern), &ex)
	return ex
}

func TestFixBotUAAllowRoundTrip(t *testing.T) {
	env := setupFixEnv(t)
	e := botEntry(env, "curl/8.18.0")
	f := explain(t, e.Seq).fix("bot-ua-allow")
	if f == nil || f.Scope != "site" || f.Site != "app.example.com" || f.Input == nil || f.Input.Value != "curl/" || f.Input.Error != "" {
		t.Fatalf("fix: %+v", f)
	}
	want := "After this: requests whose User-Agent contains \"curl/\" skip the bot rules on app.example.com only. Other sites unchanged."
	if f.Preview != want {
		t.Errorf("preview %q", f.Preview)
	}
	if !strings.Contains(f.Warning, "spoofable") || len(f.Changes) != 1 || f.Changes[0].Before != "(none)" || f.Changes[0].After != "curl/" {
		t.Errorf("warning / changes: %+v", f)
	}
	before, beforeFile := siteJSON(t, env)

	// the previewId binds the pattern: a different pattern with this preview is refused
	if r := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": f.ID, "previewId": f.PreviewID, "pattern": "curl/8"}); r["error"] == nil {
		t.Error("a pattern that differs from the preview must be refused")
	}
	if now, _ := siteJSON(t, env); now != before {
		t.Fatal("a refused fix changed the site")
	}
	res := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": f.ID, "previewId": f.PreviewID, "pattern": "curl/"})
	tok, _ := res["undoToken"].(string)
	if tok == "" {
		t.Fatalf("apply: %v", res)
	}
	ep, _ := env.router.LoadProxy("app.example.com")
	if len(ep.BotAllowUA) != 1 || ep.BotAllowUA[0] != "curl/" || ep.BotPolicy != "" {
		t.Fatalf("stored %+v policy %q", ep.BotAllowUA, ep.BotPolicy)
	}
	if explain(t, e.Seq).fix("bot-ua-allow") != nil {
		t.Error("fix still offered once the entry exists")
	}
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok}); r["ok"] != true {
		t.Fatalf("undo: %v", r)
	}
	after, afterFile := siteJSON(t, env)
	if after != before || afterFile != beforeFile {
		t.Errorf("undo did not restore the exact configuration\nbefore %s\nafter  %s", beforeFile, afterFile)
	}
	if strings.Contains(afterFile, "BotAllowUA") {
		t.Error("an emptied list must not stay in the file")
	}
}

func TestFixBotUAAllowEditedPatternAndUndoKeepsOthers(t *testing.T) {
	env := setupFixEnv(t)
	if err := mutateBotAllowUA("app.example.com", func([]string) ([]string, error) { return []string{"wget/"}, nil }); err != nil {
		t.Fatal(err)
	}
	e := botEntry(env, "python-requests/2.31.0")
	ex := explainPattern(t, e.Seq, "  Python-Requests/2 ")
	f := ex.fix("bot-ua-allow")
	if f == nil || f.Input.Error != "" || f.Input.Value != "python-requests/2" {
		t.Fatalf("%+v", f)
	}
	if f.Changes[0].Before != "wget/" || f.Changes[0].After != "wget/, python-requests/2" {
		t.Errorf("changes %+v", f.Changes)
	}
	tok, _ := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": f.ID, "previewId": f.PreviewID, "pattern": "  Python-Requests/2 "})["undoToken"].(string)
	if tok == "" {
		t.Fatal("not applied")
	}
	// a later edit of the list is kept by the undo, the entry of the fix goes
	if err := mutateBotAllowUA("app.example.com", func(l []string) ([]string, error) { return append(l, "okhttp/"), nil }); err != nil {
		t.Fatal(err)
	}
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok}); r["ok"] != true {
		t.Fatalf("undo: %v", r)
	}
	ep, _ := env.router.LoadProxy("app.example.com")
	if strings.Join(ep.BotAllowUA, ",") != "wget/,okhttp/" {
		t.Errorf("list after undo: %v", ep.BotAllowUA)
	}
	// undo refuses when the entry is already gone
	tok2, _ := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": f.ID, "previewId": explainPattern(t, e.Seq, "python-requests/").fix("bot-ua-allow").PreviewID, "pattern": "python-requests/"})["undoToken"].(string)
	if tok2 == "" {
		t.Fatal("second apply failed")
	}
	mutateBotAllowUA("app.example.com", func(l []string) ([]string, error) { return []string{"wget/"}, nil })
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok2}); r["error"] == nil {
		t.Error("undo must refuse when the entry was removed meanwhile")
	}
}

func TestFixBotUAAllowRefusesBroadAndShortPatterns(t *testing.T) {
	env := setupFixEnv(t)
	// browser-style User-Agents get no fix at all, and a note says why
	for _, ua := range []string{"Mozilla/5.0 (compatible; SomeBot/1.0)", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36", ""} {
		e := botEntry(env, ua)
		ex := explain(t, e.Seq)
		if ex.fix("bot-ua-allow") != nil {
			t.Errorf("fix offered for %q", ua)
		}
		if ua != "" && !strings.Contains(ex.Note, "Mozilla") {
			t.Errorf("no note for %q: %q", ua, ex.Note)
		}
	}
	// the product token of a Mozilla UA is never derived, so an edit cannot be applied either
	e := botEntry(env, "Mozilla/5.0 (compatible; SomeBot/1.0)")
	if r := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": "bot-ua-allow", "previewId": "x", "pattern": "mozilla"}); r["error"] == nil {
		t.Error("mozilla pattern applied")
	}
	// an editable fix with a bad pattern is listed with an error, no changes, and cannot be applied
	e = botEntry(env, "curl/8.18.0")
	for _, p := range []string{"cur", "mozilla", "chrome/", "gecko", "bot", "wget/", "x86_64"} {
		f := explainPattern(t, e.Seq, p).fix("bot-ua-allow")
		if f == nil || f.Input.Error == "" || len(f.Changes) != 0 || f.Preview != "" {
			t.Errorf("pattern %q: %+v", p, f)
			continue
		}
		r := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": f.ID, "previewId": f.PreviewID, "pattern": p})
		if r["error"] == nil {
			t.Errorf("pattern %q applied", p)
		}
	}
	if ep, _ := env.router.LoadProxy("app.example.com"); len(ep.BotAllowUA) != 0 {
		t.Errorf("a refused pattern was stored: %v", ep.BotAllowUA)
	}
}

func TestFixBotUAAllowNotForFakeBotOrSiteOff(t *testing.T) {
	env := setupFixEnv(t)
	e := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonBot, RuleID: "bot:fake-bot", UA: "Googlebot/2.1", Detail: "fake-bot"})
	if explain(t, e.Seq).fix("bot-ua-allow") != nil {
		t.Error("offered for a spoofed trusted bot")
	}
	e = botEntry(env, "curl/8")
	if err := applyNetworkingChange("app.example.com", func(x *dynamicproxy.ProxyEndpoint) error { x.BotPolicy = "off"; return nil }); err != nil {
		t.Fatal(err)
	}
	if explain(t, e.Seq).fix("bot-ua-allow") != nil {
		t.Error("offered although bot rules are off for the site")
	}
}

func TestBotAllowUAEndpoint(t *testing.T) {
	env := setupFixEnv(t)
	post := func(op, pattern string) string {
		form := url.Values{"ep": {"app.example.com"}, "op": {op}, "pattern": {pattern}}
		r := httptest.NewRequest(http.MethodPost, "/api/botrules/allowua", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		HandleBotAllowUA(w, r)
		return w.Body.String()
	}
	if got := post("add", "Curl/"); strings.Contains(got, "error") {
		t.Fatal(got)
	}
	post("add", "curl/") // duplicate: no second entry
	if got := post("add", "mozilla"); !strings.Contains(got, "error") {
		t.Error("broad pattern accepted: " + got)
	}
	ep, _ := env.router.LoadProxy("app.example.com")
	if len(ep.BotAllowUA) != 1 || ep.BotAllowUA[0] != "curl/" {
		t.Fatalf("%v", ep.BotAllowUA)
	}
	if got := post("remove", "nothere/"); !strings.Contains(got, "error") {
		t.Error("removing an unknown entry must say so")
	}
	if got := post("remove", "CURL/"); strings.Contains(got, "error") {
		t.Fatal(got)
	}
	ep, _ = env.router.LoadProxy("app.example.com")
	if ep.BotAllowUA != nil {
		t.Errorf("list not emptied: %v", ep.BotAllowUA)
	}
}
