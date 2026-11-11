package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/confhistory"
	db "imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/info/logger"
)

// fixEnv is a router with one site (app.example.com, CAPTCHA configured), an access controller, bot rules and a blocked log
type fixEnv struct {
	bl     *blocklog.Log
	router *dynamicproxy.Router
	rule   *access.AccessRule
	bots   *botrules.Engine
}

func setupFixEnv(t *testing.T) *fixEnv {
	t.Helper()
	router := setupEditTest(t)
	bl := setupBlockAPI(t)
	oldAC, oldBots := accessController, botEngine
	t.Cleanup(func() { accessController, botEngine = oldAC, oldBots })
	ac, err := access.NewAccessController(&access.Options{
		Database: sysdb, ConfigFolder: filepath.Join(CONF_FOLDER, "access"),
		TrustedProxiesFile: filepath.Join(CONF_FOLDER, "tp.json"), SkipPublicIPCheck: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	accessController = ac
	rule, err := ac.GetAccessRuleByID("default")
	if err != nil {
		t.Fatal(err)
	}
	rule.Name = "Office only"
	botEngineOnce.Do(func() {})
	botEngine = botrules.New(filepath.Join(CONF_FOLDER, "botrules.json"))
	cfg := botrules.DefaultConfig()
	cfg.Enabled = true
	cfg.Categories["http_library"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionChallenge}
	if err := botEngine.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ep, _ := router.LoadProxy("app.example.com")
	if err := SaveReverseProxyConfig(ep); err != nil {
		t.Fatal(err)
	}
	return &fixEnv{bl: bl, router: router, rule: rule, bots: botEngine}
}

func (e *fixEnv) record(en blocklog.Entry) blocklog.Entry {
	if en.Host == "" {
		en.Host = "app.example.com"
	}
	if en.Rule == "" {
		en.Rule = "app.example.com"
	}
	if en.Ref == "" {
		en.Ref = blocklog.NewRef()
	}
	en.Method, en.Status = "GET", 403
	e.bl.Record(en)
	got, ok := e.bl.GetByRef(en.Ref)
	if !ok {
		panic("not recorded")
	}
	return got
}

func jsonGet(t *testing.T, h http.HandlerFunc, target string, out interface{}) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, target, nil))
	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: %v: %s", target, err, w.Body.String())
		}
	}
	return w
}

func jsonPost(t *testing.T, h http.HandlerFunc, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	js, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(string(js)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h(w, r)
	out := map[string]interface{}{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON (%d): %s", w.Code, w.Body.String())
	}
	out["_code"] = w.Code
	return out
}

func explain(t *testing.T, seq uint64) blockExplanation {
	t.Helper()
	var ex blockExplanation
	jsonGet(t, HandleBlockedExplain, "/api/blocked/explain?seq="+itoa(seq), &ex)
	return ex
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

func (ex blockExplanation) fix(id string) *fixOption {
	for i := range ex.Fixes {
		if ex.Fixes[i].ID == id {
			return &ex.Fixes[i]
		}
	}
	return nil
}

func applyFix(t *testing.T, e blocklog.Entry, f *fixOption, all bool) map[string]interface{} {
	t.Helper()
	return jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": f.ID, "previewId": f.PreviewID, "allSites": all})
}

func siteJSON(t *testing.T, env *fixEnv) (string, string) {
	t.Helper()
	ep, err := env.router.LoadProxy("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(filepath.Join(CONF_HTTP_PROXY, "app.example.com.config"))
	if err != nil {
		t.Fatal(err)
	}
	return endpointJSON(t, ep), string(file)
}

func TestFixBotSiteOffRoundTrip(t *testing.T) {
	env := setupFixEnv(t)
	e := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonBot, RuleID: "bot:http_library", UA: "curl/8.18.0",
		Detail: "http_library (challenge, no CAPTCHA, acted as block)"})
	ex := explain(t, e.Seq)
	if !strings.Contains(ex.PlainText, "curl/8.18.0 matched the bot category Generic HTTP client libraries") ||
		!strings.Contains(ex.PlainText, "Its action is Challenge, but this site has no CAPTCHA, so it was blocked.") {
		t.Errorf("plain text: %s", ex.PlainText)
	}
	if ex.Ref != blocklog.FormatRef(e.Ref) || ex.RuleLink.Tab != "seccenter" || ex.RuleLink.Sec != "bots" || ex.RuleLink.Rule != "bot:http_library" || !ex.CanFix {
		t.Errorf("explain: %+v", ex)
	}
	// no UA exemption exists in the stores, and no CAPTCHA is set up for... this site has one, but the block was a missing one
	for _, id := range []string{"captcha-path-exempt", "captcha-ip-exempt", "access-ip-allow"} {
		if ex.fix(id) != nil {
			t.Errorf("fix %s offered for a challenge without CAPTCHA", id)
		}
	}
	f := ex.fix("bot-site-off")
	if f == nil || f.Scope != "site" || f.Site != "app.example.com" || len(f.Changes) != 1 || f.Changes[0].After != "off for this site" || !strings.Contains(f.Preview, "Other sites unchanged") {
		t.Fatalf("fix: %+v", f)
	}
	before, beforeFile := siteJSON(t, env)

	// preview first
	if r := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": f.ID}); r["error"] == nil {
		t.Error("applying without the preview id must be refused")
	}
	if r := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": f.ID, "previewId": "deadbeef"}); r["error"] == nil {
		t.Error("a wrong preview id must be refused")
	}
	if r := jsonPost(t, HandleBlockedFix, map[string]interface{}{"seq": e.Seq, "fixId": "nonsense", "previewId": f.PreviewID}); r["error"] == nil {
		t.Error("an unknown fix must be refused")
	}
	if now, _ := siteJSON(t, env); now != before {
		t.Fatal("a refused fix changed the site")
	}

	res := applyFix(t, e, f, false)
	tok, _ := res["undoToken"].(string)
	if tok == "" {
		t.Fatalf("apply: %v", res)
	}
	ep, _ := env.router.LoadProxy("app.example.com")
	if ep.BotPolicy != "off" {
		t.Fatalf("policy %q", ep.BotPolicy)
	}
	// the preview of the same fix is gone now (nothing left to change)
	if explain(t, e.Seq).fix("bot-site-off") != nil {
		t.Error("fix still offered after it was applied")
	}
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok}); r["ok"] != true {
		t.Fatalf("undo: %v", r)
	}
	after, afterFile := siteJSON(t, env)
	if after != before || afterFile != beforeFile {
		t.Errorf("undo did not restore the exact configuration\nbefore %s\nafter  %s", beforeFile, afterFile)
	}
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok}); r["error"] == nil {
		t.Error("an undo token works once")
	}
}

func TestFixUndoRefusesWhenChangedMeanwhile(t *testing.T) {
	env := setupFixEnv(t)
	e := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonBot, RuleID: "bot:http_library", UA: "curl/8", Detail: "http_library (challenge, no CAPTCHA, acted as block)"})
	f := explain(t, e.Seq).fix("bot-site-off")
	tok := applyFix(t, e, f, false)["undoToken"].(string)
	if err := applyNetworkingChange("app.example.com", func(x *dynamicproxy.ProxyEndpoint) error { x.BotPolicy = "on"; return nil }); err != nil {
		t.Fatal(err)
	}
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok}); r["error"] == nil {
		t.Error("undo must not overwrite a later change")
	}
	if ep, _ := env.router.LoadProxy("app.example.com"); ep.BotPolicy != "on" {
		t.Errorf("later change was overwritten: %q", ep.BotPolicy)
	}
}

func TestFixBotCategoryNeedsAllSitesAndRoundTrips(t *testing.T) {
	env := setupFixEnv(t)
	e := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonBot, RuleID: "bot:http_library", UA: "curl/8", Detail: "http_library (challenge, no CAPTCHA, acted as block)"})
	f := explain(t, e.Seq).fix("bot-category-log")
	if f == nil || f.Scope != "all" || !f.RequiresAllSites || f.Risk != "high" || f.Changes[0].Before != "challenge" {
		t.Fatalf("fix: %+v", f)
	}
	before := env.bots.Config()
	beforeJS, _ := json.Marshal(before)
	if r := applyFix(t, e, f, false); r["error"] == nil {
		t.Fatal("a global fix must need allSites=true")
	}
	if cur, _ := json.Marshal(env.bots.Config()); string(cur) != string(beforeJS) {
		t.Fatal("refused fix changed the config")
	}
	tok, _ := applyFix(t, e, f, true)["undoToken"].(string)
	if env.bots.Config().Categories["http_library"].Action != botrules.ActionLog {
		t.Fatal("category not changed")
	}
	// the other categories are untouched
	if env.bots.Config().Categories["scanner"] != before.Categories["scanner"] {
		t.Error("other categories changed")
	}
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok}); r["ok"] != true {
		t.Fatalf("undo: %v", r)
	}
	if !reflect.DeepEqual(env.bots.Config(), before) {
		t.Errorf("config not restored\nbefore %+v\nafter  %+v", before, env.bots.Config())
	}
	// and it was persisted
	var onDisk botrules.Config
	raw, _ := os.ReadFile(filepath.Join(CONF_FOLDER, "botrules.json"))
	json.Unmarshal(raw, &onDisk)
	if onDisk.Categories["http_library"] != before.Categories["http_library"] {
		t.Errorf("file: %+v", onDisk.Categories["http_library"])
	}
}

func TestFixAccessListRoundTrip(t *testing.T) {
	env := setupFixEnv(t)
	rule := env.rule
	rule.WhitelistEnabled = true
	e := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonWhitelist, RuleID: "access:Office only"})
	ex := explain(t, e.Seq)
	if !strings.Contains(ex.PlainText, `"Office only"`) {
		t.Errorf("text: %s", ex.PlainText)
	}
	f := ex.fix("access-ip-allow")
	if f == nil || f.Scope != "access-rule" || !strings.Contains(f.Preview, "198.51.100.5 is on the allow list") || !strings.Contains(f.Preview, "used by") {
		t.Fatalf("fix: %+v", f)
	}
	for _, id := range []string{"bot-site-off", "access-ip-unblock", "bot-category-log"} {
		if ex.fix(id) != nil {
			t.Errorf("%s must not be offered for an allow list block", id)
		}
	}
	before := snapshotMap(*rule.WhiteListIP)
	tok := applyFix(t, e, f, false)["undoToken"].(string)
	if _, ok := (*rule.WhiteListIP)["198.51.100.5"]; !ok {
		t.Fatal("not allowed")
	}
	jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok})
	if !reflect.DeepEqual(snapshotMap(*rule.WhiteListIP), before) {
		t.Errorf("allow list not restored: %v", *rule.WhiteListIP)
	}

	// blacklist: only an exact entry can be taken out
	rule.AddIPToBlackList("198.51.100.6", "spam")
	rule.AddIPToBlackList("203.0.113.0/24", "range")
	exact := env.record(blocklog.Entry{IP: "198.51.100.6", Reason: blocklog.ReasonBlacklist, RuleID: "access:Office only"})
	inRange := env.record(blocklog.Entry{IP: "203.0.113.9", Reason: blocklog.ReasonBlacklist, RuleID: "access:Office only"})
	if explain(t, inRange.Seq).fix("access-ip-unblock") != nil {
		t.Error("an address blocked through a range has no single entry to remove")
	}
	f = explain(t, exact.Seq).fix("access-ip-unblock")
	if f == nil {
		t.Fatal("no unblock fix")
	}
	beforeBL := snapshotMap(*rule.BlackListIP)
	tok = applyFix(t, exact, f, false)["undoToken"].(string)
	if _, ok := (*rule.BlackListIP)["198.51.100.6"]; ok {
		t.Fatal("still blacklisted")
	}
	if _, ok := (*rule.BlackListIP)["203.0.113.0/24"]; !ok {
		t.Fatal("the range must stay")
	}
	jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok})
	if !reflect.DeepEqual(snapshotMap(*rule.BlackListIP), beforeBL) {
		t.Errorf("blacklist (with its comment) not restored: %v", *rule.BlackListIP)
	}
	// a rule that was renamed or replaced since the block: no fix for the wrong rule
	rule.Name = "Renamed"
	if explain(t, exact.Seq).fix("access-ip-unblock") != nil {
		t.Error("the entry names another access rule than the site uses now")
	}
}

func snapshotMap(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestFixCaptchaExceptionsRoundTrip(t *testing.T) {
	env := setupFixEnv(t)
	e := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonCaptcha, Path: "/api/ping?x=1"})
	ex := explain(t, e.Seq)
	fp, fi := ex.fix("captcha-path-exempt"), ex.fix("captcha-ip-exempt")
	if fp == nil || fi == nil || fp.Scope != "site" || !strings.Contains(fp.Changes[0].After, "/api/ping") || strings.Contains(fp.Changes[0].After, "x=1") {
		t.Fatalf("fixes: %+v %+v", fp, fi)
	}
	before, beforeFile := siteJSON(t, env)
	tok := applyFix(t, e, fp, false)["undoToken"].(string)
	ep, _ := env.router.LoadProxy("app.example.com")
	if len(ep.CaptchaConfig.ExceptionRules) != 1 || ep.CaptchaConfig.ExceptionRules[0].PathPrefix != "/api/ping" || ep.CaptchaConfig.ExceptionRules[0].MatchMode != "exact" {
		t.Fatalf("rules: %+v", ep.CaptchaConfig.ExceptionRules)
	}
	if ex2 := explain(t, e.Seq); ex2.fix("captcha-path-exempt") != nil || ex2.fix("captcha-ip-exempt") == nil {
		t.Error("only the path fix is used up")
	}
	tok2 := applyFix(t, e, explain(t, e.Seq).fix("captcha-ip-exempt"), false)["undoToken"].(string)
	jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok2})
	jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok})
	after, afterFile := siteJSON(t, env)
	if after != before || afterFile != beforeFile {
		t.Errorf("exceptions not restored exactly\nbefore %s\nafter  %s", beforeFile, afterFile)
	}
	// a block that was a missing CAPTCHA gets no CAPTCHA exemption
	bot := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonBot, RuleID: "bot:http_library", Detail: "http_library (challenge, no CAPTCHA, acted as block)"})
	if explain(t, bot.Seq).fix("captcha-path-exempt") != nil {
		t.Error("offered a CAPTCHA exemption for a block without CAPTCHA")
	}
}

func TestExplainFallbacksAndOldEntries(t *testing.T) {
	env := setupFixEnv(t)
	// an entry written before refs existed: works from seq, nothing shows a reference
	env.bl.Record(blocklog.Entry{IP: "198.51.100.7", Host: "app.example.com", Rule: "app.example.com", Method: "GET", Path: "/", Status: 403, Reason: blocklog.ReasonBot, Detail: "scanner", UA: "sqlmap/1.5"})
	ex := explain(t, 1)
	if ex.Ref != "" || !strings.Contains(ex.PlainText, "Vulnerability scanners") || !strings.Contains(ex.PlainText, "Its action is Block.") {
		t.Errorf("old entry: %+v", ex)
	}
	if ex.fix("bot-site-off") == nil {
		t.Error("the site fix works without a rule key too")
	}
	// reasons without a fix: a link to the rule and a reason why
	w := env.record(blocklog.Entry{IP: "198.51.100.8", Reason: blocklog.ReasonWAF, RuleID: "waf:942100", Detail: "942100 SQL Injection Attack Detected [tx abc]"})
	ex = explain(t, w.Seq)
	if len(ex.Fixes) != 0 || ex.NoFixReason == "" || ex.RuleLink.Tab != "waf" || !strings.Contains(ex.PlainText, "942100 SQL Injection Attack Detected.") || strings.Contains(ex.PlainText, "[tx") {
		t.Errorf("waf: %+v", ex)
	}
	// a site that was deleted
	gone := env.record(blocklog.Entry{IP: "198.51.100.9", Reason: blocklog.ReasonBot, Rule: "gone.example.com", RuleID: "bot:scanner"})
	if ex := explain(t, gone.Seq); len(ex.Fixes) != 0 || ex.NoFixReason == "" {
		t.Errorf("deleted site: %+v", ex)
	}
	// every reason explains itself
	for _, ri := range blocklog.Reasons() {
		en := env.record(blocklog.Entry{IP: "198.51.100.10", Reason: ri.Key})
		if ex := explain(t, en.Seq); ex.PlainText == "" || ex.Reason.Key != ri.Key {
			t.Errorf("%s: %+v", ri.Key, ex)
		}
	}
	// not in the log (any more)
	if w := jsonGet(t, HandleBlockedExplain, "/api/blocked/explain?seq=9999", nil); !strings.Contains(w.Body.String(), "error") {
		t.Error("unknown seq")
	}
}

func TestBlockedLookup(t *testing.T) {
	env := setupFixEnv(t)
	a := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonBot})
	env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonWAF})
	env.record(blocklog.Entry{IP: "198.51.100.6", Reason: blocklog.ReasonWAF})
	var out blockLookupOut
	lookup := func(q string) {
		out = blockLookupOut{}
		jsonGet(t, HandleBlockedLookup, "/api/blocked/lookup"+q, &out)
	}
	lookup("?ref=" + url.QueryEscape(strings.ToLower(blocklog.FormatRef(a.Ref))))
	if !out.Found || out.Kind != "ref" || len(out.Entries) != 1 || out.Entries[0].Seq != a.Seq || out.Kept != 3 || !out.Enabled {
		t.Errorf("by ref: %+v", out)
	}
	lookup("?ip=198.51.100.5")
	if !out.Found || out.Kind != "ip" || out.Total != 2 {
		t.Errorf("by ip: %+v", out)
	}
	lookup("?q=" + url.QueryEscape(blocklog.FormatRef(a.Ref)))
	if !out.Found || out.Kind != "ref" {
		t.Errorf("q as ref: %+v", out)
	}
	lookup("?q=198.51.100.6")
	if !out.Found || out.Kind != "ip" || out.Total != 1 {
		t.Errorf("q as ip: %+v", out)
	}
	lookup("?ref=ZX-0000-0000")
	if out.Found || len(out.Entries) != 0 || out.Capacity == 0 {
		t.Errorf("not found must carry what the UI needs to explain it: %+v", out)
	}
	env.bl.SetEnabled(false)
	lookup("?ref=ZX-0000-0000")
	if out.Enabled {
		t.Error("logging is off and the answer must say so")
	}
	for _, bad := range []string{"?ref=hello", "?ip=999.1.1.1", "", "?ref=" + strings.Repeat("A", 100)} {
		if w := jsonGet(t, HandleBlockedLookup, "/api/blocked/lookup"+bad, nil); !strings.Contains(w.Body.String(), `"error"`) {
			t.Errorf("%q must be an error: %s", bad, w.Body.String())
		}
	}
	// the overview filter takes the reference too
	var ov struct {
		List blocklog.ListResult
	}
	jsonGet(t, HandleBlockedOverview, "/api/blocked/overview?ref="+blocklog.FormatRef(a.Ref), &ov)
	if ov.List.Total != 1 || ov.List.Items[0].Seq != a.Seq {
		t.Errorf("overview by ref: %+v", ov.List)
	}
	if w := jsonGet(t, HandleBlockedOverview, "/api/blocked/overview?ref=bad", nil); !strings.Contains(w.Body.String(), "invalid ref") {
		t.Error("bad ref filter")
	}
}

// A read-only account sees the explanation without fixes and cannot apply or undo, in the handler and at the router.
func TestFixIsAdminOnly(t *testing.T) {
	env := setupFixEnv(t)
	e := env.record(blocklog.Entry{IP: "198.51.100.5", Reason: blocklog.ReasonBot, RuleID: "bot:http_library", UA: "curl/8", Detail: "http_library (challenge, no CAPTCHA, acted as block)"})
	f := explain(t, e.Seq).fix("bot-site-off")

	oldAgent := authAgent
	t.Cleanup(func() { authAgent = oldAgent })
	sd, err := db.NewDatabase(filepath.Join(t.TempDir(), "authdb"), db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer sd.Close()
	lg, _ := logger.NewFmtLogger()
	oldProfile := auth.ProfileAdmin
	auth.ProfileAdmin = auth.PasswordProfile{MemoryKiB: 64, Time: 1, Threads: 1}
	defer func() { auth.ProfileAdmin = oldProfile }()
	authAgent = auth.NewAuthenticationAgent("t", []byte("0123456789abcdef0123456789abcdef"), sd, false, lg, nil)
	authAgent.CreateUserAccount("root", "password-1", "")
	authAgent.CreateUser("view", "password-2", auth.RoleViewer)
	login := func(user, pw string) *http.Cookie {
		form := url.Values{"username": {user}, "password": {pw}}
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		authAgent.HandleLogin(w, r)
		for _, c := range w.Result().Cookies() {
			if c.Name == authAgent.SessionName && c.Value != "" {
				return c
			}
		}
		t.Fatal("login failed")
		return nil
	}
	view, admin := login("view", "password-2"), login("root", "password-1")

	// explain: viewer reads, without fixes
	rq := httptest.NewRequest(http.MethodGet, "/api/blocked/explain?seq="+itoa(e.Seq), nil)
	rq.AddCookie(view)
	w := httptest.NewRecorder()
	HandleBlockedExplain(w, rq)
	var ex blockExplanation
	json.Unmarshal(w.Body.Bytes(), &ex)
	if ex.PlainText == "" || ex.CanFix || len(ex.Fixes) != 0 {
		t.Errorf("viewer explain: %+v", ex)
	}
	// fix and undo: refused with 403, nothing changed
	body, _ := json.Marshal(map[string]interface{}{"seq": e.Seq, "fixId": f.ID, "previewId": f.PreviewID})
	for _, h := range []http.HandlerFunc{HandleBlockedFix, HandleBlockedUndo} {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(view)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("viewer got %d", w.Code)
		}
	}
	if ep, _ := env.router.LoadProxy("app.example.com"); ep.BotPolicy != "" {
		t.Fatal("a viewer changed the site")
	}
	// the same request as an admin works
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(admin)
	w = httptest.NewRecorder()
	HandleBlockedFix(w, r)
	if !strings.Contains(w.Body.String(), "undoToken") {
		t.Errorf("admin: %d %s", w.Code, w.Body.String())
	}

	// and through the managed router, where the audit of all mutating routes lives
	mux := http.NewServeMux()
	rt := auth.NewManagedHTTPRouter(auth.RouterOption{AuthAgent: authAgent, RequireAuth: true, TargetMux: mux})
	RegisterBlockedAPIs(rt)
	for _, ep := range []string{"/api/blocked/fix", "/api/blocked/undo"} {
		r := httptest.NewRequest(http.MethodPost, ep, strings.NewReader("a=b"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(view)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("router: viewer POST %s = %d", ep, w.Code)
		}
	}
	for _, ep := range []string{"/api/blocked/lookup?ref=ZX-0000-0000", "/api/blocked/explain?seq=1"} {
		r := httptest.NewRequest(http.MethodGet, ep, nil)
		r.AddCookie(view)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("router: viewer GET %s = %d", ep, w.Code)
		}
	}
}

func TestFixIsRecordedInTheHistory(t *testing.T) {
	for path, want := range map[string]string{"/api/blocked/fix": "Fix applied via Blocked drawer", "/api/blocked/undo": "Fix undone via Blocked drawer"} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		if got := confhistory.Summary(r); !strings.HasPrefix(got, want) {
			t.Errorf("%s summary %q", path, got)
		}
		if confhistory.SkipPath(path) || !confhistory.Mutating(r.Method) {
			t.Errorf("%s must create a history version", path)
		}
	}
}

func TestUndoTokensExpireAndAreBounded(t *testing.T) {
	called := 0
	tok := blockUndoAdd(&blockUndoEntry{label: "x", undo: func() error { called++; return nil }})
	blockUndos.Lock()
	blockUndos.m[tok].expires = blockUndos.m[tok].expires.Add(-25 * 60 * 60 * 1e9)
	blockUndos.Unlock()
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": tok}); r["error"] == nil || called != 0 {
		t.Errorf("an expired token must not undo: %v", r)
	}
	for i := 0; i < blockUndoMax+20; i++ {
		blockUndoAdd(&blockUndoEntry{undo: func() error { return nil }})
	}
	blockUndos.Lock()
	n := len(blockUndos.m)
	blockUndos.Unlock()
	if n > blockUndoMax {
		t.Errorf("%d tokens kept", n)
	}
	if r := jsonPost(t, HandleBlockedUndo, map[string]interface{}{"undoToken": ""}); r["error"] == nil {
		t.Error("empty token")
	}
}
