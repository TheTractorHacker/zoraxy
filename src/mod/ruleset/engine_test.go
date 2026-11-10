package ruleset

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestActionValidation(t *testing.T) {
	long := strings.Repeat("a", MaxBodyLen+1)
	bad := map[string]Action{
		"empty type":               {},
		"unknown type":             {Type: "explode"},
		"block 200":                {Type: ActBlock, Status: 200},
		"block 302":                {Type: ActBlock, Status: 302},
		"block 600":                {Type: ActBlock, Status: 600},
		"block body too long":      {Type: ActBlock, Body: long},
		"block with url":           {Type: ActBlock, URL: "/x"},
		"allow with status":        {Type: ActAllow, Status: 403},
		"allow with body":          {Type: ActAllow, Body: "x"},
		"log with tag":             {Type: ActLog, Tag: "x"},
		"challenge ttl 0 ok? no":   {Type: ActChallenge, TTLMinutes: 5000},
		"skip empty":               {Type: ActSkip},
		"skip unknown":             {Type: ActSkip, Skip: []string{"everything"}},
		"skip duplicate":           {Type: ActSkip, Skip: []string{"waf", "waf"}},
		"rate zero":                {Type: ActRateLimit},
		"rate huge":                {Type: ActRateLimit, Rate: 1 << 40},
		"rate bad status":          {Type: ActRateLimit, Rate: 5, Status: 200},
		"redirect status":          {Type: ActRedirect, Status: 200, URL: "/x"},
		"redirect no url":          {Type: ActRedirect},
		"redirect javascript":      {Type: ActRedirect, URL: "javascript:alert(1)"},
		"redirect data":            {Type: ActRedirect, URL: "data:text/html,x"},
		"redirect ftp":             {Type: ActRedirect, URL: "ftp://x.example/"},
		"redirect protocol rel":    {Type: ActRedirect, URL: "//evil.example/"},
		"redirect backslash":       {Type: ActRedirect, URL: "/\\evil.example"},
		"redirect bare host":       {Type: ActRedirect, URL: "example.com/x"},
		"redirect crlf":            {Type: ActRedirect, URL: "https://a.example/\r\nSet-Cookie: x=y"},
		"redirect crlf encoded ok": {Type: ActRedirect, URL: "https://a.example/\nx"},
		"redirect space":           {Type: ActRedirect, URL: "https://a.example/a b"},
		"redirect unknown ph":      {Type: ActRedirect, URL: "https://a.example/{secret}"},
		"redirect creds":           {Type: ActRedirect, URL: "https://user@a.example/"},
		"redirect creds 2":         {Type: ActRedirect, URL: "https://a.example@evil.example/"},
		"redirect query in host":   {Type: ActRedirect, URL: "https://a{query}.example/"},
		"redirect path before dom": {Type: ActRedirect, URL: "https://{path}.evil.example/"},
		"redirect no host":         {Type: ActRedirect, URL: "https:///x"},
		"redirect too long":        {Type: ActRedirect, URL: "/" + strings.Repeat("a", MaxURLLen)},
		"redirect nul":             {Type: ActRedirect, URL: "/a\x00b"},
		"redirect unicode":         {Type: ActRedirect, URL: "/café"},
		"header name space":        {Type: ActSetReqH, Name: "X Bad", Value: "v"},
		"header name colon":        {Type: ActSetReqH, Name: "X:Bad", Value: "v"},
		"header name crlf":         {Type: ActSetReqH, Name: "X-Bad\r\nX-Evil", Value: "v"},
		"header value crlf":        {Type: ActSetReqH, Name: "X-Ok", Value: "v\r\nSet-Cookie: a=b"},
		"header value lf":          {Type: ActSetRespH, Name: "X-Ok", Value: "v\nx"},
		"header value nul":         {Type: ActSetRespH, Name: "X-Ok", Value: "v\x00"},
		"header value 8bit":        {Type: ActSetRespH, Name: "X-Ok", Value: "café"},
		"header value empty":       {Type: ActSetReqH, Name: "X-Ok"},
		"header value long":        {Type: ActSetReqH, Name: "X-Ok", Value: strings.Repeat("a", MaxValueLen+1)},
		"set host":                 {Type: ActSetReqH, Name: "Host", Value: "evil"},
		"set content-length":       {Type: ActSetReqH, Name: "content-length", Value: "0"},
		"set transfer-encoding":    {Type: ActSetReqH, Name: "Transfer-Encoding", Value: "chunked"},
		"set xff":                  {Type: ActSetReqH, Name: "X-Forwarded-For", Value: "1.1.1.1"},
		"remove xff":               {Type: ActDelReqH, Name: "x-forwarded-for"},
		"set real ip":              {Type: ActSetReqH, Name: "X-Real-IP", Value: "1.1.1.1"},
		"resp set-cookie":          {Type: ActSetRespH, Name: "Set-Cookie", Value: "a=b"},
		"resp location":            {Type: ActSetRespH, Name: "Location", Value: "/"},
		"remove with value":        {Type: ActDelReqH, Name: "X-A", Value: "v"},
		"tag bad":                  {Type: ActTag, Tag: "Bad Tag"},
		"tag empty":                {Type: ActTag},
		"tag long":                 {Type: ActTag, Tag: strings.Repeat("a", 33)},
		"tag crlf":                 {Type: ActTag, Tag: "a\nb"},
	}
	for name, a := range bad {
		if name == "challenge ttl 0 ok? no" {
			a.TTLMinutes = 5000
		}
		if err := a.Validate(); err == nil {
			t.Errorf("%s: %+v should be rejected", name, a)
		}
	}
	good := []Action{
		{Type: ActAllow}, {Type: ActLog}, {Type: ActBlock}, {Type: ActBlock, Status: 429, Body: "slow down", ReportAbuse: true},
		{Type: ActChallenge}, {Type: ActChallenge, TTLMinutes: 60},
		{Type: ActSkip, Skip: []string{"waf", "rate_limit", "auth", "captcha", "rules"}},
		{Type: ActRateLimit, Rate: 10}, {Type: ActRateLimit, Rate: 10, Burst: 50, Status: 503},
		{Type: ActRedirect, URL: "https://example.com/"}, {Type: ActRedirect, Status: 308, URL: "http://{host}{uri}"},
		{Type: ActRedirect, URL: "https://example.com{path}?q={query}"}, {Type: ActRedirect, URL: "{scheme}://www.{host}{uri}"},
		{Type: ActRedirect, URL: "/login?next={path}"},
		{Type: ActSetReqH, Name: "X-Edge", Value: "a b\tc"}, {Type: ActDelReqH, Name: "X-Edge"},
		{Type: ActSetRespH, Name: "Strict-Transport-Security", Value: "max-age=31536000"}, {Type: ActDelRespH, Name: "Server"},
		{Type: ActTag, Tag: "suspicious:scan-1.0"},
	}
	for _, a := range good {
		if err := a.Validate(); err != nil {
			t.Errorf("%+v rejected: %v", a, err)
		}
	}
}

func TestRedirectExpansionIsSafe(t *testing.T) {
	mk := func(host, target string) *Action { return &Action{Type: ActRedirect, URL: target} }
	cases := []struct {
		tpl, host, target, want string
	}{
		{"https://example.com{uri}", "a.example", "/p?q=1", "https://example.com/p?q=1"},
		{"/go{path}", "a.example", "/p", "/go/p"},
		{"/{path}", "a.example", "//evil.example/x", "/evil.example/x"}, // leading slashes collapse: cannot become //host
		{"{path}", "a.example", "/x", ""},                               // invalid template, see below
		{"https://{host}/x", "a.example:8080", "/", "https://a.example:8080/x"},
		{"https://{host}/x", "a.example/@evil.example", "/", "https://a.exampleevil.example/x"}, // host reduced to host characters
		{"https://example.com/?q={query}", "a.example", "/", "https://example.com/?q="},
		{"https://example.com/?q={query}", "a.example", "/?x=1&y=<script>\"", "https://example.com/?q=x=1&y=%3Cscript%3E%22"},
	}
	for _, c := range cases {
		a := mk(c.host, c.tpl)
		if c.want == "" {
			if a.Validate() == nil {
				t.Errorf("%q should be an invalid template", c.tpl)
			}
			continue
		}
		if err := a.Validate(); err != nil {
			t.Errorf("%q: %v", c.tpl, err)
			continue
		}
		r := httptest.NewRequest("GET", "http://x"+strings.Replace(c.target, "<script>", "%3Cscript%3E", 1), nil)
		r.Host = c.host
		r.URL.Path = strings.SplitN(c.target, "?", 2)[0]
		r.URL.RawPath = ""
		r.URL.RawQuery = ""
		if i := strings.Index(c.target, "?"); i >= 0 {
			r.URL.RawQuery = c.target[i+1:]
		}
		got := a.RedirectTarget(r)
		if got != c.want {
			t.Errorf("%q host=%q target=%q\n got  %q\n want %q", c.tpl, c.host, c.target, got, c.want)
		}
		if strings.ContainsAny(got, "\r\n \"<>") {
			t.Errorf("unsafe characters in %q", got)
		}
	}
}

func newPersisted(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ruleset")
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return e, dir
}

func in(name, expr string, a Action) RuleInput {
	f := false
	return RuleInput{Name: name, Expression: expr, Action: a, DryRun: &f}
}

func TestEngineCRUDAndPersistence(t *testing.T) {
	e, dir := newPersisted(t)
	if e.Active() {
		t.Fatal("empty engine is active")
	}
	if _, err := e.SaveList(List{Name: "office", Type: ListIP, Items: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	r1, err := e.Create("", in("one", `http.path == "/1" and ip.src in $office`, Action{Type: ActBlock}), -1)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := e.Create("", in("two", `http.path == "/2"`, Action{Type: ActLog}), 0) // inserted first
	s1, err := e.Create("app.example.com", in("site", `http.host == "app.example.com"`, Action{Type: ActTag, Tag: "x"}), -1)
	if err != nil {
		t.Fatal(err)
	}
	if rs := e.Rules(""); len(rs) != 2 || rs[0].ID != r2.ID || rs[1].ID != r1.ID {
		t.Fatalf("order: %+v", rs)
	}
	// new rules are log-only by default
	d, _ := e.Create("", RuleInput{Name: "default dry", Expression: `req.size > 1`, Action: Action{Type: ActBlock}}, -1)
	if !d.DryRun || !d.Enabled {
		t.Fatalf("defaults: %+v", d)
	}
	e.Delete("", d.ID)

	for _, f := range []string{"global.json", "lists.json", filepath.Join("sites", "app.example.com.json")} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s not written: %v", f, err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode().Perm())
		}
	}
	// no temp files left behind
	ents, _ := os.ReadDir(dir)
	for _, en := range ents {
		if strings.HasSuffix(en.Name(), ".tmp") {
			t.Errorf("stray temp file %s", en.Name())
		}
	}

	// reload from disk
	e2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rs := e2.Rules(""); len(rs) != 2 || rs[0].ID != r2.ID || rs[1].Expression != `http.path == "/1" and ip.src in $office` {
		t.Fatalf("reload: %+v", rs)
	}
	if rs := e2.Rules("app.example.com"); len(rs) != 1 || rs[0].ID != s1.ID {
		t.Fatalf("site reload: %+v", rs)
	}
	if ls := e2.Lists(); len(ls) != 1 || ls[0].Name != "office" {
		t.Fatalf("lists reload: %+v", ls)
	}
	if !e2.Active() {
		t.Fatal("reloaded engine inactive")
	}

	// update keeps id / created, replaces the rest, keeps enabled when omitted
	e.SetEnabled("", r1.ID, false)
	up, err := e.Update("", r1.ID, in("one renamed", `http.path == "/1b"`, Action{Type: ActBlock, Status: 404}))
	if err != nil || up.ID != r1.ID || up.Created != r1.Created || up.Name != "one renamed" {
		t.Fatalf("update: %+v %v", up, err)
	}
	// "in" sets DryRun explicitly false and Enabled nil -> stays disabled
	if up.Enabled {
		t.Fatal("omitted enabled must keep the old value")
	}
	if _, err := e.Update("", "nope", in("x", `req.size > 1`, Action{Type: ActLog})); err == nil {
		t.Fatal("unknown id")
	} else if _, ok := err.(ErrNotFound); !ok {
		t.Fatalf("error type %T", err)
	}
	// tree input
	tn, _ := ParseTreeJSON([]byte(`{"type":"or","children":[{"field":"http.path","op":"eq","value":"/t"},{"field":"ip.is_private","op":"eq","value":true}]}`))
	tr, err := e.Create("", RuleInput{Name: "tree", Tree: tn, Action: Action{Type: ActLog}}, -1)
	if err != nil || tr.Expression != `http.path == "/t" or ip.is_private == true` {
		t.Fatalf("tree create: %+v %v", tr, err)
	}
	// both given / neither
	if _, err := e.Create("", RuleInput{Name: "x", Expression: "req.size > 1", Tree: tn, Action: Action{Type: ActLog}}, -1); err == nil {
		t.Fatal("expression and tree together")
	}
	if _, err := e.Create("", RuleInput{Name: "x", Action: Action{Type: ActLog}}, -1); err == nil {
		t.Fatal("no expression")
	}
	// invalid things are rejected and nothing is written
	before, _ := os.ReadFile(filepath.Join(dir, "global.json"))
	for _, bad := range []RuleInput{
		in("", `req.size > 1`, Action{Type: ActLog}),
		in(strings.Repeat("n", MaxNameLen+1), `req.size > 1`, Action{Type: ActLog}),
		in("bad expr", `http.path ==`, Action{Type: ActLog}),
		in("bad action", `req.size > 1`, Action{Type: ActBlock, Status: 200}),
		in("bad list", `ip.src in $missing`, Action{Type: ActLog}),
	} {
		if _, err := e.Create("", bad, -1); err == nil {
			t.Errorf("accepted %+v", bad)
		} else if _, ok := err.(ValidationError); !ok {
			t.Errorf("error type %T for %+v", err, bad)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "global.json"))
	if string(before) != string(after) {
		t.Fatal("a rejected change modified the file")
	}
	// delete the last site rule removes the file
	if err := e.Delete("app.example.com", s1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sites", "app.example.com.json")); !os.IsNotExist(err) {
		t.Fatal("empty site file not removed")
	}
}

func TestEngineLimits(t *testing.T) {
	e := NewMemory()
	for i := 0; i < MaxRulesPerSet; i++ {
		if _, err := e.Create("", in(fmt.Sprintf("r%d", i), `req.size > 1`, Action{Type: ActLog}), -1); err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
	}
	if _, err := e.Create("", in("one too many", `req.size > 1`, Action{Type: ActLog}), -1); err == nil {
		t.Fatal("per-set limit")
	}
	if _, err := e.Create("other", in("fine", `req.size > 1`, Action{Type: ActLog}), -1); err != nil {
		t.Fatalf("other sets have their own limit: %v", err)
	}
	for i := 0; i < MaxLists; i++ {
		if _, err := e.SaveList(List{Name: fmt.Sprintf("l%d", i), Type: ListString, Items: []string{"a"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.SaveList(List{Name: "toomany", Type: ListString, Items: []string{"a"}}); err == nil {
		t.Fatal("list count limit")
	}
	items := make([]string, MaxListItems+1)
	for i := range items {
		items[i] = fmt.Sprint(i)
	}
	if _, err := e.SaveList(List{Name: "l1", Type: ListString, Items: items}); err == nil {
		t.Fatal("list item limit")
	}
}

func TestListValidationAndTypes(t *testing.T) {
	e := NewMemory()
	bad := []List{
		{Name: "Bad Name", Type: ListIP},
		{Name: "x", Type: "numbers"},
		{Name: "x", Type: ListIP, Items: []string{"not an ip"}},
		{Name: "x", Type: ListIP, Items: []string{"10.0.0.0/33"}},
		{Name: "x", Type: ListCountry, Items: []string{"usa"}},
		{Name: "x", Type: ListCountry, Items: []string{"us"}},
		{Name: "x", Type: ListString, Items: []string{"a\nb"}},
		{Name: "x", Type: ListString, Items: []string{""}},
		{Name: "x", Type: ListString, Items: []string{strings.Repeat("a", MaxListItemLen+1)}},
	}
	for _, l := range bad {
		if _, err := e.SaveList(l); err == nil {
			t.Errorf("accepted %+v", l)
		}
	}
	e.SaveList(List{Name: "ips", Type: ListIP, Items: []string{"10.0.0.1", "10.0.0.0/8", "::1", "2001:db8::/32"}})
	e.SaveList(List{Name: "cc", Type: ListCountry, Items: []string{"CN", "RU"}})
	e.SaveList(List{Name: "strs", Type: ListString, Items: []string{"A", "b"}})
	e.Create("", in("uses cc", `ip.country in $cc`, Action{Type: ActLog}), -1)
	// changing a list's type under a rule that uses it is refused
	if _, err := e.SaveList(List{Name: "cc", Type: ListIP, Items: []string{"1.1.1.1"}}); err == nil {
		t.Fatal("type change under a rule must be refused")
	}
	// a string list is usable with ip.country; strings with http.host; case matters
	if _, err := e.Create("", in("cc as strings", `ip.country in $strs`, Action{Type: ActLog}), -1); err != nil {
		t.Fatal(err)
	}
	x, _ := Parse(`http.header["x"] in $strs`)
	if err := x.Link(listMap(e.Lists())); err != nil {
		t.Fatal(err)
	}
	if !x.Eval(&Env{R: mkReq("GET", "/", map[string]string{"X": "b"}), ClientIP: "1.1.1.1"}) || x.Eval(&Env{R: mkReq("GET", "/", map[string]string{"X": "B"}), ClientIP: "1.1.1.1"}) {
		t.Fatal("string list matching is exact and case sensitive")
	}
	if err := e.DeleteList("cc"); err == nil || !strings.Contains(err.Error(), "uses cc") {
		t.Fatalf("delete in use: %v", err)
	}
	if err := e.DeleteList("nope"); err == nil {
		t.Fatal("unknown list")
	}
}

func TestLoadBadFilesIsSafe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ruleset")
	os.MkdirAll(filepath.Join(dir, "sites"), 0o700)
	os.WriteFile(filepath.Join(dir, "global.json"), []byte(`{"version":1,"rules":[
		{"id":"a","name":"ok","enabled":true,"expression":"http.path == \"/ok\"","action":{"type":"block"}},
		{"id":"b","name":"bad expr","enabled":true,"expression":"http.path ==","action":{"type":"block"}},
		{"id":"c","name":"bad action","enabled":true,"expression":"req.size > 1","action":{"type":"set_request_header","name":"Host","value":"x"}},
		{"id":"d","name":"bad list","enabled":true,"expression":"ip.src in $gone","action":{"type":"block"}},
		{"id":"a","name":"duplicate id","enabled":true,"expression":"req.size > 1","action":{"type":"log"}}]}`), 0o600)
	os.WriteFile(filepath.Join(dir, "lists.json"), []byte(`{not json`), 0o600)
	os.WriteFile(filepath.Join(dir, "sites", "x.json"), []byte(`{"version":1,"site":"y","rules":[]}`), 0o600) // name mismatch
	os.WriteFile(filepath.Join(dir, "sites", "..%2f..%2fetc.json"), []byte(`{"version":1,"site":"../../etc","rules":[{"id":"z","name":"z","enabled":true,"expression":"req.size > 1","action":{"type":"log"}}]}`), 0o600)
	e, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.LoadErrors) < 2 {
		t.Errorf("load errors: %v", e.LoadErrors)
	}
	rs := e.Rules("")
	if len(rs) != 5 {
		t.Fatalf("rules: %d", len(rs))
	}
	active := 0
	for _, r := range rs {
		if r.Error == "" {
			active++
		} else if r.Name == "ok" {
			t.Errorf("good rule marked broken: %s", r.Error)
		}
	}
	if active != 2 { // "ok" and the renamed-id duplicate
		t.Errorf("active rules: %d", active)
	}
	ids := map[string]bool{}
	for _, r := range rs {
		if ids[r.ID] {
			t.Errorf("duplicate id %s survived", r.ID)
		}
		ids[r.ID] = true
	}
	// the odd site name round-trips to a safe file name
	if got := siteFileName("../../etc"); strings.ContainsAny(got, "/\\") || strings.HasPrefix(got, ".") {
		t.Errorf("unsafe file name %q", got)
	}
	if got, _ := siteFromFileName(siteFileName("*.example.com")); got != "*.example.com" {
		t.Errorf("site name round trip: %q", got)
	}
}

func TestValidateEndpointResult(t *testing.T) {
	e := NewMemory()
	e.SaveList(List{Name: "office", Type: ListIP, Items: []string{"10.0.0.0/8"}})
	v := e.Validate(ValidateInput{Expression: `http.path starts_with "/a"   and ip.src in $office`})
	if !v.OK || v.Text != `http.path starts_with "/a" and ip.src in $office` || v.Tree == nil || strings.Join(v.Fields, ",") != "http.path,ip.src" || strings.Join(v.Lists, ",") != "office" {
		t.Fatalf("%+v", v)
	}
	v = e.Validate(ValidateInput{Expression: `http.path starts_with`})
	if v.OK || len(v.Errors) != 1 || v.Errors[0].Pos == 0 && v.Errors[0].End == 0 {
		t.Fatalf("%+v", v)
	}
	v = e.Validate(ValidateInput{Expression: `ip.src in $nope`})
	if v.OK || !strings.Contains(v.Errors[0].Msg, "unknown list") {
		t.Fatalf("%+v", v)
	}
	v = e.Validate(ValidateInput{Expression: `ip.is_private`, Action: &Action{Type: ActBlock, Status: 200}})
	if v.OK || v.ActionError == "" {
		t.Fatalf("%+v", v)
	}
	v = e.Validate(ValidateInput{})
	if v.OK {
		t.Fatal("empty input")
	}
	v = e.Validate(ValidateInput{Expression: `http.path == "/a/"`})
	if !v.OK || len(v.Warnings) == 0 {
		t.Fatalf("warnings: %+v", v)
	}
	js, _ := json.Marshal(v)
	if !strings.Contains(string(js), `"warnings"`) {
		t.Fatal("json shape")
	}
}

func TestTesterTraceAndNoSideEffects(t *testing.T) {
	e := NewMemory()
	e.Country = func(string) string { return "DE" }
	e.SaveList(List{Name: "office", Type: ListIP, Items: []string{"10.0.0.0/8"}})
	e.Create("", in("tag scanner", `lower(http.user_agent) contains "scan"`, Action{Type: ActTag, Tag: "scanner"}), -1)
	e.Create("", in("hdr", `http.path starts_with "/a"`, Action{Type: ActSetRespH, Name: "X-A", Value: "1"}), -1)
	e.Create("", RuleInput{Name: "dry block", Expression: `http.path starts_with "/admin"`, Action: Action{Type: ActBlock}}, -1)
	off, _ := e.Create("", in("off", `req.size > 0`, Action{Type: ActBlock}), -1)
	e.SetEnabled("", off.ID, false)
	e.Create("", in("block abroad", `http.path starts_with "/admin" and ip.country != "US" and ip.src not in $office`, Action{Type: ActBlock, Status: 451}), -1)
	e.Create("", in("after", `http.path starts_with "/admin"`, Action{Type: ActRedirect, URL: "/x"}), -1)
	e.Create("site.test", in("site rule", `http.host == "site.test"`, Action{Type: ActLog}), -1)

	res := e.Test(TestInput{Site: "site.test", Method: "get", URL: "https://site.test/admin/users?id=1", Headers: map[string]string{"User-Agent": "Scanner/2"}, ClientIP: "203.0.113.9"})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if res.Decision != "block" || res.DecidedBy == nil || res.DecidedBy.Name != "block abroad" || !strings.Contains(res.Effect, "451") {
		t.Fatalf("decision: %+v", res)
	}
	if strings.Join(res.Tags, ",") != "scanner" || len(res.RespHeader) != 1 {
		t.Fatalf("effects: %+v", res)
	}
	byName := map[string]TestRule{}
	for _, r := range res.Rules {
		byName[r.Name] = r
	}
	if r := byName["dry block"]; !r.Matched || !strings.Contains(r.Note, "log-only") {
		t.Fatalf("dry-run rule: %+v", r)
	}
	if r := byName["off"]; r.Evaluated || r.Note != "disabled" {
		t.Fatalf("disabled rule: %+v", r)
	}
	if r := byName["after"]; r.Evaluated || r.Note != "not reached" {
		t.Fatalf("rule after the decision: %+v", r)
	}
	if r := byName["site rule"]; r.Evaluated || r.Scope != "site" {
		t.Fatalf("site rule after the decision: %+v", r)
	}
	// trace holds a truth value for every condition, no short circuit
	tr := byName["block abroad"].Trace
	if len(tr) != 4 || !tr[0].Result || tr[0].Text != "all of" {
		t.Fatalf("trace: %+v", tr)
	}
	conds := 0
	for _, en := range tr[1:] {
		conds++
		if !en.Result || en.Actual == "" {
			t.Errorf("trace entry %+v", en)
		}
	}
	if res.Fields["http.path"] != "/admin/users" || res.Fields["ip.country"] != "DE" || res.Fields["http.scheme"] != "https" {
		t.Fatalf("fields: %+v", res.Fields)
	}
	// nothing was counted
	for _, ri := range e.Rules("") {
		if ri.Stats.Hits+ri.Stats.DryRun != 0 {
			t.Errorf("tester counted a hit: %+v", ri)
		}
	}
	if len(e.RecentHits()) != 0 {
		t.Error("tester recorded recent hits")
	}
	// a US office client is not blocked
	res = e.Test(TestInput{URL: "http://x/admin", ClientIP: "10.1.1.1", Country: "us"})
	if res.Decision != "redirect" || !strings.Contains(res.Effect, "/x") {
		t.Fatalf("second request: %+v", res)
	}
	// draft expression
	res = e.Test(TestInput{URL: "/p?x=1", Expression: `http.query_arg["x"] == "1"`})
	if len(res.Rules) != 1 || !res.Rules[0].Matched || res.Rules[0].Scope != "draft" {
		t.Fatalf("draft: %+v", res)
	}
	// bad requests
	for _, bad := range []TestInput{{URL: "http://[::1"}, {Method: "GE T"}, {Headers: map[string]string{"X\n": "a"}}, {Headers: map[string]string{"X": "a\r\nb"}}} {
		if r := e.Test(bad); r.Error == "" {
			t.Errorf("accepted %+v", bad)
		}
	}
	// the tester honours allow
	e.Create("", in("allow first? no: appended", `http.path == "/ok"`, Action{Type: ActAllow}), 0)
	res = e.Test(TestInput{URL: "/ok"})
	if res.Decision != "allow" {
		t.Fatalf("%+v", res)
	}
}

func TestConcurrentUse(t *testing.T) {
	e := NewMemory()
	e.Create("", in("a", `http.path starts_with "/a"`, Action{Type: ActLog}), -1)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", "/abc", nil)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if run := e.Begin(&Env{R: r, ClientIP: "1.1.1.1"}, "s"); run != nil {
					for m := run.Next(); m != nil; m = run.Next() {
					}
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		ri, err := e.Create("s", in(fmt.Sprintf("n%d", i), `http.path == "/abc"`, Action{Type: ActLog}), -1)
		if err != nil {
			t.Fatal(err)
		}
		e.SetEnabled("s", ri.ID, i%2 == 0)
		e.Rules("s")
	}
	close(stop)
	wg.Wait()
	// counters stay bounded: stats entries are dropped with their rules
	for _, ri := range e.Rules("s") {
		e.Delete("s", ri.ID)
	}
	n := 0
	e.stats.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Errorf("stats entries leaked: %d", n)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(1, 3)
	ok := 0
	for i := 0; i < 10; i++ {
		if l.Allow() {
			ok++
		}
	}
	if ok != 3 {
		t.Errorf("burst: %d", ok)
	}
}

func TestHourlyBuckets(t *testing.T) {
	var s ruleStats
	now := int64(1_700_000_000)
	s.hit(false, now)
	s.hit(false, now+10)
	s.hit(true, now-3600*5)
	s.hit(false, now-3600*30) // older than 24h: not shown
	v := s.view(now)
	if v.Hits != 3 || v.DryRun != 1 || v.Last24h != 3 || v.Hourly[23] != 2 || v.Hourly[18] != 1 {
		t.Fatalf("%+v", v)
	}
	// the bucket for an old hour is reused without carrying its count
	s.hit(false, now+3600*24)
	v = s.view(now + 3600*24)
	if v.Hourly[23] != 1 || v.Last24h != 1 {
		t.Fatalf("reuse: %+v", v)
	}
}

func BenchmarkTwentyRulesNoMatch(b *testing.B) {
	e := NewMemory()
	e.Country = func(string) string { return "US" }
	for i := 0; i < 20; i++ {
		e.Create("", in(fmt.Sprintf("r%d", i), []string{
			`http.path starts_with "/admin" and ip.country != "US"`, `lower(http.user_agent) contains "sqlmap"`,
			`http.user_agent matches "(?i)(curl|wget)/"`, `ip.country in ["CN", "RU"]`, `http.header["x-debug"] exists`}[i%5], Action{Type: ActBlock}), -1)
	}
	r := mkReq("GET", "http://app.example.com/products?page=2", map[string]string{"User-Agent": "Mozilla/5.0 Chrome/120"})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if run := e.Begin(&Env{R: r, ClientIP: "198.51.100.1", Country: e.Country}, "app"); run != nil {
			for m := run.Next(); m != nil; m = run.Next() {
			}
		}
	}
}

func BenchmarkNoRules(b *testing.B) {
	e := NewMemory()
	r := mkReq("GET", "/", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if e.Active() {
			e.Begin(&Env{R: r}, "")
		}
	}
}

func BenchmarkParseCompile(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Parse(`http.path starts_with "/admin" and ip.country != "US" and http.user_agent matches "(?i)curl|wget"`)
	}
}
