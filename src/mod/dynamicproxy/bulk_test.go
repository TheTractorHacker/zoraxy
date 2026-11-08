package dynamicproxy

import (
	"errors"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

func bulkRouter(t *testing.T, names ...string) *Router {
	t.Helper()
	router, _ := newOpsTestRouter(t, "127.0.0.1:1")
	router.ProxyEndpoints.Delete("app.example.com")
	for _, n := range names {
		ep := &ProxyEndpoint{ProxyType: ProxyTypeHost, RootOrMatchingDomain: n, parent: router,
			ActiveOrigins:          []*loadbalance.Upstream{{OriginIpOrDomain: "127.0.0.1:1", Weight: 1}},
			AuthenticationProvider: &AuthenticationProvider{}, Tags: []string{"old"}}
		ready, err := router.PrepareProxyRoute(ep)
		if err != nil {
			t.Fatal(err)
		}
		router.AddProxyRouteToRuntime(ready)
	}
	return router
}

func TestBulkPartialUpdateAndResults(t *testing.T) {
	router := bulkRouter(t, "a.example.com", "b.example.com")
	saved := map[string]bool{}
	hooks := BulkHooks{Persist: func(ep *ProxyEndpoint) error { saved[ep.RootOrMatchingDomain] = true; return nil }}
	res, err := router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com", "ghost.example.com", "B.example.com", "a.example.com"},
		Action: BulkAddTags, Params: BulkParams{Tags: []string{"prod", "old"}}}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("duplicates must be collapsed: %+v", res)
	}
	byName := map[string]BulkResult{}
	for _, r := range res {
		byName[r.Rule] = r
	}
	if !byName["a.example.com"].OK || !byName["b.example.com"].OK || byName["ghost.example.com"].OK || byName["ghost.example.com"].Error == "" {
		t.Fatalf("results: %+v", res)
	}
	for _, n := range []string{"a.example.com", "b.example.com"} {
		ep, _ := router.LoadProxy(n)
		if strings.Join(ep.Tags, ",") != "old,prod" || !saved[n] {
			t.Fatalf("%s tags=%v saved=%v", n, ep.Tags, saved[n])
		}
	}
}

func TestBulkInvalidRequestChangesNothing(t *testing.T) {
	router := bulkRouter(t, "a.example.com")
	bad := []*BulkRequest{
		{Rules: nil, Action: BulkEnable},
		{Rules: []string{"a.example.com"}, Action: "explode"},
		{Rules: []string{"a.example.com"}, Action: BulkAddTags},
		{Rules: []string{"a.example.com"}, Action: BulkSetWAF, Params: BulkParams{WAFSource: "custom"}},
		{Rules: []string{"a.example.com"}, Action: BulkSetAuth, Params: BulkParams{AuthMethod: "basic"}},
		{Rules: []string{"a.example.com"}, Action: BulkSetAuth, Params: BulkParams{AuthMethod: "none"}},
		{Rules: []string{"a.example.com"}, Action: BulkDelete},
		{Rules: []string{"a.example.com"}, Action: BulkSetRateLimit, Params: BulkParams{RateLimitEnabled: true}},
	}
	for i, b := range bad {
		if _, err := router.BulkEdit(b, BulkHooks{}); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := router.LoadProxy("a.example.com"); err != nil {
		t.Fatal("rule vanished")
	}
}

func TestBulkEnableDisableDryRunAndPersistFailure(t *testing.T) {
	router := bulkRouter(t, "a.example.com", "b.example.com")
	dry, _ := router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkDisable, DryRun: true}, BulkHooks{})
	if !dry[0].OK || len(dry[0].Changes) != 1 {
		t.Fatalf("%+v", dry)
	}
	if ep, _ := router.LoadProxy("a.example.com"); ep.Disabled {
		t.Fatal("dry run applied the change")
	}
	res, _ := router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com", "b.example.com"}, Action: BulkDisable},
		BulkHooks{Persist: func(ep *ProxyEndpoint) error {
			if ep.RootOrMatchingDomain == "b.example.com" {
				return errors.New("disk full")
			}
			return nil
		}})
	if !res[0].OK || res[1].OK || !strings.Contains(res[1].Error, "disk full") {
		t.Fatalf("%+v", res)
	}
	if ep, _ := router.LoadProxy("a.example.com"); !ep.Disabled {
		t.Fatal("a not disabled")
	}
}

func TestBulkRateLimitAuthAndDelete(t *testing.T) {
	router := bulkRouter(t, "a.example.com", "b.example.com")
	router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkSetRateLimit, Params: BulkParams{RateLimitEnabled: true, RateLimit: 20, RateLimitBurst: 40}}, BulkHooks{})
	if ep, _ := router.LoadProxy("a.example.com"); !ep.RequireRateLimit || ep.RateLimit != 20 || ep.RateLimitBurst != 40 {
		t.Fatalf("%+v", ep)
	}
	router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkSetAuth, Params: BulkParams{AuthMethod: "oauth2"}}, BulkHooks{})
	if ep, _ := router.LoadProxy("a.example.com"); ep.AuthenticationProvider.AuthMethod != AuthMethodOauth2 {
		t.Fatal("auth not set")
	}
	removed := []string{}
	res, _ := router.BulkEdit(&BulkRequest{Rules: []string{"b.example.com", "/"}, Action: BulkDelete, Params: BulkParams{Confirm: true}},
		BulkHooks{Remove: func(n string) error { removed = append(removed, n); return nil }})
	if !res[0].OK || res[1].OK {
		t.Fatalf("%+v", res)
	}
	if _, err := router.LoadProxy("b.example.com"); err == nil || len(removed) != 1 {
		t.Fatal("b not deleted")
	}
}

func TestBulkSetWAFSource(t *testing.T) {
	router := bulkRouter(t, "a.example.com")
	res, _ := router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkSetWAF, Params: BulkParams{WAFSource: "detection_only"}}, BulkHooks{})
	if !res[0].OK {
		t.Fatalf("%+v", res)
	}
	if ep, _ := router.LoadProxy("a.example.com"); ep.WAFSource != "detection_only" {
		t.Fatalf("source %q", ep.WAFSource)
	}
	res, _ = router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkSetWAF, Params: BulkParams{WAFSource: "profile", WAFProfile: "does-not-exist"}}, BulkHooks{})
	if res[0].OK {
		t.Fatal("unknown profile accepted")
	}
	if ep, _ := router.LoadProxy("a.example.com"); ep.WAFSource != "detection_only" {
		t.Fatal("failed rule was modified")
	}
}

func TestRuleTemplatesBuiltinsAndDiff(t *testing.T) {
	for _, tpl := range BuiltinRuleTemplates() {
		if err := tpl.Validate(); err != nil {
			t.Fatalf("%s: %v", tpl.Name, err)
		}
	}
	router := bulkRouter(t, "a.example.com")
	tpl := BuiltinRuleTemplates()[0] //Secure web app
	res, _ := router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkApplyTemplate, Params: BulkParams{Template: tpl}, DryRun: true}, BulkHooks{})
	if !res[0].OK || len(res[0].Changes) < 5 {
		t.Fatalf("preview: %+v", res)
	}
	ep, _ := router.LoadProxy("a.example.com")
	if ep.HeaderRewriteRules != nil && ep.HeaderRewriteRules.HSTSMaxAge != 0 {
		t.Fatal("preview applied")
	}
	router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkApplyTemplate, Params: BulkParams{Template: tpl}}, BulkHooks{})
	ep, _ = router.LoadProxy("a.example.com")
	if ep.HeaderRewriteRules.HSTSMaxAge != 31536000 || !ep.BlockCommonExploits || ep.WAFSource != "detection_only" ||
		strings.Join(ep.Tags, ",") != "old,web" {
		t.Fatalf("not applied: %+v tags=%v", ep.HeaderRewriteRules, ep.Tags)
	}
	hasNosniff := false
	for _, h := range ep.HeaderRewriteRules.UserDefinedHeaders {
		if strings.EqualFold(h.Key, "X-Content-Type-Options") {
			hasNosniff = true
		}
	}
	if !hasNosniff {
		t.Fatal("security headers missing")
	}
	// applying twice changes nothing more
	res, _ = router.BulkEdit(&BulkRequest{Rules: []string{"a.example.com"}, Action: BulkApplyTemplate, Params: BulkParams{Template: tpl}, DryRun: true}, BulkHooks{})
	if len(res[0].Changes) != 0 {
		t.Fatalf("second apply not idempotent: %+v", res[0].Changes)
	}
	// upstreams and authentication untouched
	if len(ep.ActiveOrigins) != 1 || ep.AuthenticationProvider == nil {
		t.Fatal("template touched upstreams or auth")
	}
}

func TestRuleTemplateValidation(t *testing.T) {
	prof := "profile"
	cases := []*RuleTemplate{
		{Name: ""}, {Name: "../x"}, {Name: "ok", WAFSource: &prof}, {Name: "ok", Tags: []string{"a,b"}},
		{Name: "ok", HSTSMaxAge: i64(-1)}, {Name: "ok", Headers: nil, RateLimit: i64(-5)},
	}
	for i, c := range cases {
		if c.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
