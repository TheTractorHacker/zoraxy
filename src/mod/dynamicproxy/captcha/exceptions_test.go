package captcha

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func exMatch(rule *ExceptionRule, target string) bool {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RequestURI = target
	return CheckException(r, []*ExceptionRule{rule}, "192.0.2.1")
}

// Path exemptions for every provider share the same gate (CheckException), so the modes are
// tested once here and the provider independence is covered by the gating tests.
func TestExceptionExactMode(t *testing.T) {
	rule := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: "/health", MatchMode: ExceptionMatchExact}
	for target, want := range map[string]bool{
		"/health":              true,
		"/health?x=1":          true,
		"/health/":             true, // trailing slash is canonical-equivalent
		"/health/live":         false,
		"/healthz":             false,
		"/Health":              false,
		"/health/../admin":     false,
		"/admin/../health":     false, // not canonical: exact never normalises into a match
		"/health/%2e%2e/admin": false,
		"//health":             false,
		"/health;x=1":          false,
		"/health%2f..%2fadmin": false,
		"/%68ealth":            true, // decoded exactly once, same path the upstream sees
		"/health\\..\\admin":   false,
		"/hea%00lth":           false,
		"/he%25616lth":         false,
	} {
		if got := exMatch(rule, target); got != want {
			t.Errorf("exact /health vs %q = %v, want %v", target, got, want)
		}
	}
	nocase := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: "/health", MatchMode: ExceptionMatchExact, CaseInsensitive: true}
	if !exMatch(nocase, "/HEALTH") || exMatch(nocase, "/HEALTH/x") {
		t.Error("case insensitive exact mode")
	}
}

func TestExceptionRegexMode(t *testing.T) {
	rule := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: `/api/v[0-9]+/hooks/[a-z]+`, MatchMode: ExceptionMatchRegex}
	for target, want := range map[string]bool{
		"/api/v1/hooks/github":         true,
		"/api/v12/hooks/gitlab?x=1":    true,
		"/api/v1/hooks/github/extra":   false, // the whole path must match
		"/x/api/v1/hooks/github":       false,
		"/api/v1/hooks/GitHub":         false,
		"/api/v1/hooks/../admin":       false,
		"/api/v1/hooks/github/../../x": false,
		"/api/v1/hooks/%61bc":          true,  // decodes (once) to a matching path
		"/api/v1/hooks/%2561bc":        false, // double encoding
		"/api/v1/hooks/abc;a=b":        false,
	} {
		if got := exMatch(rule, target); got != want {
			t.Errorf("regex vs %q = %v, want %v", target, got, want)
		}
	}
	// the pattern is anchored: alternation cannot widen the match
	alt := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: `/a|/b`, MatchMode: ExceptionMatchRegex}
	if exMatch(alt, "/a/secret") || exMatch(alt, "/xb") || !exMatch(alt, "/a") || !exMatch(alt, "/b") {
		t.Error("alternation escaped the anchors")
	}
	// ".*" as a pattern is allowed by the engine but still only on canonical paths
	any := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: `/public/.*`, MatchMode: ExceptionMatchRegex}
	if !exMatch(any, "/public/a/b.css") || exMatch(any, "/public/../admin") || exMatch(any, "/public/%2e%2e/admin") {
		t.Error("wildcard regex handling")
	}
	nocase := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: `/Static/.*`, MatchMode: ExceptionMatchRegex, CaseInsensitive: true}
	if !exMatch(nocase, "/static/app.js") {
		t.Error("case insensitive regex")
	}
	// invalid, empty and oversize patterns never match (and never panic)
	for _, p := range []string{"(", "", "   ", string(make([]byte, MaxExceptionPatternLen+1))} {
		if exMatch(&ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: p, MatchMode: ExceptionMatchRegex}, "/anything") {
			t.Errorf("pattern %q matched", p)
		}
	}
	// catastrophic patterns are linear time with RE2
	evil := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: `(a+)+$`, MatchMode: ExceptionMatchRegex}
	exMatch(evil, "/"+string(make([]byte, 0))+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!")
}

func TestExceptionDefaultPrefixModeUnchanged(t *testing.T) {
	for _, mode := range []string{"", ExceptionMatchPrefix} {
		rule := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: "/public", MatchMode: mode}
		if !exMatch(rule, "/public/x") || exMatch(rule, "/publicx") || exMatch(rule, "/public/../admin") {
			t.Errorf("prefix mode %q changed", mode)
		}
	}
	fold := &ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: "/Public", CaseInsensitive: true}
	if !exMatch(fold, "/public/x") {
		t.Error("case insensitive prefix")
	}
	// rules stored by older versions have neither field
	if !exMatch(&ExceptionRule{RuleType: ExceptionTypePaths, PathPrefix: "/public"}, "/public") {
		t.Error("legacy rule")
	}
}

func TestValidateExceptionPattern(t *testing.T) {
	for mode, ok := range map[string]bool{"": true, "prefix": true, "exact": true, "regex": true, "glob": false} {
		if err := ValidateExceptionPattern(mode, "/x"); (err == nil) != ok {
			t.Errorf("mode %q: %v", mode, err)
		}
	}
	if ValidateExceptionPattern("regex", "(") == nil || ValidateExceptionPattern("exact", string(make([]byte, 600))) == nil {
		t.Error("bad patterns accepted")
	}
}
