package redirection

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
)

func newAdvTable(t *testing.T, advanced bool) *RuleTable {
	t.Helper()
	lg, _ := logger.NewFmtLogger()
	rt, err := NewRuleTable(filepath.Join(t.TempDir(), "r"), true, true, lg)
	if err != nil {
		t.Fatal(err)
	}
	rt.AdvancedRegex = advanced
	return rt
}

func TestAdvancedRegexLookaheadMatchesOnlyInAdvancedMode(t *testing.T) {
	// "any path under /app/ that is not /app/keep"
	pattern := `^example\.com/app/(?!keep)`
	for _, advanced := range []bool{false, true} {
		rt := newAdvTable(t, advanced)
		if err := rt.AddRedirectRule(pattern, "https://new.example.org/", false, 301, false, "all"); err != nil {
			t.Fatal(err)
		}
		hit := rt.MatchRedirectRule("example.com/app/other")
		miss := rt.MatchRedirectRule("example.com/app/keep/x")
		if advanced && (hit == nil || miss != nil) {
			t.Fatalf("advanced: hit=%v miss=%v", hit, miss)
		}
		if !advanced && hit != nil {
			t.Fatal("RE2 mode must not support lookahead (default engine unchanged)")
		}
	}
}

func TestAdvancedRegexLookbehind(t *testing.T) {
	ok, err := advancedMatch(`(?<=/v2)/users`, "x.com/v2/users")
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, _ := advancedMatch(`(?<=/v2)/users`, "x.com/v1/users"); ok {
		t.Fatal("lookbehind matched wrongly")
	}
}

func TestAdvancedRegexReDoSIsCutByTimeout(t *testing.T) {
	input := strings.Repeat("a", 40) + "!"
	start := time.Now()
	ok, err := advancedMatch(`^(a+)+$`, input)
	el := time.Since(start)
	if ok || err != ErrAdvancedRegexTimeout {
		t.Fatalf("expected timeout, got ok=%v err=%v", ok, err)
	}
	if el > 2*time.Second {
		t.Fatalf("hard timeout not enforced: %v", el)
	}
	// and a request hitting such a rule through the table is simply a non match
	rt := newAdvTable(t, true)
	rt.AddRedirectRule(`^(a+)+$`, "https://x.example/", false, 301, false, "all")
	start = time.Now()
	if rt.MatchRedirectRule(input) != nil {
		t.Fatal("must not match")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("table lookup not bounded")
	}
}

func TestAdvancedRegexLimits(t *testing.T) {
	if ValidateAdvancedRegex(strings.Repeat("a", MaxAdvancedPatternLen+1)) == nil {
		t.Fatal("overlong pattern accepted")
	}
	if ValidateAdvancedRegex("(unclosed") == nil {
		t.Fatal("invalid pattern accepted")
	}
	long := strings.Repeat("b", MaxAdvancedInputLen*3) + "needle"
	if ok, _ := advancedMatch("needle", long); ok {
		t.Fatal("input beyond the cap must be truncated")
	}
}

func TestRedirectTargetExpandsSafeVariables(t *testing.T) {
	rt := newAdvTable(t, false)
	rt.AllowRegex = false
	if err := rt.AddRedirectRule("example.com/go", "https://dest.example/?from={{host}}&ip={{client_ip}}", false, 302, false, "all"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://example.com/go", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	w := httptest.NewRecorder()
	rt.HandleRedirect(w, r)
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "from=example.com") || !strings.Contains(loc, "ip=203.0.113.9") || strings.ContainsAny(loc, "\r\n") {
		t.Fatalf("Location %q", loc)
	}
}
