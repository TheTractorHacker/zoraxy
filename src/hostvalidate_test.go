package main

import (
	"strings"
	"testing"
)

func TestNormalizeRuleHostname(t *testing.T) {
	ok := map[string]string{"Status.Demo.Test": "status.demo.test", " a.test ": "a.test", "*.demo.test": "*.demo.test", "10.0.0.5": "10.0.0.5", "xn--mnchen-3ya.de": "xn--mnchen-3ya.de", "münchen-café.demo.test": "münchen-café.demo.test"}
	for in, want := range ok {
		got, err := normalizeRuleHostname(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "bad host!!", "http://x.test", "a.test/path", "a.test:8080", "a b.test", "a..b", "-a.test", strings.Repeat("a", 300), strings.Repeat("a", 64) + ".test"} {
		if _, err := normalizeRuleHostname(in); err == nil {
			t.Errorf("%q should be rejected", in)
		}
	}
}

func TestValidateDefaultSiteTarget(t *testing.T) {
	for _, c := range []struct {
		opt int
		v   string
		ok  bool
	}{
		{1, "localhost:8080", true}, {1, "example.com", true}, {1, "192.168.0.10:80", true}, {1, "https://example.com:8443", true},
		{1, "", false}, {1, "not a host!!", false}, {1, strings.Repeat("a", 500), false}, {1, "javascript:alert(1)", false},
		{2, "http://example.com", true}, {2, "https://example.com/x", true},
		{2, "javascript:alert(1)", false}, {2, "example.com", false}, {2, "", false},
		{3, "", true}, {0, "", true},
	} {
		err := validateDefaultSiteTarget(c.opt, c.v)
		if (err == nil) != c.ok {
			t.Errorf("option %d %q: err=%v want ok=%v", c.opt, c.v, err, c.ok)
		}
	}
}

func TestCheckRedirectInput(t *testing.T) {
	ok := [][2]string{{"old.demo.test", "shop.demo.test"}, {"old.demo.test", "https://shop.demo.test/x"}, {"a.test", "b.test:8080/path"}}
	for _, c := range ok {
		if err := checkRedirectInput(c[0], c[1]); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	bad := [][2]string{{"", "b.test"}, {"a.test", ""}, {"loop.test", "loop.test"}, {"loop.test", "https://loop.test/"}, {"a.test", "javascript:alert(1)"}, {"bad url!!", "b.test"}, {"a.test", "not a url"}, {strings.Repeat("a", 500), "b.test"}}
	for _, c := range bad {
		if err := checkRedirectInput(c[0], c[1]); err == nil {
			t.Errorf("%v should be rejected", c)
		}
	}
}
