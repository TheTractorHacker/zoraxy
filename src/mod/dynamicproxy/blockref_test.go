package dynamicproxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/botrules"
)

func TestRenderErrorPagePlaceholders(t *testing.T) {
	ref := "0123ABCD"
	// an operator template written for older versions has no placeholder: untouched, byte for byte
	old := []byte("<html><body>Nope <b>403</b></body></html>")
	if got := renderErrorPage(old, ref, true); string(got) != string(old) {
		t.Errorf("old template changed: %q", got)
	}
	if got := string(renderErrorPage([]byte("id={{ref}}!"), ref, false)); got != "id=ZX-0123-ABCD!" {
		t.Errorf("placeholder: %q", got)
	}
	if got := string(renderErrorPage([]byte("id={{ref}}!"), "", false)); got != "id=!" {
		t.Errorf("placeholder without a reference: %q", got)
	}
	// built-in page markers
	pg := []byte("a<!--ref-->[{{ref}}]<!--/ref-->b<!--region-->R<!--/region-->c")
	if got := string(renderErrorPage(pg, ref, false)); got != "a[ZX-0123-ABCD]bc" {
		t.Errorf("ref only: %q", got)
	}
	if got := string(renderErrorPage(pg, "", true)); got != "abRc" {
		t.Errorf("region only: %q", got)
	}
	if got := string(renderErrorPage(pg, "", false)); got != "abc" {
		t.Errorf("neither: %q", got)
	}
}

func TestBuiltinForbiddenPageIsSelfContained(t *testing.T) {
	page := string(page_forbidden)
	for _, bad := range []string{"http://", "https://", "cdnjs", "jquery", "semantic", "<link", "src="} {
		if strings.Contains(strings.ToLower(page), bad) {
			t.Errorf("the 403 page must not depend on anything external, found %q", bad)
		}
	}
	if !strings.Contains(page, "{{ref}}") || !strings.Contains(page, "prefers-color-scheme") {
		t.Error("the 403 page lacks the reference placeholder or the dark mode rule")
	}
	with := string(renderErrorPage(page_forbidden, "0123ABCD", false))
	if !strings.Contains(with, "ZX-0123-ABCD") || !strings.Contains(with, "give the site owner this reference") {
		t.Error("reference sentence missing")
	}
	if strings.Contains(with, "region limit") {
		t.Error("the region sentence belongs to country blocks only")
	}
	if !strings.Contains(string(renderErrorPage(page_forbidden, "", true)), "region limit") {
		t.Error("region sentence missing for a region block")
	}
	if without := string(renderErrorPage(page_forbidden, "", false)); strings.Contains(without, "reference") || strings.Contains(without, "{{") || strings.Contains(without, "<!--ref") {
		t.Error("no reference: the sentence and markers must be gone")
	}
}

func refRouter(t *testing.T, cfg func(c *botrules.Config)) (*Router, *ProxyEndpoint, *blocklog.Log) {
	t.Helper()
	router, sep, _ := newBotRouter(t, cfg)
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	return router, sep, bl
}

var zxRef = regexp.MustCompile(`ZX-[0-9A-Z]{4}-[0-9A-Z]{4}`)

// challenge action without a CAPTCHA: blocked, the log keeps the category, the visitor gets the reference
func TestBotChallengeUnavailableKeepsCategoryAndShowsReference(t *testing.T) {
	router, sep, bl := refRouter(t, func(c *botrules.Config) {
		c.Categories["http_library"] = botrules.CategoryCfg{Enabled: true, Action: botrules.ActionChallenge}
	})
	w := serveUA(router, sep, "curl/8.18.0")
	if w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
	hdr := w.Header().Get("X-Zoraxy-Ref")
	if !zxRef.MatchString(hdr) || !strings.Contains(w.Body.String(), hdr) {
		t.Fatalf("header %q, body must show it: %s", hdr, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "http_library") || strings.Contains(w.Body.String(), "Bot rule") || strings.Contains(w.Body.String(), "curl") {
		t.Error("the rule must never be shown to the visitor")
	}
	items := waitBlocked(t, bl, 1)
	e := items[0]
	if blocklog.FormatRef(e.Ref) != hdr {
		t.Errorf("entry ref %q, visitor saw %q", e.Ref, hdr)
	}
	if e.Reason != blocklog.ReasonBot || e.RuleID != "bot:http_library" || e.Detail != "http_library (challenge, no CAPTCHA, acted as block)" {
		t.Errorf("entry: %+v", e)
	}
	if got, ok := bl.GetByRef(hdr); !ok || got.Seq != e.Seq {
		t.Error("lookup by the reference the visitor was shown failed")
	}
	if strings.Contains(w.Body.String(), "region limit") {
		t.Error("bot blocks have nothing to do with regions")
	}
}

func TestBlockPagesCarryDistinctReferences(t *testing.T) {
	router, sep, bl := refRouter(t, nil)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		w := serveUA(router, sep, "sqlmap/1.5")
		ref := w.Header().Get("X-Zoraxy-Ref")
		if ref == "" || seen[ref] {
			t.Fatalf("reference %q empty or repeated", ref)
		}
		seen[ref] = true
	}
	for _, e := range waitBlocked(t, bl, 5) {
		if e.RuleID != "bot:scanner" || e.Ref == "" {
			t.Errorf("entry: %+v", e)
		}
	}
	// requests that are let through never get one
	if w := serveUA(router, sep, "Mozilla/5.0"); w.Header().Get("X-Zoraxy-Ref") != "" {
		t.Error("reference on an allowed request")
	}
}

func TestNoReferenceWhenTheLogIsOff(t *testing.T) {
	router, sep, bl := refRouter(t, nil)
	bl.SetEnabled(false)
	w := serveUA(router, sep, "sqlmap/1.5")
	if w.Code != 403 || w.Header().Get("X-Zoraxy-Ref") != "" || zxRef.MatchString(w.Body.String()) || strings.Contains(w.Body.String(), "give the site owner") {
		t.Errorf("a block that is not logged must not promise a reference: %d %s", w.Code, w.Body.String())
	}
	router.Option.BlockLog = nil
	if w := serveUA(router, sep, "sqlmap/1.5"); w.Code != 403 || w.Header().Get("X-Zoraxy-Ref") != "" {
		t.Error("no log at all")
	}
}

func TestCustomForbiddenTemplateWithAndWithoutRef(t *testing.T) {
	router, sep, _ := refRouter(t, nil)
	dir := filepath.Join(router.Option.WebDirectory, "templates")
	os.MkdirAll(dir, 0o755)
	// with the placeholder
	os.WriteFile(filepath.Join(dir, "forbidden.html"), []byte("<p>denied {{ref}}</p>"), 0o644)
	w := serveUA(router, sep, "sqlmap/1.5")
	hdr := w.Header().Get("X-Zoraxy-Ref")
	if w.Code != 403 || w.Body.String() != "<p>denied "+hdr+"</p>" || hdr == "" {
		t.Errorf("template with {{ref}}: %d %q (header %q)", w.Code, w.Body.String(), hdr)
	}
	// an older template: written as it is, the header is still there
	os.WriteFile(filepath.Join(dir, "forbidden.html"), []byte("<p>denied</p>"), 0o644)
	w = serveUA(router, sep, "sqlmap/1.5")
	if w.Body.String() != "<p>denied</p>" || w.Header().Get("X-Zoraxy-Ref") == "" {
		t.Errorf("template without {{ref}}: %q", w.Body.String())
	}
}

// access lists: the reference and the rule key, and the region sentence only when a country is the reason
func TestAccessBlocksReferenceAndRegionSentence(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	bl := blocklog.New("", 100, blocklog.DefaultSettings())
	router.Option.BlockLog = bl
	rule.Name = "Office only"
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.9", "test")
	w := serveNonTLS(router, sep, "http://app.example.com/x", "198.51.100.9:1000")
	hdr := w.Header().Get("X-Zoraxy-Ref")
	if w.Code != 403 || !zxRef.MatchString(hdr) || !strings.Contains(w.Body.String(), hdr) {
		t.Fatalf("blacklist page: %d %q", w.Code, hdr)
	}
	if strings.Contains(w.Body.String(), "region limit") {
		t.Error("an address on the blacklist is not a region block")
	}
	e := waitBlocked(t, bl, 1)[0]
	if e.RuleID != "access:Office only" || blocklog.FormatRef(e.Ref) != hdr {
		t.Errorf("entry: %+v", e)
	}
}
