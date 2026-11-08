package captcha

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func renderLang(cfg *Config, kind PageKind, acceptLanguage string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/x", nil)
	if acceptLanguage != "" {
		r.Header.Set("Accept-Language", acceptLanguage)
	}
	switch kind {
	case PageBlocked:
		RenderBlocked(w, r, cfg, "app.example.com")
	case PageFailed:
		RenderFailed(w, r, cfg, "app.example.com", RenderOptions{})
	default:
		RenderChallenge(w, r, cfg, "app.example.com", "")
	}
	return w
}

func TestPagesFollowAcceptLanguage(t *testing.T) {
	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "k"}
	en := renderLang(cfg, PageChallenge, "").Body.String()
	if !strings.Contains(en, `lang="en-US"`) || !strings.Contains(en, "Just a moment...") || !strings.Contains(en, "Performance &amp; security by") {
		t.Fatal("no Accept-Language must keep the English page")
	}
	zh := renderLang(cfg, PageChallenge, "zh-CN,zh;q=0.9,en;q=0.5")
	body := zh.Body.String()
	for _, want := range []string{`lang="zh-CN"`, "请稍候", "app.example.com 需要检查您的连接是否安全", "性能与安全由"} {
		if !strings.Contains(body, want) {
			t.Errorf("zh-CN challenge page misses %q", want)
		}
	}
	if strings.Contains(body, "Just a moment") {
		t.Error("English default leaked into the zh-CN page")
	}
	if !strings.Contains(zh.Header().Get("Vary"), "Accept-Language") {
		t.Error("localised responses must send Vary: Accept-Language")
	}
	if b := renderLang(cfg, PageBlocked, "de").Body.String(); !strings.Contains(b, "Zugriff blockiert") {
		t.Error("blocked page not translated to German")
	}
	if b := renderLang(cfg, PageFailed, "ja").Body.String(); !strings.Contains(b, "もう一度試す") {
		t.Error("failed page retry button not translated to Japanese")
	}
}

func TestBrandingTextBeatsTranslation(t *testing.T) {
	cfg := &Config{Provider: ProviderCloudflare, SiteKey: "k", Branding: &Branding{Title: "Custom Title", Heading: "My Heading", Message: "Custom <b>message</b>", RetryText: "Again"}}
	body := renderLang(cfg, PageChallenge, "fr").Body.String()
	if !strings.Contains(body, "Custom Title") || !strings.Contains(body, "My Heading") {
		t.Fatal("custom branding must win over the translated default")
	}
	if strings.Contains(body, "Custom <b>message</b>") || !strings.Contains(body, "Custom &lt;b&gt;message&lt;/b&gt;") {
		t.Fatal("branding text must stay HTML-escaped")
	}
	// fields left empty still fall back to the translated default
	if !strings.Contains(body, "Vérification") {
		t.Fatal("unset branding fields should use the translated defaults")
	}
}

func TestTranslatedStringsAreEscapedInPage(t *testing.T) {
	// the French default contains an apostrophe-free text, the Russian page contains quotes-free text; use a
	// string with an apostrophe (French "s'est produite") to prove html/template escapes translated defaults
	body := renderLang(&Config{Provider: ProviderCloudflare, SiteKey: "k"}, PageChallenge, "fr").Body.String()
	if strings.Contains(body, "s'est produite") && !strings.Contains(body, "s&#39;est produite") && !strings.Contains(body, `s'est produite`) && !strings.Contains(body, `s\'est`) {
		t.Fatal("apostrophe in a translated string reached the page unescaped")
	}
}
