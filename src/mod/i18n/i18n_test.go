package i18n

import (
	"strings"
	"testing"
)

func TestNegotiate(t *testing.T) {
	cases := map[string]string{
		"":                                "en",
		"*":                               "en",
		"en-US,en;q=0.9":                  "en",
		"zh-CN,zh;q=0.9,en;q=0.8":         "zh-CN",
		"zh-Hans-CN":                      "zh-CN",
		"zh-TW":                           "zh-TW",
		"zh-HK,zh;q=0.8":                  "zh-TW",
		"zh-Hant":                         "zh-TW",
		"zh":                              "zh-CN",
		"de-AT,de;q=0.9":                  "de",
		"pt-PT":                           "pt-BR",
		"pt":                              "pt-BR",
		"fr;q=0.5, ja;q=0.9":              "ja",
		"xx, ru;q=0.1":                    "ru",
		"es;q=0":                          "en",
		"it,nl":                           "en",
		"fr;q=bogus, de":                  "de",
		"ES_mx":                           "es",
		"<script>alert(1)</script>;q=0.9": "en",
		strings.Repeat("x,", 500) + "ja":  "en", // bounded work: later entries are ignored
	}
	for in, want := range cases {
		if got := Negotiate(in); got != want {
			t.Errorf("Negotiate(%.40q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrKnownAndUnknown(t *testing.T) {
	if Tr("en", "Try again") != "Try again" || Tr("", "Try again") != "Try again" {
		t.Fatal("English must be unchanged")
	}
	if Tr("de", "Try again") != "Erneut versuchen" {
		t.Fatal("de translation missing")
	}
	if Tr("de", "something unknown") != "something unknown" {
		t.Fatal("unknown strings must pass through")
	}
	if Tr("xx", "Try again") != "Try again" {
		t.Fatal("unknown language must fall back to English")
	}
}

func TestTablesAreComplete(t *testing.T) {
	base := pageText["zh-CN"]
	for _, lang := range Supported[1:] {
		tbl := pageText[lang]
		if tbl == nil {
			t.Fatalf("no table for %s", lang)
		}
		for k := range base {
			tr, ok := tbl[k]
			if !ok || strings.TrimSpace(tr) == "" {
				t.Errorf("%s: missing translation for %q", lang, k)
			}
			if strings.Contains(k, "{domain}") != strings.Contains(tr, "{domain}") {
				t.Errorf("%s: {domain} placeholder mismatch for %q", lang, k)
			}
			if strings.ContainsAny(tr, "<>") {
				t.Errorf("%s: markup in translation %q", lang, tr)
			}
		}
		if len(tbl) != len(base) {
			t.Errorf("%s has %d entries, zh-CN has %d", lang, len(tbl), len(base))
		}
	}
}

func TestTranslatePageEscapesAndKeepsMarkup(t *testing.T) {
	page := []byte("<html><head><title>Forbidden</title></head><body><h3>403 - Forbidden</h3><p>You do not have permission to view this directory or page. <br>x</p><small>Request time: <span id=\"t\"></span></small></body></html>")
	out := string(TranslatePage(page, "fr"))
	for _, want := range []string{`<html lang="fr">`, "<title>Interdit</title>", "<h3>403 - Interdit</h3>", "Heure de la requête :", "l&#39;autorisation"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	if string(TranslatePage(page, "en")) != string(page) {
		t.Fatal("English must be returned untouched")
	}
	// a hostile translation table entry would be escaped
	pageText["fr"]["Error"] = `<img src=x onerror=alert(1)> $1`
	defer func() { pageText["fr"]["Error"] = "Erreur" }()
	out = string(TranslatePage([]byte("<p>Error</p>"), "fr"))
	if strings.Contains(out, "<img") || !strings.Contains(out, "&lt;img") || !strings.Contains(out, "$1") {
		t.Fatalf("translation not escaped: %s", out)
	}
}
