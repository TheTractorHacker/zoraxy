// Package i18n holds the language negotiation and the small server-side string tables used by
// the visitor-facing pages (CAPTCHA challenge / failed / blocked, built-in 403 / 404 / 521 pages).
// The admin UI itself is translated in the browser (web/script/i18n.js, web/locales/*.json).
package i18n

import (
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Supported lists the shipped UI languages. The first entry is the default.
var Supported = []string{"en", "zh-CN", "zh-TW", "es", "de", "fr", "ja", "pt-BR", "ru"}

// Normalize maps a language tag ("zh-Hans-CN", "pt", "DE_at") to a supported code, or "" when none fits.
func Normalize(tag string) string {
	tag = strings.ReplaceAll(strings.TrimSpace(tag), "_", "-")
	if tag == "" || tag == "*" {
		return ""
	}
	lc := strings.ToLower(tag)
	for _, s := range Supported {
		if strings.ToLower(s) == lc {
			return s
		}
	}
	prim := strings.SplitN(lc, "-", 2)[0]
	switch prim {
	case "zh":
		for _, k := range []string{"tw", "hk", "mo", "hant"} {
			if strings.Contains(lc, k) {
				return "zh-TW"
			}
		}
		return "zh-CN"
	case "pt":
		return "pt-BR"
	}
	for _, s := range Supported {
		if strings.ToLower(s) == prim {
			return s
		}
	}
	return ""
}

// Negotiate picks the best supported language for an Accept-Language header value.
// English is returned for an empty, malformed or unmatched header.
func Negotiate(header string) string {
	type cand struct {
		code string
		q    float64
	}
	var cands []cand
	for i, part := range strings.Split(header, ",") {
		if i > 32 {
			break
		}
		fields := strings.Split(strings.TrimSpace(part), ";")
		q := 1.0
		for _, p := range fields[1:] {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "q=") {
				if v, err := strconv.ParseFloat(p[2:], 64); err == nil {
					q = v
				} else {
					q = 0
				}
			}
		}
		if q <= 0 {
			continue
		}
		if code := Normalize(fields[0]); code != "" {
			cands = append(cands, cand{code, q})
		}
	}
	if len(cands) == 0 {
		return Supported[0]
	}
	sort.SliceStable(cands, func(a, b int) bool { return cands[a].q > cands[b].q })
	return cands[0].code
}

// HTMLLang is the value for <html lang="..."> ("en-US" for the English default, as before).
func HTMLLang(lang string) string {
	if lang == "" || lang == "en" {
		return "en-US"
	}
	return lang
}

// Tr translates one of the known English strings; unknown strings and English return the input.
func Tr(lang, en string) string {
	if lang == "" || lang == "en" {
		return en
	}
	if t, ok := pageText[lang][en]; ok {
		return t
	}
	return en
}

var textNodeRe = map[string]*regexp.Regexp{}

func init() {
	for en := range pageText["zh-CN"] {
		textNodeRe[en] = regexp.MustCompile(`(>\s*)` + regexp.QuoteMeta(en) + `(\s*<)`)
	}
}

// TranslatePage translates the text nodes of a built-in HTML error page. Only text that is exactly
// one of the known English strings (between tags) is replaced; translations are HTML-escaped.
// Pages supplied by the operator are never passed through here.
func TranslatePage(page []byte, lang string) []byte {
	if lang == "" || lang == "en" || pageText[lang] == nil {
		return page
	}
	out := string(page)
	for en, re := range textNodeRe {
		tr, ok := pageText[lang][en]
		if !ok {
			continue
		}
		esc := strings.ReplaceAll(html.EscapeString(tr), "$", "$$")
		out = re.ReplaceAllString(out, "${1}"+esc+"${2}")
	}
	out = strings.Replace(out, "<html>", `<html lang="`+HTMLLang(lang)+`">`, 1)
	return []byte(out)
}
