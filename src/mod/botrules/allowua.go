package botrules

import (
	"errors"
	"fmt"
	"strings"
)

/*
	Per-site User-Agent allow list (ProxyEndpoint.BotAllowUA, applied in
	mod/dynamicproxy/bot_hook.go): a request whose User-Agent contains one of the
	entries skips the bot rules of that site only.

	This is a convenience for a known client (curl in a monitoring script, an agent
	that cannot solve a CAPTCHA), not a security control: a User-Agent is whatever
	the client says it is. That is why the entries are kept narrow: a product token
	such as "curl/" is accepted, a token every browser sends ("mozilla") or a short
	fragment is not.
*/

const (
	MaxAllowUAs      = 20 //entries per site
	MinAllowUALen    = 4
	MaxAllowUALen    = 64
	maxAllowUAHeader = 512 //only the head of the header is matched, as Evaluate does
)

// genericUATokens are words a browser, a crawler family or a plain word carries: allowing one of them
// would let whole classes of clients skip the rules
var genericUATokens = []string{
	"mozilla", "applewebkit", "webkit", "khtml", "gecko", "chrome", "chromium", "safari", "firefox", "edge", "edg/", "opera", "msie", "trident",
	"windows", "linux", "android", "iphone", "ipad", "macintosh", "mac os", "x11", "compatible", "like gecko",
	"bot", "spider", "crawler", "crawl", "http", "https", "www", "agent", "client", "browser", "user", "test", "version",
}

// browserProductTokens are the "name/" parts a browser sends; an entry containing one would match browsers
var browserProductTokens = []string{
	"chrome/", "chromium/", "safari/", "firefox/", "applewebkit/", "gecko/", "edg/", "edge/", "edga/", "edgios/", "opr/", "opera/",
	"crios/", "fxios/", "version/", "mobile/", "trident/", "khtml", "msie",
}

// referenceBrowserUAs: no entry may be a part of what an ordinary browser sends
var referenceBrowserUAs = []string{
	"mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/126.0.0.0 safari/537.36 edg/126.0.0.0 opr/110.0.0.0",
	"mozilla/5.0 (macintosh; intel mac os x 10_15_7) applewebkit/605.1.15 (khtml, like gecko) version/17.5 safari/605.1.15",
	"mozilla/5.0 (x11; ubuntu; linux x86_64; rv:127.0) gecko/20100101 firefox/127.0",
	"mozilla/5.0 (iphone; cpu iphone os 17_5 like mac os x) applewebkit/605.1.15 (khtml, like gecko) crios/126.0.0.0 mobile/15e148 safari/604.1",
	"mozilla/5.0 (linux; android 14; pixel 8) applewebkit/537.36 (khtml, like gecko) chrome/126.0.0.0 mobile safari/537.36",
	"mozilla/5.0 (compatible; msie 10.0; windows nt 6.1; trident/6.0)",
}

// NormalizeAllowUA validates one allow list entry and returns it in the stored form (trimmed, lower case).
func NormalizeAllowUA(p string) (string, error) {
	p = strings.ToLower(strings.TrimSpace(p))
	if len(p) < MinAllowUALen {
		return "", fmt.Errorf("the pattern must be at least %d characters (a short fragment would match far more than one client)", MinAllowUALen)
	}
	if len(p) > MaxAllowUALen {
		return "", fmt.Errorf("the pattern is too long (max %d characters)", MaxAllowUALen)
	}
	letters := 0
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("the pattern contains a control character")
		}
		if r >= 'a' && r <= 'z' {
			letters++
		}
	}
	if letters < 3 {
		return "", errors.New("the pattern must contain a product name, for example curl/")
	}
	for _, g := range genericUATokens {
		if p == g || p == g+"/" || p == g+"-" {
			return "", fmt.Errorf("%q is a generic token that many clients send, so it is not accepted", p)
		}
	}
	// a browser product token with any version ("chrome/9", "firefox/1") is as broad as the browser itself
	for _, b := range browserProductTokens {
		if strings.Contains(p, b) {
			return "", fmt.Errorf("%q is a browser product token, so it is not accepted", p)
		}
	}
	if strings.HasPrefix(p, "mozilla") {
		return "", errors.New("User-Agents that start with Mozilla are what every browser and most bots send, so they cannot be allowed by a pattern")
	}
	for _, b := range referenceBrowserUAs {
		if strings.Contains(b, p) {
			return "", fmt.Errorf("%q is part of what ordinary browsers send, so it is not accepted", p)
		}
	}
	return p, nil
}

// AllowUAToken derives the narrow pattern offered for a client from its User-Agent: the product token
// up to and including the slash ("curl/8.18.0" gives "curl/"). It refuses (error) when no safe token
// can be derived, which includes every Mozilla-style User-Agent.
func AllowUAToken(ua string) (string, error) {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" {
		return "", errors.New("the request has no User-Agent")
	}
	if strings.Contains(ua, "mozilla/") {
		return "", errors.New("this User-Agent starts like a browser (Mozilla/...); a pattern for it would allow every browser-like bot")
	}
	end := len(ua)
	if i := strings.IndexAny(ua, " ;(,"); i >= 0 {
		end = i
	}
	tok := ua[:end]
	if i := strings.Index(tok, "/"); i >= 0 {
		tok = tok[:i+1]
	}
	return NormalizeAllowUA(tok)
}

// NormalizeAllowUAList validates and de-duplicates a list (order kept). nil in, nil out.
func NormalizeAllowUAList(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > MaxAllowUAs {
		return nil, fmt.Errorf("too many allowed User-Agents (max %d)", MaxAllowUAs)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		n, err := NormalizeAllowUA(p)
		if err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

// AllowedUA reports whether ua contains one of the entries (case-insensitive). Entries are compared as stored
// (they were normalised on the way in; a hand-edited upper-case entry is lower-cased here as well).
func AllowedUA(list []string, ua string) bool {
	if len(list) == 0 || ua == "" {
		return false
	}
	if len(ua) > maxAllowUAHeader {
		ua = ua[:maxAllowUAHeader]
	}
	ua = strings.ToLower(ua)
	for _, p := range list {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) >= MinAllowUALen && strings.Contains(ua, p) {
			return true
		}
	}
	return false
}
