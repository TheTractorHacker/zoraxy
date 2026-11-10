package ruleset

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

/*
	actions.go

	What a rule does when its expression matches. Every parameter is validated when the rule is saved
	(and again when the files are loaded, as a hub can publish them), so the request path never has to
	deal with a malformed action.

	Terminating actions end the evaluation for the request: block, redirect, allow, and (when the visitor
	has not solved it) challenge; rate_limit terminates only when the client is over the limit. The others
	(log, tag, skip, header actions) let evaluation go on.
*/

// Action types
const (
	ActAllow     = "allow"
	ActBlock     = "block"
	ActChallenge = "challenge"
	ActLog       = "log"
	ActSkip      = "skip"
	ActRateLimit = "rate_limit"
	ActRedirect  = "redirect"
	ActSetReqH   = "set_request_header"
	ActDelReqH   = "remove_request_header"
	ActSetRespH  = "set_response_header"
	ActDelRespH  = "remove_response_header"
	ActTag       = "tag"
)

// Skip targets
const (
	SkipWAF       = "waf"
	SkipRateLimit = "rate_limit"
	SkipAuth      = "auth"
	SkipCaptcha   = "captcha"
	SkipRules     = "rules"
)

// Skip bit masks (Outcome.Skips)
const (
	SkipBitWAF uint8 = 1 << iota
	SkipBitRateLimit
	SkipBitAuth
	SkipBitCaptcha
)

var skipNames = []string{SkipWAF, SkipRateLimit, SkipAuth, SkipCaptcha, SkipRules}

// ActionTypes lists the types for the builder UI
func ActionTypes() []string {
	return []string{ActAllow, ActBlock, ActChallenge, ActLog, ActSkip, ActRateLimit, ActRedirect, ActSetReqH, ActDelReqH, ActSetRespH, ActDelRespH, ActTag}
}

// SkipTargets lists what a skip action can switch off
func SkipTargets() []string { return append([]string{}, skipNames...) }

// Action is the THEN part of a rule. Only the parameters of its type may be set.
type Action struct {
	Type        string   `json:"type"`
	Status      int      `json:"status,omitempty"`       // block (400-599, default 403), redirect (301/302/303/307/308, default 302), rate_limit (400-599, default 429)
	Body        string   `json:"body,omitempty"`         // block: plain text answer (default: the standard 403 page)
	ReportAbuse bool     `json:"report_abuse,omitempty"` // block: count towards the automatic ban (off by default)
	TTLMinutes  int      `json:"ttl_minutes,omitempty"`  // challenge: how long solving it is remembered (default 30)
	Skip        []string `json:"skip,omitempty"`         // skip: waf, rate_limit, auth, captcha, rules
	Rate        int64    `json:"rate,omitempty"`         // rate_limit: requests per second per client address
	Burst       int64    `json:"burst,omitempty"`        // rate_limit: bucket size (default = rate)
	URL         string   `json:"url,omitempty"`          // redirect: template
	Name        string   `json:"name,omitempty"`         // header actions
	Value       string   `json:"value,omitempty"`        // set_*_header
	Tag         string   `json:"tag,omitempty"`          // tag
}

// Terminating reports whether the action can end the evaluation (before knowing whether it does)
func (a *Action) Terminating() bool {
	switch a.Type {
	case ActAllow, ActBlock, ActChallenge, ActRedirect, ActRateLimit:
		return true
	}
	return false
}

// Describe renders the action for logs and the tester
func (a *Action) Describe() string {
	switch a.Type {
	case ActBlock:
		return fmt.Sprintf("block %d", a.StatusOr(403))
	case ActRedirect:
		return fmt.Sprintf("redirect %d %s", a.StatusOr(302), a.URL)
	case ActSkip:
		return "skip " + strings.Join(a.Skip, ", ")
	case ActRateLimit:
		return fmt.Sprintf("rate_limit %d/s", a.Rate)
	case ActSetReqH, ActSetRespH:
		return a.Type + " " + a.Name
	case ActDelReqH, ActDelRespH:
		return a.Type + " " + a.Name
	case ActTag:
		return "tag " + a.Tag
	}
	return a.Type
}

// StatusOr returns the status, or def when unset
func (a *Action) StatusOr(def int) int {
	if a.Status != 0 {
		return a.Status
	}
	return def
}

var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,31}$`)

const (
	MaxBodyLen  = 2000
	MaxURLLen   = 2000
	MaxValueLen = 1000
)

// Header names the rules may not touch: framing and connection management (changing them breaks the
// protocol or smuggles requests), and every header that carries the client address or protocol, because
// the proxy and later stages (rate limit, captcha, abuse ban) read those.
var forbiddenHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "keep-alive": true,
	"upgrade": true, "te": true, "trailer": true, "proxy-authorization": true, "proxy-authenticate": true,
	"proxy-connection": true, "forwarded": true, "x-forwarded-for": true, "x-forwarded-host": true,
	"x-forwarded-proto": true, "x-forwarded-port": true, "x-real-ip": true, "cf-connecting-ip": true,
	"true-client-ip": true, "fastly-client-ip": true, "x-client-ip": true, "x-cluster-client-ip": true,
	"content-encoding": true, "expect": true,
}

var forbiddenResponseHeaders = map[string]bool{"set-cookie": true, "location": true, "content-length": true, "transfer-encoding": true, "connection": true, "keep-alive": true, "upgrade": true, "trailer": true, "content-encoding": true}

func checkHeaderName(name string, response bool) error {
	if !validToken(name) {
		return fmt.Errorf("%q is not a valid header name (letters, digits and !#$%%&'*+-.^_`|~, at most 100)", name)
	}
	l := strings.ToLower(name)
	if response {
		if forbiddenResponseHeaders[l] {
			return fmt.Errorf("the response header %s cannot be changed by a rule", name)
		}
	} else if forbiddenHeaders[l] {
		return fmt.Errorf("the request header %s cannot be changed by a rule (it carries protocol framing or the client address)", name)
	}
	return nil
}

func checkHeaderValue(v string) error {
	if len(v) > MaxValueLen {
		return fmt.Errorf("the header value is longer than %d characters", MaxValueLen)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' || (c >= 0x20 && c < 0x7f) {
			continue
		}
		return fmt.Errorf("the header value may only contain printable ASCII (no line breaks or control characters)")
	}
	return nil
}

func statusIn(s, lo, hi int, what string) error {
	if s < lo || s > hi {
		return fmt.Errorf("%s must be between %d and %d", what, lo, hi)
	}
	return nil
}

// Validate checks the action and applies nothing. It rejects parameters that do not belong to the type.
func (a *Action) Validate() error {
	stray := func(names ...string) error {
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		check := func(name string, used bool) error {
			if used && !set[name] {
				return fmt.Errorf("%q does not apply to the %s action", name, a.Type)
			}
			return nil
		}
		for _, e := range []error{
			check("status", a.Status != 0), check("body", a.Body != ""), check("report_abuse", a.ReportAbuse),
			check("ttl_minutes", a.TTLMinutes != 0), check("skip", len(a.Skip) > 0), check("rate", a.Rate != 0),
			check("burst", a.Burst != 0), check("url", a.URL != ""), check("name", a.Name != ""),
			check("value", a.Value != ""), check("tag", a.Tag != ""),
		} {
			if e != nil {
				return e
			}
		}
		return nil
	}
	switch a.Type {
	case ActAllow, ActLog:
		return stray()
	case ActBlock:
		if err := stray("status", "body", "report_abuse"); err != nil {
			return err
		}
		if a.Status != 0 {
			if err := statusIn(a.Status, 400, 599, "the status"); err != nil {
				return err
			}
		}
		if len(a.Body) > MaxBodyLen || strings.ContainsRune(a.Body, 0) {
			return fmt.Errorf("the body is limited to %d characters of text", MaxBodyLen)
		}
	case ActChallenge:
		if err := stray("ttl_minutes"); err != nil {
			return err
		}
		if a.TTLMinutes != 0 {
			return statusIn(a.TTLMinutes, 1, 1440, "ttl_minutes")
		}
	case ActSkip:
		if err := stray("skip"); err != nil {
			return err
		}
		if len(a.Skip) == 0 {
			return fmt.Errorf("skip needs at least one of %s", strings.Join(skipNames, ", "))
		}
		seen := map[string]bool{}
		for _, s := range a.Skip {
			ok := false
			for _, n := range skipNames {
				ok = ok || n == s
			}
			if !ok {
				return fmt.Errorf("cannot skip %q (choose from %s)", s, strings.Join(skipNames, ", "))
			}
			if seen[s] {
				return fmt.Errorf("%q is listed twice", s)
			}
			seen[s] = true
		}
	case ActRateLimit:
		if err := stray("rate", "burst", "status"); err != nil {
			return err
		}
		if err := statusIn(int(a.Rate), 1, 100000, "rate (requests per second)"); err != nil {
			return err
		}
		if a.Burst != 0 {
			if err := statusIn(int(a.Burst), 1, 1000000, "burst"); err != nil {
				return err
			}
		}
		if a.Status != 0 {
			return statusIn(a.Status, 400, 599, "the status")
		}
	case ActRedirect:
		if err := stray("status", "url"); err != nil {
			return err
		}
		switch a.StatusOr(302) {
		case 301, 302, 303, 307, 308:
		default:
			return fmt.Errorf("a redirect status is 301, 302, 303, 307 or 308")
		}
		return validateRedirectTemplate(a.URL)
	case ActSetReqH, ActSetRespH:
		if err := stray("name", "value"); err != nil {
			return err
		}
		if err := checkHeaderName(a.Name, a.Type == ActSetRespH); err != nil {
			return err
		}
		if a.Value == "" {
			return fmt.Errorf("a header value is required (use remove_*_header to delete a header)")
		}
		return checkHeaderValue(a.Value)
	case ActDelReqH, ActDelRespH:
		if err := stray("name"); err != nil {
			return err
		}
		return checkHeaderName(a.Name, a.Type == ActDelRespH)
	case ActTag:
		if err := stray("tag"); err != nil {
			return err
		}
		if !tagRe.MatchString(a.Tag) {
			return fmt.Errorf("a tag is 1-32 characters: lower case letters, digits and _ . : -")
		}
	case "":
		return fmt.Errorf("the action type is required (%s)", strings.Join(ActionTypes(), ", "))
	default:
		return fmt.Errorf("unknown action type %q (%s)", a.Type, strings.Join(ActionTypes(), ", "))
	}
	return nil
}

// SkipMask converts the skip list to bits; rules is true when later rules are skipped too
func (a *Action) SkipMask() (mask uint8, rules bool) {
	for _, s := range a.Skip {
		switch s {
		case SkipWAF:
			mask |= SkipBitWAF
		case SkipRateLimit:
			mask |= SkipBitRateLimit
		case SkipAuth:
			mask |= SkipBitAuth
		case SkipCaptcha:
			mask |= SkipBitCaptcha
		case SkipRules:
			rules = true
		}
	}
	return
}

// ---------------------------------------------------------------------
// redirect templates

// Placeholders usable in a redirect URL. Each is replaced by a value that cannot change the structure of
// the URL: {host} is the request host restricted to host name characters, {path} the escaped path (always
// starting with /), {query} the raw query without ?, {uri} path plus ?query, {scheme} http or https.
var redirectPlaceholders = []string{"{host}", "{path}", "{query}", "{uri}", "{scheme}"}

var placeholderRe = regexp.MustCompile(`\{[a-z_]*\}`)

func validateRedirectTemplate(t string) error {
	if t == "" {
		return fmt.Errorf("a redirect needs a url")
	}
	if len(t) > MaxURLLen {
		return fmt.Errorf("the url is longer than %d characters", MaxURLLen)
	}
	for i := 0; i < len(t); i++ {
		if t[i] <= 0x20 || t[i] >= 0x7f || t[i] == '\\' {
			return fmt.Errorf("the url may only contain printable ASCII without spaces, line breaks or backslashes (percent-encode other characters)")
		}
	}
	for _, p := range placeholderRe.FindAllString(t, -1) {
		ok := false
		for _, q := range redirectPlaceholders {
			ok = ok || p == q
		}
		if !ok {
			return fmt.Errorf("unknown placeholder %s (use %s)", p, strings.Join(redirectPlaceholders, ", "))
		}
	}
	rest := ""
	switch {
	case strings.HasPrefix(t, "https://"):
		rest = t[len("https://"):]
	case strings.HasPrefix(t, "http://"):
		rest = t[len("http://"):]
	case strings.HasPrefix(t, "{scheme}://"):
		rest = t[len("{scheme}://"):]
	case strings.HasPrefix(t, "/"):
		if strings.HasPrefix(t, "//") {
			return fmt.Errorf("a url starting with // is a network-path reference; write the full https:// address")
		}
		sample := expandRedirect(t, "example.com", "/p", "q=1", "https")
		if _, err := url.Parse(sample); err != nil {
			return fmt.Errorf("the url is not valid: %v", err)
		}
		return nil
	default:
		return fmt.Errorf("a redirect url must start with http://, https:// or / (relative)")
	}
	// absolute: the authority (up to the first / ? #) may use {host} but not the request-controlled parts
	end := len(rest)
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		end = i
	}
	auth := rest[:end]
	if auth == "" {
		return fmt.Errorf("the url has no host name")
	}
	//{path} and {uri} always expand to something starting with "/", so they may end the authority
	//(https://example.com{uri}); anywhere else, or {query} / {scheme}, they could change the host
	auth = strings.TrimSuffix(strings.TrimSuffix(auth, "{path}"), "{uri}")
	for _, bad := range []string{"{path}", "{query}", "{uri}", "{scheme}"} {
		if strings.Contains(auth, bad) {
			return fmt.Errorf("%s cannot be used in the host part of the url", bad)
		}
	}
	if strings.Contains(auth, "@") {
		return fmt.Errorf("the url must not contain credentials (user@host)")
	}
	sample := expandRedirect(t, "example.com", "/p", "q=1", "https")
	u, err := url.Parse(sample)
	if err != nil || u.Host == "" {
		return fmt.Errorf("the url is not valid")
	}
	return nil
}

// safeURLPart percent-encodes everything that is not an unreserved or sub-delimiter URL character
func safeURLPart(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c > 0x20 && c < 0x7f && !strings.ContainsRune("\"<>\\^`{|}", rune(c)) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func safeHost(h string) string {
	var b strings.Builder
	for i := 0; i < len(h) && i < 253; i++ {
		c := h[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '[' || c == ']' || c == ':' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func expandRedirect(t, host, path, query, scheme string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	uri := path
	if query != "" {
		uri += "?" + query
	}
	r := strings.NewReplacer("{host}", safeHost(host), "{path}", safeURLPart(path), "{query}", safeURLPart(query),
		"{uri}", safeURLPart(uri), "{scheme}", scheme)
	out := r.Replace(t)
	if strings.HasPrefix(out, "/") {
		// A relative target must stay on this host: "//x" or "/\x" would be read as another host
		out = "/" + strings.TrimLeft(out, "/")
	}
	return out
}

// RedirectTarget expands the redirect template for a request. The result is a valid, single line Location
// that is either http(s) with the host fixed by the template, or an absolute path.
func (a *Action) RedirectTarget(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	p := r.URL.EscapedPath()
	return expandRedirect(a.URL, r.Host, p, r.URL.RawQuery, scheme)
}
