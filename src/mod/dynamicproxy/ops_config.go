package dynamicproxy

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

/*
	ops_config.go

	Per proxy rule "ops" options, all optional (nil = nothing changes):
	  - ErrorPages      custom pages for selected status codes        (upstream #313)
	  - StaticResponses fixed responses served without the upstream   (upstream #431)
	  - CORS            proxy handled CORS policy and preflight       (upstream #680)
	  - Bandwidth       response bandwidth limit                      (upstream #1208)

	Config, validation and compilation live here; request handling is in ops_handlers.go and
	ops_writer.go. A compiled runtime is built lazily and cached on the config object; an edit
	always produces a new config object (copy of the endpoint), so the cache never goes stale.
*/

type OpsConfig struct {
	ErrorPages       *ErrorPagesConfig `json:",omitempty"`
	StaticResponses  []*StaticResponse `json:",omitempty"`
	CORS             *CORSConfig       `json:",omitempty"`
	Bandwidth        *BandwidthConfig  `json:",omitempty"`
	ExposeRequestID  bool              `json:",omitempty"` //Add X-Request-Id to responses
	ForwardRequestID bool              `json:",omitempty"` //Add X-Request-Id to requests sent to the upstream

	rt atomic.Pointer[opsRuntime] `json:"-"`
}

const (
	ErrorPagesInherit = "inherit"
	ErrorPagesOff     = "off"
	ErrorPagesOn      = "on"

	MaxOpsTemplateBytes = 64 * 1024
	MaxOpsBodyBytes     = 64 * 1024
)

// ErrorPagesConfig selects the status codes that are answered with a custom page instead of the upstream's body
type ErrorPagesConfig struct {
	Mode              string            //"on", "off" or "inherit" (endpoint only: use the global default; the default)
	Statuses          []int             //Status codes (400-599) to replace, e.g. 502, 503, 504
	Template          string            //html/template used for every listed status; empty = built in page
	StatusTemplates   map[string]string `json:",omitempty"` //Optional template per status code ("503": "...")
	RetryAfterSeconds int               `json:",omitempty"` //Retry-After for 429/503 if the response has none (0 = none)
}

// Template data: .Status .StatusText .RequestID .Host .Path .RuleName
type ErrorPageData struct {
	Status     int
	StatusText string
	RequestID  string
	Host       string
	Path       string
	RuleName   string
}

const defaultErrorPageTemplate = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Status}} {{.StatusText}}</title>
<style>body{font-family:system-ui,sans-serif;background:#f4f5f7;color:#222;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
main{background:#fff;padding:2rem 2.5rem;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1);max-width:32rem}
h1{margin:0 0 .5rem;font-size:3rem}p{color:#555}small{color:#888}</style></head>
<body><main><h1>{{.Status}}</h1><p>{{.StatusText}}</p><small>{{.Host}} &middot; request {{.RequestID}}</small></main></body></html>`

// StaticResponse is a fixed response for a path, answered by Zoraxy itself
type StaticResponse struct {
	Name        string
	Path        string   //Request path, must start with /
	MatchMode   string   //"exact" (default) or "prefix" (segment boundary)
	Methods     []string //Default GET and HEAD
	Status      int      //Default 200
	ContentType string   //Default text/plain; charset=utf-8
	Body        string   //Up to 64 KiB. {{variables}} are expanded
	Location    string   //Redirect target for 3xx statuses
	Headers     []StaticHeader
	Public      bool //Evaluated before client certificate, WAF, rate limit and authentication (access lists still apply)
	Disabled    bool
}

type StaticHeader struct {
	Name  string
	Value string
}

// CORSConfig is the proxy handled CORS policy
type CORSConfig struct {
	Enabled          bool
	AllowedOrigins   []string //Exact "https://a.example", wildcard "https://*.example.com", "regex:^https://x[0-9]+\\.example\\.com$" or "*"
	AllowedMethods   []string //Default GET, HEAD, POST
	AllowedHeaders   []string //Empty = reflect Access-Control-Request-Headers; "*" allows any
	ExposeHeaders    []string
	AllowCredentials bool //Never combined with "*": the matched origin is echoed instead (an "*" origin entry is refused)
	MaxAgeSeconds    int  //Access-Control-Max-Age of preflight answers (0 = header omitted)
}

// BandwidthConfig limits the response bandwidth
type BandwidthConfig struct {
	BytesPerSecond          int64 //Per connection (response), 0 = unlimited
	PerClientBytesPerSecond int64 //Shared by all connections of one client IP, 0 = unlimited
}

// ---- validation ----

var forbiddenStaticHeaders = map[string]bool{
	"content-length": true, "transfer-encoding": true, "connection": true, "upgrade": true,
	"host": true, "content-type": true, "location": true, "trailer": true, "te": true, "keep-alive": true,
}

func hasControl(s string) bool {
	for _, c := range s {
		if c < 0x20 && c != '\t' || c == 0x7f {
			return true
		}
	}
	return false
}

// Validate checks the whole ops config
func (o *OpsConfig) Validate() error {
	if o == nil {
		return nil
	}
	if err := o.ErrorPages.Validate(); err != nil {
		return fmt.Errorf("error pages: %w", err)
	}
	if len(o.StaticResponses) > 100 {
		return errors.New("too many static responses (max 100)")
	}
	seen := map[string]bool{}
	for i, s := range o.StaticResponses {
		if s == nil {
			return fmt.Errorf("static response %d is empty", i+1)
		}
		if err := s.Validate(); err != nil {
			return fmt.Errorf("static response %d (%s): %w", i+1, s.Path, err)
		}
		key := s.MatchMode + "|" + s.Path
		if seen[key] {
			return fmt.Errorf("static response %d: duplicate path %s", i+1, s.Path)
		}
		seen[key] = true
	}
	if err := o.CORS.Validate(); err != nil {
		return fmt.Errorf("CORS: %w", err)
	}
	if err := o.Bandwidth.Validate(); err != nil {
		return fmt.Errorf("bandwidth: %w", err)
	}
	return nil
}

func (e *ErrorPagesConfig) Validate() error {
	if e == nil {
		return nil
	}
	switch e.Mode {
	case "", ErrorPagesInherit, ErrorPagesOff, ErrorPagesOn:
	default:
		return errors.New("mode must be on, off or inherit")
	}
	if len(e.Statuses) > 64 {
		return errors.New("too many status codes")
	}
	for _, c := range e.Statuses {
		if c < 400 || c > 599 {
			return fmt.Errorf("status %d is outside 400-599", c)
		}
	}
	if e.RetryAfterSeconds < 0 || e.RetryAfterSeconds > 86400 {
		return errors.New("Retry-After must be between 0 and 86400 seconds")
	}
	if len(e.StatusTemplates) > 32 {
		return errors.New("too many per status templates")
	}
	if _, err := compileErrorTemplate(e.Template); err != nil {
		return err
	}
	for k, v := range e.StatusTemplates {
		code, err := strconv.Atoi(k)
		if err != nil || code < 400 || code > 599 {
			return fmt.Errorf("invalid per status template key %q", k)
		}
		if _, err := compileErrorTemplate(v); err != nil {
			return fmt.Errorf("template for %s: %w", k, err)
		}
	}
	return nil
}

// compileErrorTemplate parses an html/template and test-renders it. Empty = built in page.
func compileErrorTemplate(src string) (*template.Template, error) {
	if src == "" {
		src = defaultErrorPageTemplate
	}
	if len(src) > MaxOpsTemplateBytes {
		return nil, errors.New("template is larger than 64 KiB")
	}
	t, err := template.New("errpage").Option("missingkey=zero").Parse(src)
	if err != nil {
		return nil, fmt.Errorf("template error: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ErrorPageData{Status: 502, StatusText: "Bad Gateway", RequestID: "preview", Host: "example.com", Path: "/", RuleName: "rule"}); err != nil {
		return nil, fmt.Errorf("template cannot be rendered: %w", err)
	}
	return t, nil
}

// RenderErrorPagePreview renders a template with sample data (used by the UI preview)
func RenderErrorPagePreview(src string, status int) (string, error) {
	t, err := compileErrorTemplate(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, ErrorPageData{Status: status, StatusText: http.StatusText(status), RequestID: "0123456789abcdef", Host: "app.example.com", Path: "/example", RuleName: "app.example.com"})
	return buf.String(), err
}

func (s *StaticResponse) normalize() {
	if s.MatchMode == "" {
		s.MatchMode = "exact"
	}
	if s.Status == 0 {
		s.Status = 200
	}
}

func (s *StaticResponse) Validate() error {
	s.normalize()
	if !strings.HasPrefix(s.Path, "/") || hasControl(s.Path) || strings.ContainsAny(s.Path, "?#") || len(s.Path) > 1024 {
		return errors.New("path must start with / and contain no query, fragment or control characters")
	}
	if s.MatchMode != "exact" && s.MatchMode != "prefix" {
		return errors.New("match mode must be exact or prefix")
	}
	if s.Status < 200 || s.Status > 599 {
		return errors.New("status must be 200-599")
	}
	for _, m := range s.Methods {
		switch strings.ToUpper(m) {
		case "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS":
		default:
			return fmt.Errorf("unsupported method %q", m)
		}
	}
	if len(s.Body) > MaxOpsBodyBytes {
		return errors.New("body is larger than 64 KiB")
	}
	if hasControl(s.ContentType) || len(s.ContentType) > 200 {
		return errors.New("invalid content type")
	}
	if s.Status >= 300 && s.Status < 400 && s.Status != 304 {
		if s.Location == "" {
			return errors.New("a redirect status needs a Location")
		}
	}
	if s.Location != "" {
		if hasControl(s.Location) || strings.ContainsAny(s.Location, " \\") {
			return errors.New("invalid Location")
		}
		if !strings.HasPrefix(s.Location, "/") || strings.HasPrefix(s.Location, "//") {
			u, err := url.Parse(s.Location)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return errors.New("Location must be a path or an http(s) URL")
			}
		}
	}
	if len(s.Headers) > 32 {
		return errors.New("too many headers")
	}
	for _, h := range s.Headers {
		if !headerNameRe.MatchString(h.Name) || forbiddenStaticHeaders[strings.ToLower(h.Name)] {
			return fmt.Errorf("header name %q is not allowed", h.Name)
		}
		if hasControl(h.Value) || len(h.Value) > 4096 {
			return fmt.Errorf("invalid value for header %s", h.Name)
		}
	}
	return nil
}

func (c *CORSConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if len(c.AllowedOrigins) == 0 {
		return errors.New("at least one allowed origin is required")
	}
	if len(c.AllowedOrigins) > 100 {
		return errors.New("too many allowed origins")
	}
	for _, o := range c.AllowedOrigins {
		if o == "*" && c.AllowCredentials {
			return errors.New("the wildcard origin * cannot be combined with credentials; list the origins explicitly")
		}
		if _, err := compileOriginMatcher(o); err != nil {
			return err
		}
	}
	for _, list := range [][]string{c.AllowedMethods, c.AllowedHeaders, c.ExposeHeaders} {
		if len(list) > 64 {
			return errors.New("list too long")
		}
		for _, v := range list {
			if v != "*" && !headerNameRe.MatchString(v) {
				return fmt.Errorf("invalid token %q", v)
			}
		}
	}
	if c.AllowCredentials {
		for _, v := range append(append([]string{}, c.AllowedHeaders...), c.ExposeHeaders...) {
			if v == "*" {
				return errors.New("* in headers has no wildcard meaning with credentials; list the headers")
			}
		}
	}
	if c.MaxAgeSeconds < 0 || c.MaxAgeSeconds > 86400 {
		return errors.New("max age must be between 0 and 86400 seconds")
	}
	return nil
}

func (b *BandwidthConfig) Validate() error {
	if b == nil {
		return nil
	}
	if b.BytesPerSecond < 0 || b.PerClientBytesPerSecond < 0 {
		return errors.New("limits cannot be negative")
	}
	for _, v := range []int64{b.BytesPerSecond, b.PerClientBytesPerSecond} {
		if v != 0 && v < 100 {
			return errors.New("a limit below 100 bytes per second is not useful")
		}
	}
	return nil
}

// ---- origin matching ----

type originMatcher struct {
	any   bool
	exact string
	re    *regexp.Regexp
}

var originShape = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/?#\s]+$`)

func compileOriginMatcher(pattern string) (*originMatcher, error) {
	switch {
	case pattern == "*":
		return &originMatcher{any: true}, nil
	case strings.HasPrefix(pattern, "regex:"):
		expr := strings.TrimPrefix(pattern, "regex:")
		if len(expr) > 500 {
			return nil, errors.New("origin regex too long")
		}
		re, err := regexp.Compile("^(?:" + expr + ")$")
		if err != nil {
			return nil, fmt.Errorf("invalid origin regex: %w", err)
		}
		return &originMatcher{re: re}, nil
	case strings.Contains(pattern, "*"):
		if !originShape.MatchString(strings.ReplaceAll(pattern, "*", "x")) || strings.Count(pattern, "*") != 1 || !strings.Contains(pattern, "://*.") {
			return nil, fmt.Errorf("wildcard origin %q must look like https://*.example.com", pattern)
		}
		quoted := regexp.QuoteMeta(pattern)
		quoted = strings.Replace(quoted, `\*`, `[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*`, 1)
		return &originMatcher{re: regexp.MustCompile("^" + quoted + "$")}, nil
	case pattern == "null":
		return &originMatcher{exact: "null"}, nil
	default:
		if !originShape.MatchString(pattern) {
			return nil, fmt.Errorf("origin %q must be scheme://host[:port] without a path", pattern)
		}
		return &originMatcher{exact: strings.ToLower(pattern)}, nil
	}
}

func (m *originMatcher) match(origin string) bool {
	switch {
	case m.any:
		return true
	case m.re != nil:
		return m.re.MatchString(origin) || m.re.MatchString(strings.ToLower(origin))
	default:
		return strings.ToLower(origin) == m.exact
	}
}

// ---- compiled runtime ----

type opsRuntime struct {
	errPages      *errorPagesRuntime
	statics       []*StaticResponse
	corsOrigins   []*originMatcher
	corsMethods   []string
	corsAnyOrigin bool
	bw            *bandwidthRuntime
}

type errorPagesRuntime struct {
	statuses   map[int]bool
	def        *template.Template
	perStatus  map[int]*template.Template
	retryAfter int
}

func buildErrorPagesRuntime(c *ErrorPagesConfig) *errorPagesRuntime {
	if c == nil || len(c.Statuses) == 0 {
		return nil
	}
	def, err := compileErrorTemplate(c.Template)
	if err != nil {
		def, _ = compileErrorTemplate("")
	}
	rt := &errorPagesRuntime{statuses: map[int]bool{}, def: def, perStatus: map[int]*template.Template{}, retryAfter: c.RetryAfterSeconds}
	for _, s := range c.Statuses {
		rt.statuses[s] = true
	}
	for k, v := range c.StatusTemplates {
		if code, err := strconv.Atoi(k); err == nil {
			if t, err := compileErrorTemplate(v); err == nil {
				rt.perStatus[code] = t
			}
		}
	}
	return rt
}

// runtime returns the compiled config (never nil for a non nil receiver)
func (o *OpsConfig) runtime() *opsRuntime {
	if rt := o.rt.Load(); rt != nil {
		return rt
	}
	rt := &opsRuntime{}
	if o.ErrorPages != nil && (o.ErrorPages.Mode == ErrorPagesOn) {
		rt.errPages = buildErrorPagesRuntime(o.ErrorPages)
	}
	for _, s := range o.StaticResponses {
		if s != nil && !s.Disabled {
			c := *s
			c.normalize()
			rt.statics = append(rt.statics, &c)
		}
	}
	if o.CORS != nil && o.CORS.Enabled && o.CORS.Validate() == nil {
		for _, p := range o.CORS.AllowedOrigins {
			if m, err := compileOriginMatcher(p); err == nil {
				rt.corsOrigins = append(rt.corsOrigins, m)
				if m.any {
					rt.corsAnyOrigin = true
				}
			}
		}
		rt.corsMethods = o.CORS.AllowedMethods
		if len(rt.corsMethods) == 0 {
			rt.corsMethods = []string{"GET", "HEAD", "POST"}
		}
	}
	if o.Bandwidth != nil && (o.Bandwidth.BytesPerSecond > 0 || o.Bandwidth.PerClientBytesPerSecond > 0) {
		rt.bw = newBandwidthRuntime(o.Bandwidth)
	}
	o.rt.CompareAndSwap(nil, rt)
	return o.rt.Load()
}
