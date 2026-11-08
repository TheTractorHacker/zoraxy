package captcha

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

/*
	pages.go

	Rendering of the challenge / verification failed / blocked pages, their
	Content-Security-Policy and the validation of per-endpoint custom templates.
*/

//go:embed page_base.html challenge.html failed.html blocked.html
var pageFS embed.FS

// Test keys published by the providers. Used only for the admin preview; they
// never leave the browser and are not valid for real traffic.
const (
	PreviewTurnstileSiteKey = "1x00000000000000000000AA"
	PreviewRecaptchaSiteKey = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
)

// PageKind selects which page is rendered.
type PageKind string

const (
	PageChallenge PageKind = "challenge"
	PageFailed    PageKind = "failed"
	PageBlocked   PageKind = "blocked"
)

// Provider ids exposed to templates as {{.Provider}}.
const (
	ProviderIDTurnstile   = "turnstile"
	ProviderIDRecaptchaV2 = "recaptcha_v2"
	ProviderIDRecaptchaV3 = "recaptcha_v3"
)

// PageStrings are the status texts of the page, already defaulted.
type PageStrings struct {
	Verifying string
	Success   string
	Failed    string
	Error     string
	Retry     string
}

// ClientConfig is serialised as a JSON object into the page script. Custom
// templates normally get it for free through {{template "zx_runtime" .}}.
type ClientConfig struct {
	Provider   string `json:"provider"`
	SiteKey    string `json:"siteKey"`
	VerifyPath string `json:"verifyPath"`
	Field      string `json:"field"` // form field name the token is POSTed as
	Preview    bool   `json:"preview"`
	ShowLoader bool   `json:"showLoader"`
	S          struct {
		Verifying string `json:"verifying"`
		Success   string `json:"success"`
		Failed    string `json:"failed"`
		Error     string `json:"error"`
	} `json:"s"`
	Turnstile struct {
		Mode       string `json:"mode"`
		Appearance string `json:"appearance"`
		Theme      string `json:"theme"`
		Size       string `json:"size"`
		Action     string `json:"action"`
		CData      string `json:"cdata"`
	} `json:"turnstile"`
	Invisible bool   `json:"invisible"` // reCAPTCHA v2 invisible
	Action    string `json:"action"`    // reCAPTCHA v3 action
}

// TemplateData is the value every page template is executed with. It is the
// documented contract for custom templates; Domain, SiteKey and VerifyPath are
// the original three fields and keep working in legacy webroot templates.
type TemplateData struct {
	Domain     string
	SiteKey    string
	VerifyPath string

	Nonce    string // per-response CSP nonce, put it on every inline <script> and <style>
	Provider string // turnstile, recaptcha_v2 or recaptcha_v3
	Page     string // challenge, failed or blocked
	Preview  bool

	Title      string
	Heading    string
	Message    string
	Notice     string
	Strings    PageStrings
	LogoURL    template.URL // empty if no (valid) logo
	Accent     string
	Background string // empty = theme default
	Theme      string // auto, light or dark
	ShowFooter bool
	ShowLoader bool
	RetryURL   string // failed page: where the retry button leads

	Client ClientConfig
}

// RenderOptions tunes a render call.
type RenderOptions struct {
	WebDir   string // webroot that may hold legacy template overrides
	Preview  bool   // admin preview: dummy site key, nothing is verified, HTTP 200
	RetryURL string // failed page only, derived from the request when empty
}

func providerID(c *Config) string {
	if c == nil || c.Provider == ProviderCloudflare {
		return ProviderIDTurnstile
	}
	if c.RecaptchaVersion == "v3" {
		return ProviderIDRecaptchaV3
	}
	return ProviderIDRecaptchaV2
}

func pick(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func expandDomain(s, domain string) string {
	return strings.ReplaceAll(s, "{domain}", domain)
}

func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("captcha: no entropy for CSP nonce: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// buildData resolves the config (nil is allowed) into template data, applying
// defaults and re-validating every customisation value.
func buildData(cfg *Config, kind PageKind, domain, nonce string, opts RenderOptions) TemplateData {
	var b Branding
	if cfg != nil && cfg.Branding != nil {
		b = *cfg.Branding
	}
	var ts TurnstileOptions
	if cfg != nil && cfg.Turnstile != nil && cfg.Turnstile.Validate() == nil {
		ts = *cfg.Turnstile
	}
	prov := providerID(cfg)

	d := TemplateData{
		Domain:     domain,
		VerifyPath: VerifyPath,
		Nonce:      nonce,
		Provider:   prov,
		Page:       string(kind),
		Preview:    opts.Preview,
		Accent:     DefaultAccentColor,
		Theme:      ThemeAuto,
		ShowFooter: !b.HideFooter,
		LogoURL:    safeLogo(b.LogoURL),
		RetryURL:   opts.RetryURL,
	}
	if cfg != nil {
		d.SiteKey = cfg.SiteKey
	}
	if opts.Preview {
		if prov == ProviderIDTurnstile {
			d.SiteKey = PreviewTurnstileSiteKey
		} else {
			d.SiteKey = PreviewRecaptchaSiteKey
		}
	}
	if hexColorRe.MatchString(b.AccentColor) {
		d.Accent = b.AccentColor
	}
	if hexColorRe.MatchString(b.BackgroundColor) {
		d.Background = b.BackgroundColor
	}
	if oneOf(b.Theme, ThemeLight, ThemeDark) {
		d.Theme = b.Theme
	}

	text := func(v, def string) string { return expandDomain(pick(v, def), domain) }
	d.Strings = PageStrings{
		Verifying: text(b.VerifyingText, DefaultVerifyingText),
		Success:   text(b.SuccessText, DefaultSuccessText),
		Failed:    text(b.FailedText, DefaultFailedText),
		Error:     text(b.ErrorText, DefaultErrorText),
		Retry:     text(b.RetryText, DefaultRetryText),
	}

	switch kind {
	case PageFailed:
		d.Title = text(b.Title, DefaultFailedHeading)
		d.Heading = DefaultFailedHeading
		d.Message = d.Strings.Failed
	case PageBlocked:
		d.Title = text(b.BlockedTitle, DefaultBlockedTitle)
		d.Heading = text(b.BlockedHeading, DefaultBlockedHeading)
		d.Message = text(b.BlockedMessage, DefaultBlockedMessage)
		d.ShowLoader = false
	default:
		defMsg := DefaultMessage
		if prov == ProviderIDRecaptchaV3 {
			defMsg = DefaultMessageV3
		}
		d.Title = text(b.Title, DefaultTitle)
		d.Heading = text(b.Heading, domain)
		d.Message = text(b.Message, defMsg)
		d.Notice = text(b.Notice, DefaultNotice)
	}
	if kind == PageFailed {
		d.Notice = text(b.Notice, "")
	}

	// client side configuration
	c := &d.Client
	c.Provider = prov
	c.SiteKey = d.SiteKey
	c.VerifyPath = VerifyPath
	c.Preview = opts.Preview
	c.S.Verifying, c.S.Success, c.S.Failed, c.S.Error = d.Strings.Verifying, d.Strings.Success, d.Strings.Failed, d.Strings.Error
	switch prov {
	case ProviderIDTurnstile:
		c.Field = "cf-turnstile-response"
		c.Turnstile.Mode, c.Turnstile.Appearance, c.Turnstile.Theme = ts.Mode, ts.Appearance, ts.Theme
		c.Turnstile.Size, c.Turnstile.Action, c.Turnstile.CData = ts.Size, ts.Action, ts.CData
		d.ShowLoader = ts.Mode == "invisible" || ts.Mode == "non-interactive" || ts.Appearance == "interaction-only"
	case ProviderIDRecaptchaV2:
		c.Field = "g-recaptcha-response"
		c.Invisible = cfg != nil && cfg.RecaptchaInvisible
		d.ShowLoader = c.Invisible
	default:
		c.Field = "g-recaptcha-response"
		c.Action = "access"
		if cfg != nil {
			c.Action = cfg.recaptchaAction()
		}
		d.ShowLoader = true
	}
	if kind != PageChallenge {
		d.ShowLoader = false
	}
	c.ShowLoader = d.ShowLoader
	return d
}

// contentSecurityPolicy returns the CSP for a page. Inline script and style
// are only allowed through the per-response nonce, and only the hosts the
// provider widget needs are reachable. relaxed is for legacy webroot
// templates written before nonces existed.
func contentSecurityPolicy(prov string, kind PageKind, nonce string, relaxed, preview bool) string {
	n := "'nonce-" + nonce + "'"
	ancestors := "'none'"
	if preview {
		ancestors = "'self'"
	}
	script := n
	style := n
	frame := ""
	connect := "'self'"
	if kind == PageChallenge {
		switch prov {
		case ProviderIDTurnstile:
			script += " https://challenges.cloudflare.com"
			frame = "https://challenges.cloudflare.com"
			connect += " https://challenges.cloudflare.com"
		default:
			script += " https://www.google.com https://www.gstatic.com"
			frame = "https://www.google.com https://recaptcha.google.com"
			connect += " https://www.google.com"
			// reCAPTCHA injects inline styles that cannot carry a nonce
			style = "'unsafe-inline'"
		}
	}
	if relaxed {
		script = strings.Replace(script, n, "'unsafe-inline'", 1)
		style = "'unsafe-inline'"
	}
	parts := []string{
		"default-src 'none'",
		"script-src " + script,
		"style-src " + style,
		"img-src 'self' data: https:",
		"connect-src " + connect,
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors " + ancestors,
	}
	if frame != "" {
		parts = append(parts, "frame-src "+frame)
	}
	return strings.Join(parts, "; ")
}

func readEmbedded(name string) string {
	b, err := pageFS.ReadFile(name)
	if err != nil {
		panic("captcha: missing embedded template " + name)
	}
	return string(b)
}

// parsePage parses the shared definitions plus one page body.
func parsePage(body string) (*template.Template, error) {
	t := template.New("zx_root")
	if _, err := t.Parse(readEmbedded("page_base.html")); err != nil {
		return nil, err
	}
	if _, err := t.New("page").Parse(body); err != nil {
		return nil, err
	}
	return t, nil
}

var (
	builtinMu    sync.Mutex
	builtinCache = map[PageKind]*template.Template{}

	customMu    sync.Mutex
	customCache = map[string]*template.Template{}
)

func builtinPage(kind PageKind) (*template.Template, error) {
	builtinMu.Lock()
	defer builtinMu.Unlock()
	if t, ok := builtinCache[kind]; ok {
		return t, nil
	}
	t, err := parsePage(readEmbedded(string(kind) + ".html"))
	if err != nil {
		return nil, err
	}
	builtinCache[kind] = t
	return t, nil
}

func customPage(content string) (*template.Template, error) {
	sum := sha256.Sum256([]byte(content))
	key := hex.EncodeToString(sum[:])
	customMu.Lock()
	defer customMu.Unlock()
	if t, ok := customCache[key]; ok {
		return t, nil
	}
	t, err := parsePage(content)
	if err != nil {
		return nil, err
	}
	if len(customCache) >= 64 {
		customCache = map[string]*template.Template{}
	}
	customCache[key] = t
	return t, nil
}

// executePage runs t, converting a panic into an error so a bad template can
// never take the proxy down.
func executePage(t *template.Template, data TemplateData) (out []byte, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("template panicked: %v", rec)
		}
	}()
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "page", data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ValidateCustomTemplate checks a custom challenge template: size limit, html/template
// syntax, and one sample render for every provider. Call it when saving.
func ValidateCustomTemplate(content string) error {
	if len(content) > MaxCustomTemplateBytes {
		return fmt.Errorf("custom template is too large (max %d KiB)", MaxCustomTemplateBytes/1024)
	}
	if strings.TrimSpace(content) == "" {
		return errors.New("custom template is empty")
	}
	// Fresh, uncached parse: a syntax error must surface here.
	t, err := parsePage(content)
	if err != nil {
		return fmt.Errorf("custom template does not parse: %w", err)
	}
	samples := []*Config{
		{Provider: ProviderCloudflare, SiteKey: "sample-site-key"},
		{Provider: ProviderGoogle, RecaptchaVersion: "v2", SiteKey: "sample-site-key"},
		{Provider: ProviderGoogle, RecaptchaVersion: "v3", SiteKey: "sample-site-key"},
	}
	for _, cfg := range samples {
		data := buildData(cfg, PageChallenge, "example.com", "sample-nonce", RenderOptions{})
		if _, err := executePage(t, data); err != nil {
			return fmt.Errorf("custom template failed to render (%s): %w", data.Provider, err)
		}
	}
	return nil
}

// loadExternalTemplate tries to load a legacy override from <webroot>/templates.
func loadExternalTemplate(webDir string, templateName string) (string, error) {
	for _, path := range []string{
		filepath.Join(webDir, "templates", templateName+".html"),
		filepath.Join(webDir, "templates", templateName+".tmpl"),
	} {
		if _, err := os.Stat(path); err == nil {
			content, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("failed to read external template: %w", err)
			}
			return string(content), nil
		}
	}
	return "", os.ErrNotExist
}

func legacyTemplateName(prov string) string {
	switch prov {
	case ProviderIDTurnstile:
		return "captcha_cloudflare"
	case ProviderIDRecaptchaV2:
		return "captcha_recaptcha_v2"
	}
	return "captcha_recaptcha_v3"
}

// retryURLFor picks where the "try again" button of the failed page leads: the
// page the visitor came from when it is on the same host, else the site root.
func retryURLFor(r *http.Request) string {
	if ref, err := url.Parse(r.Referer()); err == nil && ref.Host != "" && sameHost(ref.Host, r.Host) {
		p := ref.EscapedPath()
		if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && p != VerifyPath {
			if ref.RawQuery != "" {
				p += "?" + ref.RawQuery
			}
			return p
		}
	}
	return "/"
}

func statusFor(kind PageKind, preview bool) int {
	if preview {
		return http.StatusOK
	}
	if kind == PageFailed {
		return http.StatusUnauthorized
	}
	return http.StatusForbidden
}

// renderPage is the single place that turns a config into a response.
func renderPage(w http.ResponseWriter, r *http.Request, cfg *Config, kind PageKind, domain string, opts RenderOptions) {
	nonce := newNonce()
	if kind == PageFailed && opts.RetryURL == "" {
		opts.RetryURL = retryURLFor(r)
	}
	data := buildData(cfg, kind, domain, nonce, opts)

	var t *template.Template
	var err error
	relaxed := false
	switch {
	case kind == PageChallenge && cfg != nil && cfg.Branding != nil && cfg.Branding.CustomTemplate != "":
		t, err = customPage(cfg.Branding.CustomTemplate)
	default:
		if kind == PageChallenge && opts.WebDir != "" && !opts.Preview {
			if legacy, lerr := loadExternalTemplate(opts.WebDir, legacyTemplateName(data.Provider)); lerr == nil && legacy != "" {
				// Legacy overrides predate nonces, so they get the relaxed CSP.
				relaxed = true
				t, err = template.New("page").Parse(legacy)
				break
			}
		}
		t, err = builtinPage(kind)
	}

	var body []byte
	if err == nil {
		body, err = executePage(t, data)
	}
	if err != nil {
		// A broken template must not take the page down: fall back to the stock page.
		if kind == PageChallenge && cfg != nil && ((cfg.Branding != nil && cfg.Branding.CustomTemplate != "") || relaxed) {
			stock := *cfg
			b := Branding{}
			if cfg.Branding != nil {
				b = *cfg.Branding
			}
			b.CustomTemplate = ""
			stock.Branding = &b
			renderPage(w, r, &stock, kind, domain, RenderOptions{Preview: opts.Preview})
			return
		}
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", contentSecurityPolicy(data.Provider, kind, nonce, relaxed, opts.Preview))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	if !opts.Preview {
		h.Set("X-Frame-Options", "DENY")
	}
	w.WriteHeader(statusFor(kind, opts.Preview))
	w.Write(body)
}

// RenderChallenge renders the CAPTCHA challenge page (HTTP 403).
func RenderChallenge(w http.ResponseWriter, r *http.Request, config *Config, domain string, webDir string) {
	renderPage(w, r, config, PageChallenge, domain, RenderOptions{WebDir: webDir})
}

// RenderFailed renders the "verification failed" page with a retry button (HTTP 401).
func RenderFailed(w http.ResponseWriter, r *http.Request, config *Config, domain string, opts RenderOptions) {
	renderPage(w, r, config, PageFailed, domain, opts)
}

// RenderBlocked renders the generic "blocked" page (HTTP 403). config may be nil.
func RenderBlocked(w http.ResponseWriter, r *http.Request, config *Config, domain string) {
	renderPage(w, r, config, PageBlocked, domain, RenderOptions{})
}

// RenderPreview renders any page for the admin preview: dummy site key, HTTP
// 200, nothing is verified and no external service is called by the server.
func RenderPreview(w http.ResponseWriter, r *http.Request, config *Config, kind PageKind, domain string) {
	renderPage(w, r, config, kind, domain, RenderOptions{Preview: true})
}
