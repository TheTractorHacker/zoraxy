package captcha

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

/*
	branding.go

	Per-endpoint customisation of the CAPTCHA pages. Everything here is
	optional: an empty Branding (or a nil pointer) renders the stock look, so
	configs saved before this feature existed behave exactly as before.
*/

const (
	// MaxLogoBytes is the largest decoded logo accepted as a data URI.
	MaxLogoBytes = 256 * 1024
	// MaxCustomTemplateBytes is the largest custom HTML template accepted.
	MaxCustomTemplateBytes = 64 * 1024

	maxTitleLen   = 120
	maxHeadingLen = 200
	maxMessageLen = 500
	maxStringLen  = 200
)

// Theme values for Branding.Theme
const (
	ThemeAuto  = "auto"
	ThemeLight = "light"
	ThemeDark  = "dark"
)

// Default texts. They match the wording of the pages before they became customisable.
const (
	DefaultTitle          = "Just a moment..."
	DefaultMessage        = "Verify you are human by completing the action below."
	DefaultMessageV3      = "Verifying your connection..."
	DefaultNotice         = "{domain} needs to review the security of your connection before proceeding."
	DefaultVerifyingText  = "Verifying..."
	DefaultSuccessText    = "Verification successful! Redirecting..."
	DefaultFailedText     = "Verification failed. Please try again."
	DefaultErrorText      = "An error occurred. Please try again."
	DefaultRetryText      = "Try again"
	DefaultFailedHeading  = "Verification failed"
	DefaultBlockedTitle   = "Access blocked"
	DefaultBlockedHeading = "Access blocked"
	DefaultBlockedMessage = "Your request was blocked by the security rules of this site."
	DefaultAccentColor    = "#2c7cb0"
)

// Branding holds the optional look-and-feel overrides of an endpoint's CAPTCHA
// pages. Empty strings mean "use the default". In every text field the
// placeholder {domain} is replaced by the requested host name. All text is
// HTML-escaped when rendered.
type Branding struct {
	Title          string `json:"Title,omitempty"`          // <title> of the challenge page
	Heading        string `json:"Heading,omitempty"`        // main heading, default: the host name
	Message        string `json:"Message,omitempty"`        // text under the heading
	Notice         string `json:"Notice,omitempty"`         // text under the widget
	VerifyingText  string `json:"VerifyingText,omitempty"`  // shown while the token is being checked
	SuccessText    string `json:"SuccessText,omitempty"`    // shown after a successful check
	FailedText     string `json:"FailedText,omitempty"`     // shown when the check was rejected
	ErrorText      string `json:"ErrorText,omitempty"`      // shown on network / widget errors
	RetryText      string `json:"RetryText,omitempty"`      // label of the retry button
	BlockedTitle   string `json:"BlockedTitle,omitempty"`   // <title> of the blocked page
	BlockedHeading string `json:"BlockedHeading,omitempty"` // heading of the blocked page
	BlockedMessage string `json:"BlockedMessage,omitempty"` // text of the blocked page

	LogoURL         string `json:"LogoURL,omitempty"`         // https URL or data:image/(png|jpeg|gif|webp);base64,... (max 256 KiB decoded)
	AccentColor     string `json:"AccentColor,omitempty"`     // CSS hex colour, default #2c7cb0
	BackgroundColor string `json:"BackgroundColor,omitempty"` // CSS hex colour, default follows the theme
	Theme           string `json:"Theme,omitempty"`           // auto (default), light or dark
	HideFooter      bool   `json:"HideFooter,omitempty"`      // hide the "Performance & security by Zoraxy" footer
	FooterText      string `json:"FooterText,omitempty"`      // replaces "Performance & security by"
	FooterLinkText  string `json:"FooterLinkText,omitempty"`  // replaces the link label "Zoraxy"
	FooterLinkURL   string `json:"FooterLinkURL,omitempty"`   // http(s) URL of the footer link; empty = Zoraxy website

	// CustomTemplate replaces the built-in challenge page for this endpoint.
	// It is an html/template, see DEVELOPMENT.md ("Customising CAPTCHA pages").
	CustomTemplate string `json:"CustomTemplate,omitempty"`
}

// TurnstileOptions are the Cloudflare Turnstile specific settings. Empty values
// mean the Turnstile default.
type TurnstileOptions struct {
	Mode       string `json:"Mode,omitempty"`       // managed (default), non-interactive, invisible. Must match the widget type of the site key.
	Appearance string `json:"Appearance,omitempty"` // always (default), execute, interaction-only
	Theme      string `json:"Theme,omitempty"`      // auto (default), light, dark
	Size       string `json:"Size,omitempty"`       // normal (default), flexible, compact
	Action     string `json:"Action,omitempty"`     // bound to the token, checked in siteverify when set
	CData      string `json:"CData,omitempty"`      // bound to the token, checked in siteverify when set
}

var (
	hexColorRe   = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)
	actionNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	cdataRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
)

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func checkLen(name, v string, max int) error {
	if utf8.RuneCountInString(v) > max {
		return fmt.Errorf("%s is too long (max %d characters)", name, max)
	}
	return nil
}

// ValidateLogo checks that logo is an https URL or a small base64 raster image
// data URI. The empty string is valid (no logo).
func ValidateLogo(logo string) error {
	if logo == "" {
		return nil
	}
	if strings.HasPrefix(logo, "data:") {
		if len(logo) > MaxLogoBytes*4/3+128 {
			return fmt.Errorf("logo is too large (max %d KiB)", MaxLogoBytes/1024)
		}
		header, payload, ok := strings.Cut(logo, ",")
		if !ok {
			return errors.New("logo data URI is malformed")
		}
		var mime string
		switch header {
		case "data:image/png;base64":
			mime = "image/png"
		case "data:image/jpeg;base64":
			mime = "image/jpeg"
		case "data:image/gif;base64":
			mime = "image/gif"
		case "data:image/webp;base64":
			mime = "image/webp"
		default:
			return errors.New("logo must be a base64 PNG, JPEG, GIF or WebP image (SVG is not accepted)")
		}
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return errors.New("logo data URI is not valid base64")
		}
		if len(raw) > MaxLogoBytes {
			return fmt.Errorf("logo is too large (max %d KiB)", MaxLogoBytes/1024)
		}
		if detected := http.DetectContentType(raw); detected != mime {
			return fmt.Errorf("logo content is %s but the data URI claims %s", detected, mime)
		}
		return nil
	}
	if len(logo) > 2048 {
		return errors.New("logo URL is too long")
	}
	u, err := url.Parse(logo)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("logo must be an https:// URL or an uploaded image")
	}
	return nil
}

// Validate checks the branding fields and returns a clear error for the first
// invalid one. It does not check CustomTemplate; see ValidateCustomTemplate.
func (b *Branding) Validate() error {
	if b == nil {
		return nil
	}
	for _, f := range []struct {
		name, v string
		max     int
	}{
		{"Page title", b.Title, maxTitleLen}, {"Blocked page title", b.BlockedTitle, maxTitleLen},
		{"Heading", b.Heading, maxHeadingLen}, {"Blocked page heading", b.BlockedHeading, maxHeadingLen},
		{"Message", b.Message, maxMessageLen}, {"Notice", b.Notice, maxMessageLen}, {"Blocked page message", b.BlockedMessage, maxMessageLen},
		{"Verifying text", b.VerifyingText, maxStringLen}, {"Success text", b.SuccessText, maxStringLen},
		{"Footer text", b.FooterText, maxStringLen}, {"Footer link text", b.FooterLinkText, maxTitleLen}, {"Footer link URL", b.FooterLinkURL, 512},
		{"Failed text", b.FailedText, maxStringLen}, {"Error text", b.ErrorText, maxStringLen}, {"Retry text", b.RetryText, maxStringLen},
	} {
		if err := checkLen(f.name, f.v, f.max); err != nil {
			return err
		}
	}
	if b.AccentColor != "" && !hexColorRe.MatchString(b.AccentColor) {
		return errors.New("accent colour must be a hex colour like #2c7cb0")
	}
	if b.BackgroundColor != "" && !hexColorRe.MatchString(b.BackgroundColor) {
		return errors.New("background colour must be a hex colour like #ffffff")
	}
	if b.Theme != "" && !oneOf(b.Theme, ThemeAuto, ThemeLight, ThemeDark) {
		return errors.New("theme must be auto, light or dark")
	}
	if b.FooterLinkURL != "" && safeFooterURL(b.FooterLinkURL) == "" {
		return errors.New("footer link must be an http:// or https:// URL")
	}
	return ValidateLogo(b.LogoURL)
}

// Validate checks the Turnstile options.
func (t *TurnstileOptions) Validate() error {
	if t == nil {
		return nil
	}
	if t.Mode != "" && !oneOf(t.Mode, "managed", "non-interactive", "invisible") {
		return errors.New("turnstile mode must be managed, non-interactive or invisible")
	}
	if t.Appearance != "" && !oneOf(t.Appearance, "always", "execute", "interaction-only") {
		return errors.New("turnstile appearance must be always, execute or interaction-only")
	}
	if t.Theme != "" && !oneOf(t.Theme, "auto", "light", "dark") {
		return errors.New("turnstile theme must be auto, light or dark")
	}
	if t.Size != "" && !oneOf(t.Size, "normal", "flexible", "compact") {
		return errors.New("turnstile size must be normal, flexible or compact")
	}
	if t.Action != "" && !actionNameRe.MatchString(t.Action) {
		return errors.New("turnstile action may only contain letters, digits, '-' and '_' (max 32 characters)")
	}
	if t.CData != "" && !cdataRe.MatchString(t.CData) {
		return errors.New("turnstile cData may only contain letters, digits, '-' and '_' (max 255 characters)")
	}
	return nil
}

// ValidatePageSettings validates every customisation field of the config,
// including the custom template (parse + one sample render per provider).
func (c *Config) ValidatePageSettings() error {
	if c == nil {
		return nil
	}
	if err := c.Branding.Validate(); err != nil {
		return err
	}
	if err := c.Turnstile.Validate(); err != nil {
		return err
	}
	if c.FriendlyEndpoint != "" && c.FriendlyEndpoint != FriendlyEndpointGlobal && c.FriendlyEndpoint != FriendlyEndpointEU {
		return errors.New("Friendly Captcha endpoint must be \"global\" or \"eu\"")
	}
	if c.RecaptchaAction != "" && !actionNameRe.MatchString(c.RecaptchaAction) {
		return errors.New("reCAPTCHA action may only contain letters, digits, '-' and '_' (max 32 characters)")
	}
	if c.Branding != nil && c.Branding.CustomTemplate != "" {
		if err := ValidateCustomTemplate(c.Branding.CustomTemplate); err != nil {
			return err
		}
	}
	return nil
}

// safeLogo returns the logo as a template.URL (so html/template keeps data:
// URIs) only if it passes validation again; render time never trusts storage.
func safeLogo(logo string) template.URL {
	if ValidateLogo(logo) != nil {
		return ""
	}
	return template.URL(logo)
}

// DefaultFooterURL is where the footer link leads unless branding overrides it.
const DefaultFooterURL = "https://zoraxy.aroz.org"

// safeFooterURL returns u if it is a plain http(s) URL, otherwise "".
func safeFooterURL(u string) string {
	p, err := url.Parse(strings.TrimSpace(u))
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || p.User != nil {
		return ""
	}
	return p.String()
}
