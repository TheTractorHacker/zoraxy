package captcha

import (
	"errors"
	"sync/atomic"
)

/*
	central.go

	A node wide, central CAPTCHA provider configuration. A proxy rule that sets
	Config.UseCentral takes the provider fields from here (provider, keys,
	session length, reCAPTCHA / Altcha / Friendly / Turnstile options, hostname
	check) and keeps its own protected paths, exceptions, "limit challenges"
	switch and page branding. The rule's own provider fields stay stored and
	untouched, so switching back restores them.

	The central config is resolved at request time (ResolveCentral), so editing
	it applies to every opted in rule at once. With UseCentral on and no usable
	central provider, the rule is NOT configured (IsConfigured false), which is
	the existing fail closed behaviour, never an open door.
*/

// Central is the node wide provider configuration.
type Central struct {
	Provider           Provider          `json:"Provider"`
	SiteKey            string            `json:"SiteKey"`
	SecretKey          string            `json:"SecretKey"`
	SessionDuration    int               `json:"SessionDuration"`
	RecaptchaVersion   string            `json:"RecaptchaVersion"`
	RecaptchaScore     float64           `json:"RecaptchaScore"`
	RecaptchaInvisible bool              `json:"RecaptchaInvisible,omitempty"`
	RecaptchaAction    string            `json:"RecaptchaAction,omitempty"`
	FriendlyEndpoint   string            `json:"FriendlyEndpoint,omitempty"`
	AltchaMaxNumber    int               `json:"AltchaMaxNumber,omitempty"`
	VerifyHostname     bool              `json:"VerifyHostname,omitempty"`
	Turnstile          *TurnstileOptions `json:"Turnstile,omitempty"`
}

// CentralView is what the admin API returns: the secret is never part of it.
type CentralView struct {
	Central
	SecretSet  bool `json:"SecretSet"`
	Configured bool `json:"Configured"`
}

var central atomic.Pointer[Central]

// Clone returns a deep copy.
func (c *Central) Clone() *Central {
	if c == nil {
		return nil
	}
	d := *c
	if c.Turnstile != nil {
		t := *c.Turnstile
		d.Turnstile = &t
	}
	return &d
}

// asConfig returns the provider part as a Config.
func (c *Central) asConfig() *Config {
	cfg := &Config{
		Provider:           c.Provider,
		SiteKey:            c.SiteKey,
		SecretKey:          c.SecretKey,
		SessionDuration:    c.SessionDuration,
		RecaptchaVersion:   c.RecaptchaVersion,
		RecaptchaScore:     c.RecaptchaScore,
		RecaptchaInvisible: c.RecaptchaInvisible,
		RecaptchaAction:    c.RecaptchaAction,
		FriendlyEndpoint:   c.FriendlyEndpoint,
		AltchaMaxNumber:    c.AltchaMaxNumber,
		VerifyHostname:     c.VerifyHostname,
	}
	if c.Turnstile != nil {
		t := *c.Turnstile
		cfg.Turnstile = &t
	}
	return cfg
}

// IsConfigured reports whether the central provider has the keys it needs.
func (c *Central) IsConfigured() bool {
	if c == nil {
		return false
	}
	return c.asConfig().IsConfigured()
}

// Normalize fills the defaults the per-site form fills in.
func (c *Central) Normalize() {
	c.SessionDuration = ClampSessionDuration(c.SessionDuration)
	if c.RecaptchaVersion == "" {
		c.RecaptchaVersion = "v2"
	}
	if c.RecaptchaScore == 0 {
		c.RecaptchaScore = 0.5
	}
	if c.Provider == ProviderFriendly {
		c.FriendlyEndpoint = NormalizeFriendlyEndpoint(c.FriendlyEndpoint)
	}
	if c.Turnstile != nil && *c.Turnstile == (TurnstileOptions{}) {
		c.Turnstile = nil
	}
}

// Validate checks the provider fields like the per-site form does, and that the
// result is usable (keys present), since an unusable central config would make
// every opted in rule fail closed.
func (c *Central) Validate() error {
	if c == nil {
		return errors.New("no central CAPTCHA configuration given")
	}
	switch c.Provider {
	case ProviderCloudflare, ProviderGoogle, ProviderAltcha, ProviderFriendly:
	default:
		return errors.New("unknown CAPTCHA provider")
	}
	if c.RecaptchaVersion != "" && c.RecaptchaVersion != "v2" && c.RecaptchaVersion != "v3" {
		return errors.New("reCAPTCHA version must be v2 or v3")
	}
	if c.RecaptchaScore < 0 || c.RecaptchaScore > 1 {
		return errors.New("reCAPTCHA score must be between 0.0 and 1.0")
	}
	if err := c.asConfig().ValidatePageSettings(); err != nil {
		return err
	}
	if !c.IsConfigured() {
		if c.Provider == ProviderAltcha {
			return errors.New("Altcha needs a secret key (the HMAC key)")
		}
		return errors.New("the site key and the secret key are both required")
	}
	return nil
}

// View returns the API representation, without the secret.
func (c *Central) View() *CentralView {
	if c == nil {
		return nil
	}
	v := &CentralView{Central: *c.Clone(), SecretSet: c.SecretKey != "", Configured: c.IsConfigured()}
	v.SecretKey = ""
	return v
}

// SetCentral replaces the node wide central config (nil clears it). The caller
// validates and normalises it first.
func SetCentral(c *Central) {
	if c == nil {
		central.Store(nil)
		return
	}
	central.Store(c.Clone())
}

// GetCentral returns a copy of the central config, nil when none is set.
func GetCentral() *Central {
	return central.Load().Clone()
}

// ResolveCentral returns the config a request must be handled with. A rule that
// does not opt in is returned as is. An opted in rule gets the central provider
// fields plus its own protected paths, exceptions, limit switch and branding;
// cfg is never modified. Without a usable central provider the provider fields
// stay empty, so IsConfigured is false.
func ResolveCentral(cfg *Config) *Config {
	if cfg == nil || !cfg.UseCentral {
		return cfg
	}
	var out *Config
	if c := central.Load(); c != nil {
		out = c.asConfig()
	} else {
		out = &Config{}
	}
	out.UseCentral = true
	out.ProtectedPathPrefixes = cfg.ProtectedPathPrefixes
	out.ExceptionRules = cfg.ExceptionRules
	out.LimitChallengesToPaths = cfg.LimitChallengesToPaths
	out.Branding = cfg.Branding
	return out
}
