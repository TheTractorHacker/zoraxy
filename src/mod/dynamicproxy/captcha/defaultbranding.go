package captcha

import "sync/atomic"

/*
	defaultbranding.go

	A node wide default Branding. A rule that customises nothing (or only some
	fields) inherits the remaining fields from it, field by field. It never
	touches the provider, keys or Turnstile options.
*/

var defaultBranding atomic.Pointer[Branding]

// SetDefaultBranding replaces the node wide default (nil or empty clears it).
// The caller validates it first, see Branding.Validate.
func SetDefaultBranding(b *Branding) {
	if b == nil || *b == (Branding{}) {
		defaultBranding.Store(nil)
		return
	}
	c := *b
	defaultBranding.Store(&c)
}

// DefaultBranding returns a copy of the node wide default, nil when none is set.
func DefaultBranding() *Branding {
	if b := defaultBranding.Load(); b != nil {
		c := *b
		return &c
	}
	return nil
}

// MergeBranding returns rule with every unset field filled from def. Both may be nil.
func MergeBranding(rule, def *Branding) *Branding {
	if def == nil {
		return rule
	}
	if rule == nil {
		c := *def
		return &c
	}
	m := *rule
	fill := func(dst *string, src string) {
		if *dst == "" {
			*dst = src
		}
	}
	fill(&m.Title, def.Title)
	fill(&m.Heading, def.Heading)
	fill(&m.Message, def.Message)
	fill(&m.Notice, def.Notice)
	fill(&m.VerifyingText, def.VerifyingText)
	fill(&m.SuccessText, def.SuccessText)
	fill(&m.FailedText, def.FailedText)
	fill(&m.ErrorText, def.ErrorText)
	fill(&m.RetryText, def.RetryText)
	fill(&m.BlockedTitle, def.BlockedTitle)
	fill(&m.BlockedHeading, def.BlockedHeading)
	fill(&m.BlockedMessage, def.BlockedMessage)
	fill(&m.LogoURL, def.LogoURL)
	fill(&m.AccentColor, def.AccentColor)
	fill(&m.BackgroundColor, def.BackgroundColor)
	fill(&m.Theme, def.Theme)
	fill(&m.CustomTemplate, def.CustomTemplate)
	m.HideFooter = m.HideFooter || def.HideFooter
	return &m
}

// ApplyDefaultBranding returns cfg with the node default merged into its
// branding. cfg is never modified; with no default set it is returned as is.
func ApplyDefaultBranding(cfg *Config) *Config {
	def := defaultBranding.Load()
	if def == nil {
		return cfg
	}
	if cfg == nil {
		return &Config{Branding: MergeBranding(nil, def)}
	}
	c := *cfg
	c.Branding = MergeBranding(cfg.Branding, def)
	return &c
}
