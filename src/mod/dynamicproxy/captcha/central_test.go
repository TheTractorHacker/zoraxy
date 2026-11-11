package captcha

import (
	"encoding/json"
	"strings"
	"testing"
)

func withCentral(t *testing.T, c *Central) {
	t.Helper()
	SetCentral(c)
	t.Cleanup(func() { SetCentral(nil) })
}

func validCentral() *Central {
	return &Central{Provider: ProviderCloudflare, SiteKey: "csite", SecretKey: "csecret", SessionDuration: 900}
}

func TestCentralValidate(t *testing.T) {
	if err := validCentral().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(c *Central){
		"unknown provider":   func(c *Central) { c.Provider = 9 },
		"no site key":        func(c *Central) { c.SiteKey = "" },
		"no secret":          func(c *Central) { c.SecretKey = "" },
		"bad version":        func(c *Central) { c.RecaptchaVersion = "v9" },
		"score out of range": func(c *Central) { c.RecaptchaScore = 1.5 },
		"bad turnstile":      func(c *Central) { c.Turnstile = &TurnstileOptions{Mode: "bogus"} },
		"bad action":         func(c *Central) { c.RecaptchaAction = "no spaces allowed!" },
		"bad friendly":       func(c *Central) { c.FriendlyEndpoint = "mars" },
	}
	for name, mut := range bad {
		c := validCentral()
		mut(c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Altcha needs only the secret
	a := &Central{Provider: ProviderAltcha, SecretKey: "hmac"}
	if err := a.Validate(); err != nil {
		t.Errorf("altcha: %v", err)
	}
	a.SecretKey = ""
	if a.Validate() == nil {
		t.Error("altcha without secret accepted")
	}
}

func TestCentralNormalize(t *testing.T) {
	c := &Central{Provider: ProviderGoogle, SiteKey: "a", SecretKey: "b", SessionDuration: 5, Turnstile: &TurnstileOptions{}}
	c.Normalize()
	if c.SessionDuration != MinSessionDuration || c.RecaptchaVersion != "v2" || c.RecaptchaScore != 0.5 || c.Turnstile != nil {
		t.Fatalf("%+v", c)
	}
}

func TestCentralViewNeverCarriesSecret(t *testing.T) {
	c := validCentral()
	c.SecretKey = "super-secret-value"
	v := c.View()
	js, _ := json.Marshal(v)
	if strings.Contains(string(js), "super-secret-value") || v.SecretKey != "" || !v.SecretSet || !v.Configured {
		t.Fatalf("view leaks or lacks state: %s", js)
	}
	if (*Central)(nil).View() != nil {
		t.Fatal("nil central must have a nil view")
	}
}

func TestCentralSetGetIsolated(t *testing.T) {
	c := validCentral()
	c.Turnstile = &TurnstileOptions{Theme: "dark"}
	withCentral(t, c)
	c.SiteKey = "changed-after-set"
	c.Turnstile.Theme = "light"
	got := GetCentral()
	if got.SiteKey != "csite" || got.Turnstile.Theme != "dark" {
		t.Fatalf("stored config aliases the caller's copy: %+v", got)
	}
	got.SiteKey = "x"
	if GetCentral().SiteKey != "csite" {
		t.Fatal("GetCentral returned the live pointer")
	}
	SetCentral(nil)
	if GetCentral() != nil {
		t.Fatal("clear failed")
	}
}

func TestResolveCentralOptIn(t *testing.T) {
	own := &Config{Provider: ProviderGoogle, SiteKey: "own", SecretKey: "ownsecret", SessionDuration: 111, RecaptchaVersion: "v3"}
	withCentral(t, validCentral())
	// not opted in: the very same pointer, nothing resolved
	if ResolveCentral(own) != own {
		t.Fatal("a rule without UseCentral must be returned as is")
	}
	if ResolveCentral(nil) != nil {
		t.Fatal("nil in, nil out")
	}
}

func TestResolveCentralKeepsPerSiteParts(t *testing.T) {
	br := &Branding{Title: "Site title"}
	ex := []*ExceptionRule{{RuleType: ExceptionTypePaths, PathPrefix: "/health"}}
	own := &Config{
		Provider: ProviderGoogle, SiteKey: "own", SecretKey: "ownsecret", SessionDuration: 111, RecaptchaVersion: "v3",
		ProtectedPathPrefixes: []string{"/admin"}, ExceptionRules: ex, LimitChallengesToPaths: true, Branding: br,
		Turnstile: &TurnstileOptions{Theme: "dark"}, UseCentral: true,
	}
	c := validCentral()
	c.Turnstile = &TurnstileOptions{Theme: "light"}
	withCentral(t, c)

	eff := ResolveCentral(own)
	if eff == own {
		t.Fatal("resolved config must be a copy")
	}
	if eff.Provider != ProviderCloudflare || eff.SiteKey != "csite" || eff.SecretKey != "csecret" || eff.SessionDuration != 900 {
		t.Fatalf("provider fields not from central: %+v", eff)
	}
	if eff.Turnstile == nil || eff.Turnstile.Theme != "light" {
		t.Fatalf("turnstile options not from central: %+v", eff.Turnstile)
	}
	if len(eff.ProtectedPathPrefixes) != 1 || eff.ProtectedPathPrefixes[0] != "/admin" || !eff.LimitChallengesToPaths ||
		len(eff.ExceptionRules) != 1 || eff.Branding != br {
		t.Fatalf("per-site parts lost: %+v", eff)
	}
	// own fields untouched, switching back restores them
	if own.Provider != ProviderGoogle || own.SiteKey != "own" || own.SecretKey != "ownsecret" || own.SessionDuration != 111 || own.Turnstile.Theme != "dark" {
		t.Fatalf("own provider fields were modified: %+v", own)
	}
	own.UseCentral = false
	if got := ResolveCentral(own); got.SiteKey != "own" || got.Provider != ProviderGoogle {
		t.Fatal("switching back must restore the own provider")
	}
	// path scoping still works on the resolved config
	own.UseCentral = true
	eff = ResolveCentral(own)
	if !ShouldEnforcePath("/admin/x", eff) || ShouldEnforcePath("/other", eff) || eff.ChallengeAllowedOnPath("/other") {
		t.Fatal("protected path prefixes must stay per site")
	}
	// mutating the resolved config never reaches the central config
	eff.Turnstile.Theme = "dark"
	if GetCentral().Turnstile.Theme != "light" {
		t.Fatal("resolved config aliases the central config")
	}
}

func TestResolveCentralBrandingMerge(t *testing.T) {
	SetDefaultBranding(&Branding{Heading: "Default heading", Title: "Default title"})
	t.Cleanup(func() { SetDefaultBranding(nil) })
	withCentral(t, validCentral())
	own := &Config{UseCentral: true, Branding: &Branding{Title: "Mine"}}
	// resolve, then the render step merges the node default on top, as for any rule
	m := ApplyDefaultBranding(ResolveCentral(own)).Branding
	if m.Title != "Mine" || m.Heading != "Default heading" {
		t.Fatalf("branding merge: %+v", m)
	}
}

func TestResolveCentralMissingFailsClosed(t *testing.T) {
	SetCentral(nil)
	own := &Config{Provider: ProviderCloudflare, SiteKey: "own", SecretKey: "ownsecret", UseCentral: true,
		ProtectedPathPrefixes: []string{"/p"}}
	eff := ResolveCentral(own)
	if eff == nil || eff.IsConfigured() {
		t.Fatalf("no central provider must mean NOT configured, got %+v", eff)
	}
	if eff.SiteKey != "" || eff.SecretKey != "" {
		t.Fatal("the rule's own keys must never act as a fallback")
	}
	if !eff.UseCentral || len(eff.ProtectedPathPrefixes) != 1 {
		t.Fatalf("per-site parts must stay on the unconfigured result: %+v", eff)
	}
	withCentral(t, &Central{Provider: ProviderCloudflare, SiteKey: "k"}) // no secret
	if ResolveCentral(own).IsConfigured() {
		t.Fatal("central without secret must not be configured")
	}
}

func TestConfigUseCentralJSONCompat(t *testing.T) {
	// configs written by older versions load with UseCentral off, and off is not written
	var c Config
	if err := json.Unmarshal([]byte(`{"Provider":0,"SiteKey":"a","SecretKey":"b","SessionDuration":60}`), &c); err != nil || c.UseCentral {
		t.Fatalf("old config: %v %+v", err, c)
	}
	js, _ := json.Marshal(c)
	if strings.Contains(string(js), "UseCentral") {
		t.Fatalf("UseCentral=false must be omitted: %s", js)
	}
	c.UseCentral = true
	js, _ = json.Marshal(c)
	if !strings.Contains(string(js), `"UseCentral":true`) {
		t.Fatalf("%s", js)
	}
}
