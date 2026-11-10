package aicrawler

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Actions of a policy. "" (or a missing key) = no policy: the existing behaviour applies unchanged.
const (
	ActAllow     = "allow"     // let the crawler through (and keep the AI crawler switch / bot rules from stopping it)
	ActBlock     = "block"     // 403
	ActChallenge = "challenge" // the CAPTCHA of the proxy rule (403 when the rule has none)
	ActRateLimit = "ratelimit" // allow up to N requests per minute per crawler and site, 429 above that
	ActLog       = "log"       // log only; everything else behaves as without the policy
)

// robots.txt modes of a site
const (
	RobotsOff   = "off"
	RobotsMerge = "merge" // append the generated rules to the upstream file (or serve them alone when the upstream has none)
	RobotsServe = "serve" // answer /robots.txt with the generated rules instead of the upstream file
)

// llms.txt modes of a site
const (
	LLMSOff      = "off"
	LLMSServe    = "serve"    // answer /llms.txt with the admin's text instead of the upstream file
	LLMSFallback = "fallback" // only when the upstream has no /llms.txt
)

// Site modes
const (
	SiteInherit = ""       // follow the global policy
	SiteCustom  = "custom" // global policy with the overrides of the site on top
	SiteOff     = "off"    // the policy does nothing for this site
)

const (
	DefaultRateLimit = 30 // requests per minute per crawler and site
	maxRateLimit     = 100000
	maxSites         = 5000
	maxLLMSText      = 64 * 1024
	maxSiteKey       = 253
)

// Settings are the policy values. The global policy has one set, a site can override parts of it.
type Settings struct {
	Groups             map[string]string `json:"Groups,omitempty"`   // group id -> action
	Crawlers           map[string]string `json:"Crawlers,omitempty"` // crawler id -> action (wins over the group)
	VerifiedOnly       bool              `json:"VerifiedOnly"`       // allow / rate limit only crawlers whose identity checks out
	SpoofAction        string            `json:"SpoofAction"`        // what a failed verification gets (default block)
	RateLimitPerMinute int               `json:"RateLimitPerMinute"` // for the ratelimit action (default 30)
	BypassWAF          bool              `json:"BypassWAF"`          // verified, allowed crawlers skip the WAF. Off by default.
}

// SiteSettings are the overrides of one site (custom mode). Pointers and empty values inherit.
type SiteSettings struct {
	Groups             map[string]string `json:"Groups,omitempty"`
	Crawlers           map[string]string `json:"Crawlers,omitempty"`
	VerifiedOnly       *bool             `json:"VerifiedOnly,omitempty"`
	SpoofAction        string            `json:"SpoofAction,omitempty"`
	RateLimitPerMinute int               `json:"RateLimitPerMinute,omitempty"`
	BypassWAF          *bool             `json:"BypassWAF,omitempty"`
}

// RobotsCfg selects what happens to /robots.txt. robots.txt is advisory: a crawler can ignore it.
// The block / challenge actions are the enforcement.
type RobotsCfg struct {
	Mode string `json:"Mode"` // "" = off (site: "" = follow the global default)
}

// LLMSCfg is the optional /llms.txt text of a site
type LLMSCfg struct {
	Mode string `json:"Mode"`
	Text string `json:"Text,omitempty"`
}

// SiteCfg is the configuration of one proxy rule (key = its host name)
type SiteCfg struct {
	Mode   string       `json:"Mode,omitempty"` // "" inherit | custom | off
	Custom SiteSettings `json:"Custom"`
	Robots RobotsCfg    `json:"Robots"`
	LLMS   LLMSCfg      `json:"LLMS"`
}

// Config is the persisted configuration (conf/aicrawler.json)
type Config struct {
	Version int                 `json:"Version"`
	Enabled bool                `json:"Enabled"` // master switch, off by default. Off = nothing here runs, nothing is served.
	Global  Settings            `json:"Global"`
	Robots  RobotsCfg           `json:"Robots"` // default robots.txt mode of sites that do not choose
	Sites   map[string]*SiteCfg `json:"Sites,omitempty"`
}

// DefaultConfig is everything off
func DefaultConfig() Config {
	return Config{Version: 1, Global: Settings{SpoofAction: ActBlock, RateLimitPerMinute: DefaultRateLimit}}
}

func validAction(a string) bool {
	switch a {
	case ActAllow, ActBlock, ActChallenge, ActRateLimit, ActLog:
		return true
	}
	return false
}

func validSpoof(a string) bool {
	return a == ActBlock || a == ActChallenge || a == ActLog
}

func checkPolicyMap(where string, groups, crawlers map[string]string) error {
	known := map[string]bool{}
	for _, g := range Groups() {
		known[g.ID] = true
	}
	for id, a := range groups {
		if !known[id] {
			return fmt.Errorf("%s: unknown group %q", where, id)
		}
		if a != "" && !validAction(a) {
			return fmt.Errorf("%s: invalid action %q for group %s", where, a, id)
		}
	}
	for id, a := range crawlers {
		e, ok := Lookup(id)
		if !ok {
			return fmt.Errorf("%s: unknown crawler %q", where, id)
		}
		if a != "" && !validAction(a) {
			return fmt.Errorf("%s: invalid action %q for %s", where, a, e.Name)
		}
		if e.TokenOnly && a != "" && a != ActAllow && a != ActBlock {
			return fmt.Errorf("%s: %s is a robots.txt token, only allow or block make sense", where, e.Name)
		}
	}
	return nil
}

func checkRate(where string, n int) error {
	if n < 0 || n > maxRateLimit {
		return fmt.Errorf("%s: rate limit must be between 1 and %d requests per minute", where, maxRateLimit)
	}
	return nil
}

// Validate checks a configuration without applying it
func (c Config) Validate() error {
	if err := checkPolicyMap("global", c.Global.Groups, c.Global.Crawlers); err != nil {
		return err
	}
	if c.Global.SpoofAction != "" && !validSpoof(c.Global.SpoofAction) {
		return errors.New("global: the action for a failed verification must be block, challenge or log")
	}
	if err := checkRate("global", c.Global.RateLimitPerMinute); err != nil {
		return err
	}
	if m := c.Robots.Mode; m != "" && m != RobotsOff && m != RobotsMerge && m != RobotsServe {
		return errors.New("invalid default robots.txt mode")
	}
	if len(c.Sites) > maxSites {
		return fmt.Errorf("too many sites (max %d)", maxSites)
	}
	for key, s := range c.Sites {
		if key == "" || len(key) > maxSiteKey || strings.ContainsAny(key, "\x00\r\n") {
			return fmt.Errorf("invalid site name %q", key)
		}
		if s == nil {
			return fmt.Errorf("site %s: empty entry", key)
		}
		switch s.Mode {
		case SiteInherit, SiteCustom, SiteOff:
		default:
			return fmt.Errorf("site %s: mode must be empty, custom or off", key)
		}
		if err := checkPolicyMap("site "+key, s.Custom.Groups, s.Custom.Crawlers); err != nil {
			return err
		}
		if s.Custom.SpoofAction != "" && !validSpoof(s.Custom.SpoofAction) {
			return fmt.Errorf("site %s: the action for a failed verification must be block, challenge or log", key)
		}
		if err := checkRate("site "+key, s.Custom.RateLimitPerMinute); err != nil {
			return err
		}
		if m := s.Robots.Mode; m != "" && m != RobotsOff && m != RobotsMerge && m != RobotsServe {
			return fmt.Errorf("site %s: invalid robots.txt mode", key)
		}
		switch s.LLMS.Mode {
		case "", LLMSOff, LLMSServe, LLMSFallback:
		default:
			return fmt.Errorf("site %s: invalid llms.txt mode", key)
		}
		if len(s.LLMS.Text) > maxLLMSText {
			return fmt.Errorf("site %s: the llms.txt text is longer than %d bytes", key, maxLLMSText)
		}
		if strings.ContainsRune(s.LLMS.Text, 0) {
			return fmt.Errorf("site %s: the llms.txt text contains a NUL character", key)
		}
	}
	return nil
}

// normalise drops empty actions and fills the defaults. The input is not modified.
func (c Config) normalise() Config {
	out := c
	if out.Version == 0 {
		out.Version = 1
	}
	out.Global = normSettings(c.Global)
	out.Sites = map[string]*SiteCfg{}
	for k, s := range c.Sites {
		cp := *s
		cp.Custom.Groups = dropEmpty(s.Custom.Groups)
		cp.Custom.Crawlers = dropEmpty(s.Custom.Crawlers)
		out.Sites[k] = &cp
	}
	return out
}

func normSettings(s Settings) Settings {
	s.Groups = dropEmpty(s.Groups)
	s.Crawlers = dropEmpty(s.Crawlers)
	if s.SpoofAction == "" {
		s.SpoofAction = ActBlock
	}
	if s.RateLimitPerMinute <= 0 {
		s.RateLimitPerMinute = DefaultRateLimit
	}
	return s
}

func dropEmpty(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// effective is the policy of one site after the overrides are applied
type effective struct {
	off      bool
	groups   map[string]string
	crawlers map[string]string
	settings Settings
	site     *SiteCfg
}

// effectiveFor resolves the policy of a site: custom entries first, then the global ones
func (c *Config) effectiveFor(site string) effective {
	g := c.Global
	ef := effective{groups: g.Groups, crawlers: g.Crawlers, settings: g}
	s := c.Sites[site]
	if s == nil {
		return ef
	}
	ef.site = s
	switch s.Mode {
	case SiteOff:
		ef.off = true
	case SiteCustom:
		ef.groups = merged(g.Groups, s.Custom.Groups)
		ef.crawlers = merged(g.Crawlers, s.Custom.Crawlers)
		if s.Custom.VerifiedOnly != nil {
			ef.settings.VerifiedOnly = *s.Custom.VerifiedOnly
		}
		if s.Custom.SpoofAction != "" {
			ef.settings.SpoofAction = s.Custom.SpoofAction
		}
		if s.Custom.RateLimitPerMinute > 0 {
			ef.settings.RateLimitPerMinute = s.Custom.RateLimitPerMinute
		}
		if s.Custom.BypassWAF != nil {
			ef.settings.BypassWAF = *s.Custom.BypassWAF
		}
	}
	return ef
}

func merged(base, over map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// actionFor is the configured action for a crawler: its own entry, else its group, else "" (no policy)
func (e effective) actionFor(c Entry) string {
	if a := e.crawlers[c.ID]; a != "" {
		return a
	}
	return e.groups[c.Group]
}

// robotsMode is the effective robots.txt mode of a site
func (c *Config) robotsMode(site string) string {
	if s := c.Sites[site]; s != nil && s.Robots.Mode != "" {
		return s.Robots.Mode
	}
	if c.Robots.Mode == "" {
		return RobotsOff
	}
	return c.Robots.Mode
}

func saveConfig(path string, c Config) error {
	js, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, js)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
