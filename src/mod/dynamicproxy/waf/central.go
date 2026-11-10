package waf

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	pathpkg "path"
	"regexp"
	"sort"
	"strings"
)

/*
	central.go

	Central WAF management: one global Policy, reusable named Profiles and a
	per endpoint Setting that says where the endpoint takes its WAF
	configuration from. A State is an immutable snapshot of policy + profiles;
	the router swaps whole States atomically, so a request never sees a half
	applied change.

	Endpoint sources:
	  ""        legacy / unset: "custom" if the endpoint has a WAF config, else "inherit"
	  inherit   global policy (mode = policy default mode, only when the policy is enabled)
	  off       WAF disabled for this endpoint
	  detection_only / block   fixed mode, everything else from the global policy
	  profile   mode and tuning from a named profile
	  custom    the endpoint's own complete Config (the pre-central behaviour)
*/

const (
	SourceInherit = "inherit"
	SourceOff     = "off"
	SourceProfile = "profile"
	SourceCustom  = "custom"
	// detection_only / block are also valid sources

	MaxProfiles      = 64
	maxListEntries   = 1000
	acmeChallengeDir = "/.well-known/acme-challenge/"
)

// TrustedPath is a request path (optionally restricted to a host) that bypasses the WAF
type TrustedPath struct {
	Host  string // Optional host name, "*.example.com" wildcard supported. Empty = any host
	Path  string // Must start with "/"
	Exact bool   // Exact match instead of prefix match
}

// Policy is the global WAF policy
type Policy struct {
	Enabled                bool   // Master switch for endpoints that inherit
	DefaultMode            string // off, detection_only, block: mode of inheriting endpoints
	ParanoiaLevel          int
	InboundThreshold       int
	MaxBodyBytes           int64
	AllowEndpointOverride  bool            // Endpoints may change paranoia level / threshold
	ExcludedRuleIDs        []string        // Rules disabled everywhere
	PathExclusions         []PathExclusion // Rules disabled for matching paths, everywhere
	CustomRules            string          // Global SecLang, runs before profile / endpoint rules
	TrustedPaths           []TrustedPath   // Requests that skip the WAF
	AllowedIPs             []string        // IPs / CIDRs that skip the WAF
	IgnoreAnalyticsCookies bool            `json:",omitempty"` // Do not inspect the values of analytics cookies (PostHog, Google Analytics, ...), see Config

	// Graduated response, see bands.go. ChallengeThreshold 0 = challenge band off.
	ChallengeThreshold  int `json:",omitempty"`
	ChallengeTTLMinutes int `json:",omitempty"` // 0 = default (60)
	// --- WAF tuning assistant (see tuning.go) ---
	TargetExclusions []TargetExclusion `json:",omitempty"` // Variable scoped exclusions, everywhere
	// --- Response inspection (outbound leak detection), see respinspect.go ---
	Response *ResponseConfig `json:",omitempty"` // Defaults for every endpoint that has the WAF on; profiles / endpoints override per group
	// --- API protection (apiguard_config.go) ---
	API *APIConfig `json:",omitempty"` // Default API protection for endpoints that inherit
}

// Profile is a reusable named bundle of WAF settings
type Profile struct {
	Name                   string
	Description            string
	BuiltIn                bool `json:",omitempty"` // Read-only, shipped with Zoraxy
	Mode                   string
	ParanoiaLevel          int // 0 = use the global policy value
	InboundThreshold       int // 0 = use the global policy value
	ExcludedRuleIDs        []string
	PathExclusions         []PathExclusion
	CustomRules            string
	IgnoreAnalyticsCookies bool `json:",omitempty"` // Additive: on if the policy or the profile turns it on

	// Graduated response, see bands.go. 0 = use the global policy value.
	ChallengeThreshold  int `json:",omitempty"`
	ChallengeTTLMinutes int `json:",omitempty"`
	// --- WAF tuning assistant (see tuning.go) ---
	TargetExclusions []TargetExclusion `json:",omitempty"`
	// --- Response inspection (outbound leak detection), see respinspect.go ---
	Response *ResponseConfig `json:",omitempty"` // Per group override of the policy
	// --- API protection (apiguard_config.go) ---
	API *APIConfig `json:",omitempty"` // Layered over the policy's API protection
}

// Overrides are the per endpoint additions applied on top of the global
// policy / profile. Exclusions and rules are always additive.
type Overrides struct {
	ParanoiaLevel    int `json:",omitempty"` // Only honoured when the policy allows endpoint override
	InboundThreshold int `json:",omitempty"`
	ExcludedRuleIDs  []string
	PathExclusions   []PathExclusion
	CustomRules      string

	// Graduated response, see bands.go. 0 = inherit. Like the paranoia level and threshold they are
	// only honoured when the policy allows endpoint override.
	ChallengeThreshold  int `json:",omitempty"`
	ChallengeTTLMinutes int `json:",omitempty"`
	// --- WAF tuning assistant (see tuning.go) ---
	TargetExclusions []TargetExclusion `json:",omitempty"`
	// --- Response inspection (outbound leak detection), see respinspect.go ---
	Response *ResponseConfig `json:",omitempty"` // Per group override of the policy / profile
}

// Setting is the WAF choice of one endpoint
type Setting struct {
	Source  string     // see the Source* constants, "" = legacy
	Profile string     // for SourceProfile
	Extra   *Overrides // for every source except custom / off
	Custom  *Config    // for SourceCustom (and legacy)

	// --- API protection (apiguard_config.go) ---
	API *APIConfig `json:",omitempty"` // The endpoint's own API protection, layered over policy / profile (ProxyEndpoint.WAFAPI)
}

// Resolved is the outcome of applying a Setting to a State
type Resolved struct {
	Source  string  // effective source: inherit, off, detection_only, block, profile, custom
	Label   string  // human readable origin: "global", "profile:X", "custom", "endpoint"
	Mode    string  // effective mode
	Config  *Config // nil when the WAF is off
	Bypass  bool    // trusted path / IP lists apply
	Warning string

	bandErr string // set when the merged challenge threshold is not below the block threshold, see applyBands
}

// State is an immutable policy + profiles snapshot
type State struct {
	Policy   Policy
	profiles map[string]Profile // user profiles by lower case name
	nets     []*net.IPNet
	ips      []net.IP
}

var profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,39}$`)

// DefaultPolicy is what a fresh install (or an upgrade) starts with: off
func DefaultPolicy() Policy {
	return Policy{DefaultMode: ModeDetectionOnly}
}

func profileKey(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// NewState validates and indexes a policy and user profiles.
func NewState(p Policy, profiles []Profile) (*State, error) {
	p.DefaultMode = strings.ToLower(strings.TrimSpace(p.DefaultMode))
	if p.DefaultMode == "" {
		p.DefaultMode = ModeDetectionOnly
	}
	s := &State{Policy: p, profiles: map[string]Profile{}}
	if err := s.Policy.validate(); err != nil {
		return nil, err
	}
	for _, ip := range p.AllowedIPs {
		ip = strings.TrimSpace(ip)
		if strings.Contains(ip, "/") {
			_, n, err := net.ParseCIDR(ip)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", ip)
			}
			s.nets = append(s.nets, n)
		} else if parsed := net.ParseIP(ip); parsed != nil {
			s.ips = append(s.ips, parsed)
		} else {
			return nil, fmt.Errorf("invalid IP address %q", ip)
		}
	}
	if len(profiles) > MaxProfiles {
		return nil, errors.New("too many profiles")
	}
	builtin := builtinProfiles()
	for _, pr := range profiles {
		pr.BuiltIn = false
		if err := pr.validate(); err != nil {
			return nil, err
		}
		k := profileKey(pr.Name)
		if _, isBuiltin := builtin[k]; isBuiltin {
			return nil, fmt.Errorf("profile name %q is reserved for a built-in profile", pr.Name)
		}
		if _, dup := s.profiles[k]; dup {
			return nil, fmt.Errorf("duplicate profile %q", pr.Name)
		}
		s.profiles[k] = pr
	}
	for _, pr := range s.profiles {
		if r := s.Resolve(Setting{Source: SourceProfile, Profile: pr.Name}); r.bandErr != "" {
			return nil, fmt.Errorf("profile %q: %s", pr.Name, r.bandErr)
		}
	}
	return s, nil
}

// EmptyState is the policy used when nothing is configured
func EmptyState() *State {
	s, _ := NewState(DefaultPolicy(), nil)
	return s
}

func (p *Policy) validate() error {
	switch p.DefaultMode {
	case ModeOff, ModeDetectionOnly, ModeBlock:
	default:
		return fmt.Errorf("invalid default mode %q", p.DefaultMode)
	}
	if len(p.TrustedPaths) > maxListEntries || len(p.AllowedIPs) > maxListEntries {
		return errors.New("too many entries in the trusted path / IP list")
	}
	for _, tp := range p.TrustedPaths {
		if !strings.HasPrefix(tp.Path, "/") || strings.ContainsAny(tp.Path, "\\\r\n\x00%") {
			return fmt.Errorf("invalid trusted path %q (must start with / and contain no backslash or %%)", tp.Path)
		}
		if strings.ContainsAny(tp.Host, " /\\\r\n\x00") {
			return fmt.Errorf("invalid trusted host %q", tp.Host)
		}
	}
	c := Config{Mode: p.DefaultMode, ParanoiaLevel: p.ParanoiaLevel, InboundThreshold: p.InboundThreshold,
		MaxBodyBytes: p.MaxBodyBytes, ExcludedRuleIDs: p.ExcludedRuleIDs, PathExclusions: p.PathExclusions, CustomRules: p.CustomRules,
		ChallengeThreshold: p.ChallengeThreshold, ChallengeTTLMinutes: p.ChallengeTTLMinutes}
	c.TargetExclusions = p.TargetExclusions
	if c.Mode == ModeOff {
		c.Mode = ModeDetectionOnly
	}
	if err := p.Response.Validate(); err != nil {
		return err
	}
	if err := p.API.Validate(); err != nil {
		return err
	}
	return c.Validate()
}

func (pr *Profile) validate() error {
	if !profileNamePattern.MatchString(pr.Name) {
		return fmt.Errorf("invalid profile name %q (letters, digits, space, - _ . ; max 40 characters)", pr.Name)
	}
	pr.Mode = strings.ToLower(strings.TrimSpace(pr.Mode))
	if pr.Mode == "" {
		pr.Mode = ModeBlock
	}
	if len(pr.Description) > 300 {
		return errors.New("profile description too long")
	}
	c := Config{Mode: pr.Mode, ParanoiaLevel: pr.ParanoiaLevel, InboundThreshold: pr.InboundThreshold,
		ExcludedRuleIDs: pr.ExcludedRuleIDs, PathExclusions: pr.PathExclusions, CustomRules: pr.CustomRules}
	if err := validateBandValues(pr.ChallengeThreshold, pr.ChallengeTTLMinutes); err != nil {
		return err
	}
	c.TargetExclusions = pr.TargetExclusions
	if err := pr.Response.Validate(); err != nil {
		return err
	}
	if err := pr.API.Validate(); err != nil {
		return err
	}
	return c.Validate()
}

// Profile returns a built-in or user profile by name (case insensitive)
func (s *State) Profile(name string) (Profile, bool) {
	k := profileKey(name)
	if p, ok := builtinProfiles()[k]; ok {
		return p, true
	}
	p, ok := s.profiles[k]
	return p, ok
}

// Profiles lists built-in profiles first, then user profiles by name
func (s *State) Profiles() []Profile {
	var out []Profile
	for _, p := range builtinProfiles() {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return append(out, s.UserProfiles()...)
}

// UserProfiles lists only the editable profiles
func (s *State) UserProfiles() []Profile {
	var user []Profile
	for _, p := range s.profiles {
		user = append(user, p)
	}
	sort.Slice(user, func(i, j int) bool { return strings.ToLower(user[i].Name) < strings.ToLower(user[j].Name) })
	return user
}

// EffectiveSource maps the legacy "" source
func (set Setting) EffectiveSource() string {
	src := strings.ToLower(strings.TrimSpace(set.Source))
	if src == "" {
		if set.Custom != nil {
			return SourceCustom
		}
		return SourceInherit
	}
	return src
}

// ValidateSetting checks a setting against a state (used by the API on save)
func (s *State) ValidateSetting(set Setting) error {
	switch set.EffectiveSource() {
	case SourceInherit, SourceOff, ModeDetectionOnly, ModeBlock:
	case SourceProfile:
		if _, ok := s.Profile(set.Profile); !ok {
			return fmt.Errorf("unknown WAF profile %q", set.Profile)
		}
	case SourceCustom:
		if set.Custom != nil {
			if err := set.Custom.Validate(); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid WAF source %q", set.Source)
	}
	if set.Extra != nil {
		if (set.Extra.ParanoiaLevel != 0 || set.Extra.InboundThreshold != 0) && !s.Policy.AllowEndpointOverride {
			return errors.New("endpoint paranoia / threshold override is not allowed by the global WAF policy")
		}
		if err := validateBandValues(set.Extra.ChallengeThreshold, set.Extra.ChallengeTTLMinutes); err != nil {
			return err
		}
		if (set.Extra.ChallengeThreshold != 0 || set.Extra.ChallengeTTLMinutes != 0) && !s.Policy.AllowEndpointOverride {
			return errors.New("endpoint challenge override is not allowed by the global WAF policy")
		}
		c := Config{Mode: ModeBlock, ParanoiaLevel: set.Extra.ParanoiaLevel, InboundThreshold: set.Extra.InboundThreshold,
			ExcludedRuleIDs: set.Extra.ExcludedRuleIDs, PathExclusions: set.Extra.PathExclusions, CustomRules: set.Extra.CustomRules}
		c.TargetExclusions = set.Extra.TargetExclusions
		if err := c.Validate(); err != nil {
			return err
		}
		if err := set.Extra.Response.Validate(); err != nil {
			return err
		}
	}
	if r := s.Resolve(set); r.bandErr != "" {
		return errors.New(r.bandErr)
	}
	if err := set.API.Validate(); err != nil {
		return err
	}
	return nil
}

// Resolve computes the effective configuration for an endpoint setting. It
// never fails: unusable settings degrade to the global default with a warning
// so a config file can always be loaded.
func (s *State) Resolve(set Setting) Resolved {
	src := set.EffectiveSource()
	if src == SourceCustom {
		res := Resolved{Source: SourceCustom, Label: "custom", Mode: ModeOff, Bypass: s.Policy.Enabled}
		if set.Custom != nil {
			n := set.Custom.Normalize()
			res.Mode = n.Mode
			if n.Mode != ModeOff {
				res.Config = set.Custom
			}
		}
		return res
	}
	res := Resolved{Source: src, Bypass: true}
	var mode string
	var prof *Profile
	switch src {
	case SourceOff:
		return Resolved{Source: SourceOff, Label: "endpoint", Mode: ModeOff}
	case ModeDetectionOnly, ModeBlock:
		mode = src
		res.Label = "endpoint"
	case SourceProfile:
		if p, ok := s.Profile(set.Profile); ok {
			prof = &p
			mode = p.Mode
			res.Label = "profile:" + p.Name
		} else {
			res.Warning = fmt.Sprintf("profile %q not found, using the global default", set.Profile)
			res.Source = SourceInherit
			res.Label = "global"
			mode = s.inheritMode()
		}
	default: // inherit and anything unknown
		res.Source = SourceInherit
		res.Label = "global"
		mode = s.inheritMode()
		if src != SourceInherit {
			res.Warning = fmt.Sprintf("unknown WAF source %q, using the global default", src)
		}
	}
	res.Mode = mode
	if mode == ModeOff || mode == "" {
		res.Mode = ModeOff
		return res
	}
	p := s.Policy
	cfg := Config{Mode: mode, ParanoiaLevel: p.ParanoiaLevel, InboundThreshold: p.InboundThreshold, MaxBodyBytes: p.MaxBodyBytes}
	cfg.ExcludedRuleIDs = append(cfg.ExcludedRuleIDs, p.ExcludedRuleIDs...)
	cfg.PathExclusions = append(cfg.PathExclusions, p.PathExclusions...)
	cfg.TargetExclusions = append(cfg.TargetExclusions, p.TargetExclusions...)
	cfg.IgnoreAnalyticsCookies = p.IgnoreAnalyticsCookies
	rules := []string{p.CustomRules}
	if prof != nil {
		if prof.ParanoiaLevel > 0 {
			cfg.ParanoiaLevel = prof.ParanoiaLevel
		}
		if prof.InboundThreshold > 0 {
			cfg.InboundThreshold = prof.InboundThreshold
		}
		cfg.ExcludedRuleIDs = append(cfg.ExcludedRuleIDs, prof.ExcludedRuleIDs...)
		cfg.PathExclusions = append(cfg.PathExclusions, prof.PathExclusions...)
		cfg.TargetExclusions = append(cfg.TargetExclusions, prof.TargetExclusions...)
		cfg.IgnoreAnalyticsCookies = cfg.IgnoreAnalyticsCookies || prof.IgnoreAnalyticsCookies
		rules = append(rules, prof.CustomRules)
	}
	if x := set.Extra; x != nil {
		if p.AllowEndpointOverride {
			if x.ParanoiaLevel > 0 {
				cfg.ParanoiaLevel = x.ParanoiaLevel
			}
			if x.InboundThreshold > 0 {
				cfg.InboundThreshold = x.InboundThreshold
			}
		} else if x.ParanoiaLevel != 0 || x.InboundThreshold != 0 {
			res.Warning = "endpoint paranoia / threshold override ignored (not allowed by the global policy)"
		}
		cfg.ExcludedRuleIDs = append(cfg.ExcludedRuleIDs, x.ExcludedRuleIDs...)
		cfg.PathExclusions = append(cfg.PathExclusions, x.PathExclusions...)
		cfg.TargetExclusions = append(cfg.TargetExclusions, x.TargetExclusions...)
		rules = append(rules, x.CustomRules)
	}
	var joined []string
	for _, r := range rules {
		if r = strings.TrimSpace(r); r != "" {
			joined = append(joined, r)
		}
	}
	cfg.CustomRules = strings.Join(joined, "\n")
	s.applyBands(&cfg, prof, set.Extra, &res)
	cfg.ExcludedRuleIDs = dedupe(cfg.ExcludedRuleIDs)
	cfg.TargetExclusions = dedupeTargetExclusions(cfg.TargetExclusions)
	s.resolveResponse(&cfg, prof, set.Extra)
	res.Config = &cfg
	return res
}

// InheritMode is the effective mode of endpoints that inherit the central policy.
func (s *State) InheritMode() string { return s.inheritMode() }

func (s *State) inheritMode() string {
	if !s.Policy.Enabled {
		return ModeOff
	}
	return s.Policy.DefaultMode
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// ValidationConfigs returns configs that exercise the policy and every user
// profile, so bad SecLang is caught on save even if no endpoint uses them yet.
func (s *State) ValidationConfigs() []*Config {
	var out []*Config
	pol := s.Resolve(Setting{Source: ModeDetectionOnly})
	if pol.Config != nil {
		out = append(out, pol.Config)
	}
	for _, p := range s.UserProfiles() {
		if r := s.Resolve(Setting{Source: SourceProfile, Profile: p.Name}); r.Config != nil {
			out = append(out, r.Config)
		}
	}
	return out
}

/*
	Bypass: trusted paths, ACME challenge and IP allow-list
*/

// BypassReason returns a non empty reason if the request must skip the WAF.
// clientIP is the trusted client address as resolved by the router.
func (s *State) BypassReason(r *http.Request, clientIP string) string {
	if s == nil {
		return ""
	}
	if len(s.nets) > 0 || len(s.ips) > 0 {
		host, _, err := net.SplitHostPort(clientIP)
		if err != nil {
			host = clientIP
		}
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			for _, a := range s.ips {
				if a.Equal(ip) {
					return "allowed-ip"
				}
			}
			for _, n := range s.nets {
				if n.Contains(ip) {
					return "allowed-ip"
				}
			}
		}
	}
	p, ok := cleanBypassPath(r)
	if !ok {
		return ""
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.HasPrefix(p, acmeChallengeDir) && len(p) > len(acmeChallengeDir) {
		return "acme-challenge"
	}
	if len(s.Policy.TrustedPaths) > 0 {
		host := hostOnly(r.Host)
		for _, tp := range s.Policy.TrustedPaths {
			if tp.Host != "" && !hostMatches(tp.Host, host) {
				continue
			}
			if tp.Exact && p == tp.Path || !tp.Exact && strings.HasPrefix(p, tp.Path) {
				return "trusted-path"
			}
		}
	}
	return ""
}

// cleanBypassPath returns the request path only if it is already in canonical
// form. Anything ambiguous (//, /./, /../, a leftover %, backslash, control
// characters, encoded slash or dot in the raw form) is refused, so path tricks
// can only ever result in the request being inspected, never in a bypass.
// Matching is case sensitive.
func cleanBypassPath(r *http.Request) (string, bool) {
	if r == nil || r.URL == nil {
		return "", false
	}
	p := r.URL.Path
	if p == "" || p[0] != '/' || strings.ContainsAny(p, "%\\") {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return "", false
		}
	}
	if raw := strings.ToLower(r.URL.RawPath); raw != "" && (strings.Contains(raw, "%2f") || strings.Contains(raw, "%2e") || strings.Contains(raw, "%5c")) {
		return "", false
	}
	cleaned := pathpkg.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	if cleaned != p {
		return "", false
	}
	return p, true
}

func hostOnly(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.TrimSuffix(h, ".")
}

func hostMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:]) && len(host) > len(pattern)-1
	}
	return pattern == host
}
