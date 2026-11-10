package posture

import "time"

// Facts is a snapshot of everything the checks look at. A nil section means the
// host could not determine it, and the checks that need it report unknown.
type Facts struct {
	Now time.Time

	Admin    *AdminFacts
	Proxy    *ProxyFacts
	Certs    *CertFacts
	WAF      *WAFFacts
	Abuse    *AbuseFacts
	Access   *AccessFacts
	Bots     *BotFacts
	Tokens   *TokenFacts
	SSO      *SSOFacts
	Updater  *UpdaterFacts
	Backup   *BackupFacts
	Notify   *NotifyFacts
	ECH      *ECHFacts
	Tools    *ToolFacts
	Visitors *VisitorFacts
	Cluster  *ClusterFacts
}

// AdminFacts: the management interface
type AdminFacts struct {
	AuthRequired  bool   // false with -noauth
	TLSMode       string // off | auto | custom
	ListenAddr    string // the -port value, e.g. ":8000" or "127.0.0.1:8000"
	AllInterfaces bool   // bound to every interface
	Loopback      bool   // bound to a loopback address only
}

// RuleFacts: one proxy rule (host rule) or the default site
type RuleFacts struct {
	Name      string
	Disabled  bool
	IsDefault bool   // the default site (root), excluded from per rule counts
	WAFMode   string // off | detection_only | block
	WAFOrigin string // where the mode comes from: inherit (central policy), off, detection_only, block, profile, custom
	RateLimit bool
	// PathRateLimits are the path patterns of the rule's path scoped rate limits (rate_limit path rules)
	PathRateLimits []string
	AuthMethod     string // none | basic | forward | oauth2 | zorxauth
	// AccessLimited is true when the access rule of this proxy rule has an IP/country allow list switched on
	AccessLimited  bool
	UptimeMonitor  bool
	HSTSMaxAge     int64
	Logging        bool
	BlockExploits  bool
	ChallengeBand  bool // the WAF challenge band is configured
	ChallengeReady bool // ... and a CAPTCHA provider can serve it
	RequireCaptcha bool
	CaptchaKeysOK  bool   // provider keys present (or provider needs none)
	BotPolicy      string // "", on, off
	ForwardAuthURL string
	Wildcard       bool // host contains a wildcard
}

// ProxyFacts: the reverse proxy listener and its rules
type ProxyFacts struct {
	UseTLS             bool
	Port               int
	ListenOnPort80     bool
	ForceHTTPSRedirect bool
	MinTLSVersion      string // "1.0", "1.1", "1.2", "1.3" or "" (unset = Go default 1.2)
	DevelopmentMode    bool
	SanitiseClientIP   bool
	DefaultSite        string // human readable: "static web server", "reverse proxy", "redirect", "404 page", "no response"
	DefaultSiteProxies bool   // the default site forwards unknown host names to an upstream
	Rules              []RuleFacts
}

// HostRules returns the enabled host rules (no default site, no disabled rule)
func (p *ProxyFacts) HostRules() []RuleFacts {
	var out []RuleFacts
	for _, r := range p.Rules {
		if !r.IsDefault && !r.Disabled {
			out = append(out, r)
		}
	}
	return out
}

// HostCert is the certificate verdict for one served host name
type HostCert struct {
	Host     string
	State    string // ok | selfsigned | fallback | missing | expired | mismatch (tlscert.Cert*)
	DaysLeft int    // only meaningful when NotAfter is set
	NotAfter time.Time
}

// CertFacts: certificates actually served for the proxy rules
type CertFacts struct {
	Hosts   []HostCert
	Skipped int // host names that cannot carry a public certificate and were not checked (wildcards, IP addresses)
	Stored  int // certificates in the store
}

// WAFFacts: the central WAF policy
type WAFFacts struct {
	PolicyEnabled          bool
	DefaultMode            string
	ParanoiaLevel          int
	InboundThreshold       int
	IgnoreAnalyticsCookies bool
}

// AbuseFacts: the auto-ban engine
type AbuseFacts struct {
	Enabled          bool
	EnabledDetectors []string
	TotalDetectors   int
}

// AccessFacts: the default access rule
type AccessFacts struct {
	TrustProxyHeadersOnly bool
	BlacklistEnabled      bool
	WhitelistEnabled      bool
	TrustedProxies        int
}

// BotFacts: bot (User-Agent) rules
type BotFacts struct {
	Enabled           bool
	EnabledCategories int
}

// Token is an API token, without any secret
type Token struct {
	Name     string
	Scope    string
	Created  time.Time
	LastUsed time.Time // zero = never
	Expires  time.Time // zero = never
	Revoked  bool
	Expired  bool
}

// TokenFacts: API tokens
type TokenFacts struct{ Tokens []Token }

// SSOURL is a URL used by an SSO provider or a forward-auth rule
type SSOURL struct {
	Owner string // provider or rule name
	Kind  string // issuer, token endpoint, forward-auth ...
	URL   string
}

// SSOFacts: URLs the SSO integrations talk to
type SSOFacts struct {
	Providers int
	URLs      []SSOURL
}

// UpdaterFacts: update state from the local cache; never from a network call
type UpdaterFacts struct {
	Offline         bool
	Checked         bool      // a release list is cached
	CheckedAt       time.Time // when the cache was filled
	UpdateAvailable bool
	Latest          string
	Current         string
	Channel         string
}

// BackupFacts: backups Zoraxy knows about (pre-update backups)
type BackupFacts struct {
	Count  int
	Latest time.Time
}

// NotifyFacts: notification channels
type NotifyFacts struct {
	Channels int // enabled channels
	Webhooks int // enabled webhooks
	Command  bool
}

// ECHFacts: Encrypted Client Hello
type ECHFacts struct {
	Enabled    bool
	PublicName string
	CertState  string // tlscert.Cert* state of the public name
	CertReason string
}

// ToolFacts: optional features that widen the attack surface
type ToolFacts struct {
	ForwardProxy bool
	ForwardPort  int
	WebSSHLoop   bool // -sshlb
}

// VisitorFacts: how clients reached the proxy (used to detect a CDN in front)
type VisitorFacts struct {
	Via   map[string]int // direct | cloudflare | proxy
	Total int
}

// ClusterFacts: HA / Fleet role
type ClusterFacts struct{ Role string }
