package dynamicproxy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/rewrite"
)

/*
	ruletemplate.go

	Reusable named defaults for proxy rules (upstream #826 #877). A template only lists what it
	wants to set: every field is optional and unset fields leave the rule alone. Applying is
	additive/overriding, never destructive: tags are added, headers are merged by name and
	direction, the upstreams, domains and authentication of a rule are never touched.

	ApplyRuleTemplate works on a copy and reports each change, which is the "diff preview".
*/

type RuleTemplate struct {
	Name        string
	Description string
	Builtin     bool `json:",omitempty"` //Built in templates are read only

	HSTSMaxAge       *int64                      `json:",omitempty"` //Seconds, 0 turns HSTS off
	SecurityHeaders  bool                        `json:",omitempty"` //Add the standard browser hardening response headers
	Headers          []rewrite.UserDefinedHeader `json:",omitempty"` //Extra headers, merged by direction + name
	UptimeMonitor    *bool                       `json:",omitempty"`
	UptimeMonitorURI *string                     `json:",omitempty"`
	WAFSource        *string                     `json:",omitempty"` //inherit, off, detection_only, block, profile
	WAFProfile       *string                     `json:",omitempty"`
	RateLimit        *int64                      `json:",omitempty"` //Requests per second, 0 turns the limit off
	RateLimitBurst   *int64                      `json:",omitempty"`
	Tags             []string                    `json:",omitempty"` //Added to the rule's tags
	BlockExploits    *bool                       `json:",omitempty"`
	DisableWebSocket *bool                       `json:",omitempty"`
	WebsocketTimeout *int64                      `json:",omitempty"`
	ExposeRequestID  *bool                       `json:",omitempty"`

	// App preset metadata (see ruletemplate_presets.go). Category "app" templates are shown as presets.
	Category     string `json:",omitempty"`
	Note         string `json:",omitempty"` //Short plain-language note shown with the preset ("a starting point, review it")
	NoDowngrade  bool   `json:",omitempty"` //Never weaken what the rule already has: WAF, rate limit, exploit blocking, HSTS, own headers
	RequiresAuth bool   `json:",omitempty"` //The preset assumes the rule has an authentication provider; the UI warns when it has none
}

// RuleChange is one line of the diff between a rule and the rule after a template
type RuleChange struct {
	Field string
	Old   string
	New   string
}

var templateNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$`)
var wafSourceNames = map[string]bool{"inherit": true, "off": true, "detection_only": true, "block": true, "profile": true}

// securityHeaderSet is the header block of the "SecurityHeaders" option
var securityHeaderSet = []rewrite.UserDefinedHeader{
	{Direction: rewrite.HeaderDirection_ZoraxyToDownstream, Key: "X-Content-Type-Options", Value: "nosniff"},
	{Direction: rewrite.HeaderDirection_ZoraxyToDownstream, Key: "X-Frame-Options", Value: "SAMEORIGIN"},
	{Direction: rewrite.HeaderDirection_ZoraxyToDownstream, Key: "Referrer-Policy", Value: "strict-origin-when-cross-origin"},
	{Direction: rewrite.HeaderDirection_ZoraxyToDownstream, Key: "Cross-Origin-Opener-Policy", Value: "same-origin"},
}

func i64(v int64) *int64    { return &v }
func bptr(v bool) *bool     { return &v }
func sptr(v string) *string { return &v }

// BuiltinRuleTemplates are shipped with Zoraxy and cannot be edited
func BuiltinRuleTemplates() []*RuleTemplate {
	return append([]*RuleTemplate{
		{Name: "Secure web app", Builtin: true, Description: "HSTS (1 year), browser hardening headers, exploit blocking, uptime monitor, WAF in detection mode",
			HSTSMaxAge: i64(31536000), SecurityHeaders: true, BlockExploits: bptr(true), UptimeMonitor: bptr(true),
			WAFSource: sptr("detection_only"), Tags: []string{"web"}},
		{Name: "API backend", Builtin: true, Description: "Rate limit 100 req/s (burst 200), request id header, uptime monitor, WAF in detection mode",
			RateLimit: i64(100), RateLimitBurst: i64(200), ExposeRequestID: bptr(true), UptimeMonitor: bptr(true),
			WAFSource: sptr("detection_only"), HSTSMaxAge: i64(31536000), Tags: []string{"api"}},
		{Name: "WebSocket app", Builtin: true, Description: "WebSockets enabled with a 1 hour idle timeout, uptime monitor",
			DisableWebSocket: bptr(false), WebsocketTimeout: i64(3600), UptimeMonitor: bptr(true), Tags: []string{"websocket"}},
		{Name: "Static site", Builtin: true, Description: "HSTS, browser hardening headers, exploit blocking, light rate limit",
			HSTSMaxAge: i64(31536000), SecurityHeaders: true, BlockExploits: bptr(true), RateLimit: i64(50), RateLimitBurst: i64(100),
			Tags: []string{"static"}},
	}, AppPresets()...)
}

// Validate checks a template
func (t *RuleTemplate) Validate() error {
	if t == nil || !templateNameRe.MatchString(t.Name) {
		return errors.New("template name must be 1-64 characters: letters, digits, space, _ . -")
	}
	if len(t.Description) > 500 || len(t.Note) > 500 {
		return errors.New("description too long")
	}
	if t.Category != "" && t.Category != "app" {
		return errors.New("unknown template category")
	}
	if t.HSTSMaxAge != nil && (*t.HSTSMaxAge < 0 || *t.HSTSMaxAge > 63072000) {
		return errors.New("HSTS max age must be between 0 and 63072000 seconds")
	}
	if t.RateLimit != nil && (*t.RateLimit < 0 || *t.RateLimit > 1000000) {
		return errors.New("invalid rate limit")
	}
	if t.RateLimitBurst != nil && (*t.RateLimitBurst < 0 || *t.RateLimitBurst > 10000000) {
		return errors.New("invalid rate limit burst")
	}
	if t.WebsocketTimeout != nil && (*t.WebsocketTimeout < 0 || *t.WebsocketTimeout > 604800) {
		return errors.New("invalid WebSocket timeout")
	}
	if t.WAFSource != nil && !wafSourceNames[*t.WAFSource] {
		return errors.New("WAF source must be inherit, off, detection_only, block or profile")
	}
	if t.WAFSource != nil && *t.WAFSource == "profile" && (t.WAFProfile == nil || *t.WAFProfile == "") {
		return errors.New("a WAF profile name is required")
	}
	if len(t.Headers) > 32 || len(t.Tags) > 32 {
		return errors.New("too many headers or tags")
	}
	for _, h := range t.Headers {
		if !headerNameRe.MatchString(h.Key) || forbiddenStaticHeaders[strings.ToLower(h.Key)] || hasControl(h.Value) {
			return fmt.Errorf("invalid header %q", h.Key)
		}
	}
	for _, tag := range t.Tags {
		if strings.TrimSpace(tag) == "" || strings.ContainsAny(tag, ",\r\n") || len(tag) > 64 {
			return fmt.Errorf("invalid tag %q", tag)
		}
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ApplyRuleTemplate applies t to ep (mutating it) and returns the list of changes. Callers that only want
// a preview pass a CopyEndpoint of the rule.
func ApplyRuleTemplate(ep *ProxyEndpoint, t *RuleTemplate) ([]RuleChange, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	var ch []RuleChange
	add := func(field, old, nu string) {
		if old != nu {
			ch = append(ch, RuleChange{field, old, nu})
		}
	}
	if ep.HeaderRewriteRules == nil {
		ep.HeaderRewriteRules = GetDefaultHeaderRewriteRules()
	}
	hr := ep.HeaderRewriteRules

	if t.HSTSMaxAge != nil && !(t.NoDowngrade && *t.HSTSMaxAge < hr.HSTSMaxAge) {
		add("HSTS max age", fmt.Sprint(hr.HSTSMaxAge), fmt.Sprint(*t.HSTSMaxAge))
		hr.HSTSMaxAge = *t.HSTSMaxAge
	}
	headers := t.Headers
	if t.SecurityHeaders {
		headers = append(append([]rewrite.UserDefinedHeader{}, securityHeaderSet...), headers...)
	}
	for _, h := range headers {
		found := false
		for _, cur := range hr.UserDefinedHeaders {
			if cur.Direction == h.Direction && strings.EqualFold(cur.Key, h.Key) {
				found = true
				if t.NoDowngrade { //a preset never overwrites a header the operator already set
					break
				}
				if cur.Value != h.Value || cur.IsRemove != h.IsRemove {
					add("Header "+cur.Key, cur.Value, h.Value)
					cur.Value, cur.IsRemove = h.Value, h.IsRemove
				}
				break
			}
		}
		if !found {
			nh := h
			hr.UserDefinedHeaders = append(hr.UserDefinedHeaders, &nh)
			add("Header "+h.Key, "(not set)", h.Value)
		}
	}
	if t.UptimeMonitor != nil {
		add("Uptime monitor", yesNo(!ep.DisableUptimeMonitor), yesNo(*t.UptimeMonitor))
		ep.DisableUptimeMonitor = !*t.UptimeMonitor
	}
	if t.UptimeMonitorURI != nil && !(t.NoDowngrade && ep.UptimeMonitorURI != "") {
		add("Uptime monitor URI", ep.UptimeMonitorURI, *t.UptimeMonitorURI)
		ep.UptimeMonitorURI = *t.UptimeMonitorURI
	}
	if t.WAFSource != nil && !(t.NoDowngrade && wafRank(ep) >= wafRankOf(*t.WAFSource)) {
		old := ep.WAFSource
		if old == "" {
			old = "(default)"
		}
		nu := *t.WAFSource
		if nu == "profile" {
			nu += ": " + *t.WAFProfile
		}
		add("WAF source", old, nu)
		ep.WAFSource = *t.WAFSource
		ep.WAFProfile = ""
		if *t.WAFSource == "profile" {
			ep.WAFProfile = *t.WAFProfile
		}
	}
	rateApplied := t.RateLimit != nil
	if t.RateLimit != nil && t.NoDowngrade && (*t.RateLimit <= 0 || (ep.RequireRateLimit && ep.RateLimit > 0 && ep.RateLimit <= *t.RateLimit)) {
		rateApplied = false //an equal or stricter limit is already there
	}
	if rateApplied {
		add("Rate limit (req/s)", rateString(ep), fmt.Sprint(*t.RateLimit))
		ep.RequireRateLimit = *t.RateLimit > 0
		ep.RateLimit = *t.RateLimit
	}
	if t.RateLimitBurst != nil && (!t.NoDowngrade || rateApplied) {
		add("Rate limit burst", fmt.Sprint(ep.RateLimitBurst), fmt.Sprint(*t.RateLimitBurst))
		ep.RateLimitBurst = *t.RateLimitBurst
	}
	if t.BlockExploits != nil && !(t.NoDowngrade && !*t.BlockExploits) {
		add("Block common exploits", yesNo(ep.BlockCommonExploits), yesNo(*t.BlockExploits))
		ep.BlockCommonExploits = *t.BlockExploits
	}
	if t.DisableWebSocket != nil {
		add("WebSocket", yesNo(!ep.DisableWebSocket), yesNo(!*t.DisableWebSocket))
		ep.DisableWebSocket = *t.DisableWebSocket
	}
	if t.WebsocketTimeout != nil {
		add("WebSocket timeout (s)", fmt.Sprint(ep.WebsocketTimeout), fmt.Sprint(*t.WebsocketTimeout))
		ep.WebsocketTimeout = *t.WebsocketTimeout
	}
	if t.ExposeRequestID != nil {
		cur := ep.Ops != nil && ep.Ops.ExposeRequestID
		add("X-Request-Id response header", yesNo(cur), yesNo(*t.ExposeRequestID))
		if ep.Ops == nil {
			ep.Ops = &OpsConfig{}
		}
		ep.Ops.ExposeRequestID = *t.ExposeRequestID
		ep.Ops.rt.Store(nil)
	}
	if len(t.Tags) > 0 {
		have := map[string]bool{}
		for _, tag := range ep.Tags {
			have[tag] = true
		}
		var added []string
		for _, tag := range t.Tags {
			if !have[tag] {
				ep.Tags = append(ep.Tags, tag)
				have[tag] = true
				added = append(added, tag)
			}
		}
		if len(added) > 0 {
			add("Tags", strings.Join(ep.Tags[:len(ep.Tags)-len(added)], ", "), strings.Join(ep.Tags, ", "))
		}
	}
	return ch, nil
}

// wafRankOf orders the WAF sources by how much they protect. An unknown or custom setup ranks highest so a
// no-downgrade template never replaces it.
func wafRankOf(source string) int {
	switch source {
	case "off":
		return 0
	case "", "inherit":
		return 1
	case "detection_only":
		return 2
	default: //block, profile, custom
		return 3
	}
}

func wafRank(ep *ProxyEndpoint) int {
	if ep.WAFSource == "" && ep.WAF != nil {
		return 3
	}
	return wafRankOf(ep.WAFSource)
}

func rateString(ep *ProxyEndpoint) string {
	if !ep.RequireRateLimit {
		return "off"
	}
	return fmt.Sprint(ep.RateLimit)
}
