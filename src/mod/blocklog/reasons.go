package blocklog

import "strings"

/*
	reasons.go

	Maps the "forwardType" string the router passes to logRequest (and statistic's
	Blocked flag) to a stable reason key plus a short detail. The same function drives
	statistic.IsBlockedForwardType, so the "Blocked" counters and this log can never
	disagree about what counts as a block.
*/

// Reason keys (stable, used by the API and the UI)
const (
	ReasonBlacklist        = "blacklist"
	ReasonWhitelist        = "whitelist"
	ReasonAutoBan          = "auto-ban"
	ReasonRateLimit        = "ratelimit"
	ReasonWAF              = "waf"
	ReasonExploit          = "exploit"
	ReasonBot              = "bot"
	ReasonHeaderRule       = "header-rule"
	ReasonCaptcha          = "captcha"
	ReasonCountryChallenge = "country-challenge"
	ReasonPathRule         = "path-rule"
	ReasonClientCert       = "client-cert"
	ReasonPeer             = "peer"
	ReasonAuth             = "auth"
	ReasonPlugin           = "plugin"
)

// Classify turns a router forwardType into a reason key and a detail. ok is false when the
// request was not rejected by Zoraxy itself.
func Classify(forwardType string) (reason, detail string, ok bool) {
	ft := forwardType
	dropped := false
	if strings.HasSuffix(ft, "-dropped") {
		ft = strings.TrimSuffix(ft, "-dropped")
		dropped = true
	}
	withDrop := func(d string) string {
		if dropped {
			if d != "" {
				return d + " (connection dropped)"
			}
			return "connection dropped"
		}
		return d
	}
	switch ft {
	case "blacklist":
		return ReasonBlacklist, withDrop(""), true
	case "whitelist":
		return ReasonWhitelist, withDrop("not on the allow list"), true
	case "auto-ban":
		return ReasonAutoBan, withDrop(""), true
	case "ratelimit":
		return ReasonRateLimit, "", true
	case "waf-blocked":
		return ReasonWAF, "", true
	case "exploit-blocked":
		return ReasonExploit, "", true
	case "captcha-required":
		return ReasonCaptcha, "", true
	case "plugin-blocked":
		return ReasonPlugin, "", true
	case "peer-not-allowed":
		return ReasonPeer, "", true
	case "path-rule-deny":
		return ReasonPathRule, "deny", true
	case "path-rule-noauth":
		return ReasonPathRule, "authentication required", true
	case "path-rule-ratelimit":
		return ReasonPathRule, "rate limit", true
	case "country-challenge", "country-challenge-unavailable":
		return ReasonCountryChallenge, strings.TrimPrefix(ft, "country-"), true
	case "bot-challenge", "bot-challenge-unavailable":
		return ReasonBot, strings.TrimPrefix(ft, "bot-"), true
	}
	switch {
	case strings.HasPrefix(ft, "client-cert-"):
		return ReasonClientCert, strings.TrimPrefix(ft, "client-cert-"), true
	case strings.HasPrefix(ft, "auth-"):
		return ReasonAuth, strings.TrimPrefix(ft, "auth-"), true
	case strings.HasPrefix(ft, "header-rule-"):
		return ReasonHeaderRule, withDrop(strings.TrimPrefix(ft, "header-rule-")), true
	case strings.HasPrefix(ft, "bot-"):
		if strings.HasSuffix(ft, "-logonly") {
			return "", "", false // log-only rule: the request went through
		}
		return ReasonBot, withDrop(strings.TrimPrefix(ft, "bot-")), true
	}
	return "", "", false
}

// IsBlocked reports whether the forwardType is a rejection by Zoraxy
func IsBlocked(forwardType string) bool {
	_, _, ok := Classify(forwardType)
	return ok
}

// ReasonInfo describes a reason for the UI
type ReasonInfo struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Why   string `json:"why"`
	Tab   string `json:"tab"`           // admin menu page (tab id) where the rule lives
	Where string `json:"where"`         // its menu label, for the link text
	Sec   string `json:"sec,omitempty"` // sub section of the Security Center, if any
}

// Reasons lists every reason with an explanation and where to change the rule
func Reasons() []ReasonInfo {
	return []ReasonInfo{
		{ReasonBlacklist, "Blacklist", "The client address, or its country, is on the blacklist of the access rule.", "access", "Access Rules", ""},
		{ReasonWhitelist, "Not on allow list", "The access rule only admits whitelisted addresses and this client is not one.", "access", "Access Rules", ""},
		{ReasonAutoBan, "Auto-ban", "The client was banned automatically after repeated bad requests.", "seccenter", "Security Center, Auto-ban", "abuse"},
		{ReasonRateLimit, "Rate limit", "The client sent more requests than the rate limit of the proxy rule allows.", "httprp", "HTTP Proxy, rule settings", ""},
		{ReasonWAF, "WAF", "A Web Application Firewall rule matched the request.", "waf", "WAF events", ""},
		{ReasonExploit, "Exploit detector", "The request looked like a known exploit probe (path traversal, SQL injection ...) or an AI crawler.", "httprp", "HTTP Proxy, rule settings", ""},
		{ReasonBot, "Bot rule", "The User-Agent matched a bot rule that blocks or challenges it.", "seccenter", "Security Center, Bot rules", "bots"},
		{ReasonHeaderRule, "Header rule", "A required request header was missing or wrong.", "seccenter", "Security Center, Header rules", "headers"},
		{ReasonCaptcha, "CAPTCHA", "The request was held back until a CAPTCHA is solved.", "captcha", "CAPTCHA", ""},
		{ReasonCountryChallenge, "Country challenge", "The client country has to solve a CAPTCHA first (or no CAPTCHA is configured, so it is refused).", "access", "Access Rules", ""},
		{ReasonPathRule, "Path rule", "A path-scoped rule denied the request, required authentication or limited its rate.", "httprp", "HTTP Proxy, rule settings", ""},
		{ReasonClientCert, "Client certificate", "The client certificate was missing or not accepted (mTLS).", "httprp", "HTTP Proxy, rule settings", ""},
		{ReasonPeer, "Peer not allowed", "The direct connection came from an address outside the allowed peer list of the rule.", "httprp", "HTTP Proxy, rule settings", ""},
		{ReasonAuth, "Authentication", "Basic auth, SSO or OAuth rejected the credentials.", "seccenter", "Security Center, Auth audit", "authaudit"},
		{ReasonPlugin, "Plugin", "A plugin refused the request.", "plugins", "Plugins", ""},
	}
}
