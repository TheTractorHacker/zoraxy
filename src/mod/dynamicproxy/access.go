package dynamicproxy

import (
	"imuslab.com/zoraxy/mod/metrics"
	"net/http"
	"os"
	"path/filepath"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/eventsystem"
	"imuslab.com/zoraxy/mod/netutils"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin/events"
)

// Handle access check (blacklist / whitelist), return true if request is handled (aka blocked)
// if the return value is false, you can continue process the response writer
func (h *ProxyHandler) handleAccessRouting(ruleID string, w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	accessRule, err := h.Parent.Option.AccessController.GetAccessRuleByID(ruleID)
	if err != nil {
		//Unable to load access rule. Target rule not found?
		h.Parent.Option.Logger.PrintAndLog("proxy-access", "Unable to load access rule: "+ruleID, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - Internal Server Error"))
		return true
	}

	//Do not forward client-IP headers set by clients that are not trusted proxies
	accessRule.StripUntrustedClientIPHeaders(r)

	//Optional (default off): drop client-IP headers from any peer that is not a trusted proxy,
	//so the upstream only sees values built from the real connection (upstream #1359)
	if h.Parent.Option.SanitiseClientIPHeaders || (sep != nil && sep.SanitiseClientIPHeaders) {
		accessRule.SanitiseClientIPHeaders(r)
	}

	isBlocked, blockedReason := accessRequestBlocked(h.Parent, accessRule, h.Parent.Option.WebDirectory, w, r)
	if isBlocked {
		h.Parent.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), blockedReason)
		if accessRule.DropOnBlock {
			//Opt-in (upstream #908): no response at all, the page was not written
			h.Parent.logRequestRule(r, false, 444, blockedReason+"-dropped", r.Host, "", sep, "", AccessRuleKey(accessRule))
			dropConnection(w)
			return true
		}
		h.Parent.logRequestRule(r, false, 403, blockedReason, r.Host, "", sep, "", AccessRuleKey(accessRule))
		return true
	}

	//Opt-in (upstream #281): clients of the challenge countries solve the CAPTCHA instead of being blocked
	if accessRule.IsCountryChallenged(accessRule.GetClientIP(r)) {
		return h.Parent.countryChallenge(w, r, sep, accessRule)
	}
	return false
}

// Return boolean, return true if access is blocked
// For string, it will return the blocked reason (if any)
func accessRequestBlocked(router *Router, accessRule *access.AccessRule, templateDirectory string, w http.ResponseWriter, r *http.Request) (bool, string) {
	//Check if this ip is in blacklist
	clientIpAddr := accessRule.GetClientIP(r)
	if accessRule.IsBlacklisted(clientIpAddr) {
		if !accessRule.DropOnBlock {
			template, err := os.ReadFile(filepath.Join(templateDirectory, "templates/blacklist.html"))
			if err != nil {
				template = localizedPage(r, page_forbidden)
			}
			//a country on the blacklist (and not the address itself) is what the "region" sentence is about
			router.writeForbiddenPage(w, r, http.StatusForbidden, template, !accessRule.IsIPBlacklisted(clientIpAddr))
		}

		// Emit blacklisted IP blocked event
		// Get the comment for this IP
		comment, err := accessRule.GetBlacklistedIPComment(clientIpAddr)
		if err != nil {
			comment = "blacklisted"
		}
		eventsystem.Publisher.Emit(
			&events.BlacklistedIPBlockedEvent{
				IP:           clientIpAddr,
				Comment:      comment,
				RequestedURL: r.URL.String(),
				Hostname:     r.Host,
				UserAgent:    r.Header.Get("User-Agent"),
				Method:       r.Method,
			},
		)

		return true, "blacklist"
	}

	//Check if this ip is in whitelist
	if !accessRule.IsWhitelisted(clientIpAddr) {
		if !accessRule.DropOnBlock {
			template, err := os.ReadFile(filepath.Join(templateDirectory, "templates/whitelist.html"))
			if err != nil {
				template = localizedPage(r, page_forbidden)
			}
			router.writeForbiddenPage(w, r, http.StatusForbidden, template, len(accessRule.GetAllWhitelistedCountryCode()) > 0)
		}
		return true, "whitelist"
	}

	//Not blocked.
	return false, ""
}

// GetClientIPForEndpoint resolves the real client IP of a request using the
// access rule bounded to the given proxy endpoint. Header supplied addresses
// (X-Real-IP, CF-Connecting-IP, Fastly-Client-IP, X-Forwarded-For) are only
// honored when the access rule opted in to trusting proxy headers
func (router *Router) GetClientIPForEndpoint(r *http.Request, pe *ProxyEndpoint) string {
	ruleID := "default"
	if pe != nil && pe.AccessFilterUUID != "" {
		ruleID = pe.AccessFilterUUID
	}

	if router.Option != nil && router.Option.AccessController != nil {
		accessRule, err := router.Option.AccessController.GetAccessRuleByID(ruleID)
		if err == nil {
			if clientIP := accessRule.GetClientIP(r); clientIP != "" {
				return clientIP
			}
		}
	}

	//Access rule not available. Fallback to the connection address only
	return netutils.GetRequesterIPUntrusted(r)
}

// AccessRuleKey is the machine key of an access rule block in the blocked-request log
func AccessRuleKey(rule *access.AccessRule) string {
	if rule == nil {
		return ""
	}
	if rule.Name != "" {
		return "access:" + rule.Name
	}
	return "access:" + rule.ID
}
