package dynamicproxy

import (
	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/pathmatch"
	"net/http"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/metrics"
)

/*
Country challenge (upstream #281)

Clients of the access rule's "challenge" countries get the endpoint's CAPTCHA
instead of being blocked. A CAPTCHA must be configured on the endpoint
(CaptchaConfig, the "Require CAPTCHA" switch itself does not have to be on);
otherwise the rule falls back to a block, never to an open door.

Returns true if the request was handled (challenge page, verification, or block).
*/
func (router *Router) countryChallenge(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, rule *access.AccessRule) bool {
	return router.captchaChallengeFor(w, r, sep, "country", "", AccessRuleKey(rule))
}

// captchaChallenge serves / verifies the endpoint CAPTCHA for a request that has to prove itself
// (country challenge, bot rule action "challenge"). Fails closed (403) when no CAPTCHA is configured.
func (router *Router) captchaChallenge(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, why string) bool {
	return router.captchaChallengeFor(w, r, sep, why, "", "")
}

// captchaChallengeFor is captchaChallenge that also tells the blocked-request log which category or
// rule asked for the challenge (name, shown as "http_library (challenge, no CAPTCHA, acted as block)")
// and its machine key. The forwardType, and with it the statistics counters, is not changed.
func (router *Router) captchaChallengeFor(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, why, name, ruleID string) bool {
	if sep == nil || sep.CaptchaConfig == nil || !sep.CaptchaConfig.IsConfigured() || router.captchaSessionStore == nil {
		//Fail closed: the country is meant to be restricted, so without a CAPTCHA it is blocked
		router.writeForbiddenPage(w, r, http.StatusForbidden, localizedPage(r, page_forbidden), why == "country")
		router.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), why+"-challenge-unavailable")
		router.logRequestRule(r, false, 403, why+"-challenge-unavailable", r.Host, "", sep, blocklog.ChallengeDetail(name, true), ruleID)
		return true
	}
	if !sep.CaptchaConfig.ChallengeAllowedOnPath(pathmatch.RequestTarget(r)) {
		return false // outside the protected paths of this site: not challenged
	}
	clientIP := router.GetClientIPForEndpoint(r, sep)

	if r.URL.Path == captcha.AltchaChallengePath && sep.CaptchaConfig.Provider == captcha.ProviderAltcha {
		captcha.HandleAltchaChallenge(w, r, sep.CaptchaConfig)
		return true
	}
	if r.URL.Path == captcha.VerifyPath {
		captcha.HandleVerification(w, r, sep.CaptchaConfig, router.captchaSessionStore, clientIP)
		router.recordCaptchaVerification(w, sep)
		if !captchaVerifiedOK(w) {
			abuseNoteKind(r, "captcha_fail")
		}
		return true
	}
	if ok, _ := captcha.CheckSessionReason(r, router.captchaSessionStore); ok {
		return false
	}
	if captcha.CheckException(r, sep.CaptchaConfig.ExceptionRules, clientIP) {
		return false
	}
	domain := r.Host
	if domain == "" {
		domain = sep.RootOrMatchingDomain
	}
	captcha.RenderChallenge(w, r, sep.CaptchaConfig, domain, router.Option.WebDirectory)
	router.Option.Metrics.Event(metrics.EventCaptchaChallenge, endpointLabel(sep), why)
	router.logRequestRule(r, false, 403, why+"-challenge", r.Host, "", sep, blocklog.ChallengeDetail(name, false), ruleID)
	return true
}
