package dynamicproxy

import (
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
	return router.captchaChallenge(w, r, sep, "country")
}

// captchaChallenge serves / verifies the endpoint CAPTCHA for a request that has to prove itself
// (country challenge, bot rule action "challenge"). Fails closed (403) when no CAPTCHA is configured.
func (router *Router) captchaChallenge(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, why string) bool {
	if sep == nil || sep.CaptchaConfig == nil || !sep.CaptchaConfig.IsConfigured() || router.captchaSessionStore == nil {
		//Fail closed: the country is meant to be restricted, so without a CAPTCHA it is blocked
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		w.Write(page_forbidden)
		router.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), why+"-challenge-unavailable")
		router.logRequest(r, false, 403, why+"-challenge-unavailable", r.Host, "", sep)
		return true
	}
	clientIP := router.GetClientIPForEndpoint(r, sep)

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
	router.logRequest(r, false, 403, why+"-challenge", r.Host, "", sep)
	return true
}
