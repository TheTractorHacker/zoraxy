package dynamicproxy

import (
	"context"
	"imuslab.com/zoraxy/mod/pathmatch"
	"net/http"
	"strconv"
	"time"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/metrics"
	"imuslab.com/zoraxy/mod/ruleset"
)

/*
	ruleset_hook.go

	Glue between the request chain and the rules engine (mod/ruleset).

	Where it runs: in runEndpointChain (and for the default site in ServeHTTP) right after the access lists
	(blacklist / whitelist), which also resolve the trusted-proxy client address, and before CORS preflight,
	path / header / bot rules, plugin pre_auth, WAF, exploit detection, rate limit, CAPTCHA and authentication.
	So `skip` can switch off waf, rate_limit, captcha and auth, and a rule can answer a request before any
	of them. The global rules run first, then the rules of the proxy rule (site).

	Cost with no rule: Engine.Active() is one atomic pointer load.

	Results are passed on as follows
	  - skip           returned as a bit mask to runEndpointChain (no context lookup on the hot path)
	  - tag            kept in the request context; blocked-request log entries carry the tags
	  - header actions request headers are changed in place, response headers are applied where the
	                   proxy builds the downstream header set (hostRequest / vdirRequest)
*/

type rulesCtxKey struct{}

// rulesState is what the rules leave for later stages of the same request
type rulesState struct {
	tags        []string
	respHeaders [][]string // {name, value}; an empty value removes the header
}

func rulesStateFrom(r *http.Request) *rulesState {
	st, _ := r.Context().Value(rulesCtxKey{}).(*rulesState)
	return st
}

func rulesStateFor(r *http.Request) *rulesState {
	if st := rulesStateFrom(r); st != nil {
		return st
	}
	st := &rulesState{}
	*r = *r.WithContext(context.WithValue(r.Context(), rulesCtxKey{}, st))
	return st
}

// rulesTags returns the tags set on the request (nil unless rules are active and tagged it)
func (router *Router) rulesTags(r *http.Request) []string {
	if !router.Option.Rules.Active() {
		return nil
	}
	if st := rulesStateFrom(r); st != nil {
		return st.tags
	}
	return nil
}

// rulesDownstreamHeaders returns the response header changes requested by rules, in the format dpcore takes
func (router *Router) rulesDownstreamHeaders(r *http.Request) [][]string {
	if !router.Option.Rules.Active() {
		return nil
	}
	if st := rulesStateFrom(r); st != nil {
		return st.respHeaders
	}
	return nil
}

func (router *Router) rulesSiteKey(sep *ProxyEndpoint) string {
	if sep == nil || sep == router.Root {
		return ruleset.DefaultSiteKey
	}
	return sep.RootOrMatchingDomain
}

// handleRuleset evaluates the rules for the request. handled is true when the request was answered.
// skips are the protections the rules switched off for this request (ruleset.SkipBit*).
func (router *Router) handleRuleset(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) (handled bool, skips uint8) {
	eng := router.Option.Rules
	if !eng.Active() {
		return false, 0
	}
	clientIP := router.GetClientIPForEndpoint(r, sep)
	if eng.NeedsChallengeEndpoints() && router.ruleChallengeEndpoints(w, r, sep, clientIP) {
		return true, 0
	}
	run := eng.Begin(&ruleset.Env{R: r, ClientIP: clientIP, Country: eng.Country}, router.rulesSiteKey(sep))
	if run == nil {
		return false, 0
	}
	for m := run.Next(); m != nil; m = run.Next() {
		if m.DryRun {
			continue //counted and recorded by the engine, never acts
		}
		a := &m.Action
		switch a.Type {
		case ruleset.ActAllow:
			run.Stop()
		case ruleset.ActLog:
			//the hit itself is the record (counters, recent matches)
		case ruleset.ActTag:
			st := rulesStateFor(r)
			if len(st.tags) < 16 && !ruleHasTag(st.tags, a.Tag) {
				st.tags = append(st.tags, a.Tag)
			}
		case ruleset.ActSkip:
			mask, later := a.SkipMask()
			skips |= mask
			if later {
				run.Stop()
			}
		case ruleset.ActSetReqH:
			r.Header.Set(a.Name, a.Value)
		case ruleset.ActDelReqH:
			r.Header.Del(a.Name)
		case ruleset.ActSetRespH:
			st := rulesStateFor(r)
			st.respHeaders = append(st.respHeaders, []string{a.Name, a.Value})
		case ruleset.ActDelRespH:
			st := rulesStateFor(r)
			st.respHeaders = append(st.respHeaders, []string{a.Name, ""})
		case ruleset.ActBlock:
			router.ruleBlock(w, r, sep, m)
			return true, skips
		case ruleset.ActRedirect:
			router.ruleRedirect(w, r, sep, m)
			return true, skips
		case ruleset.ActRateLimit:
			if clientIP == "" {
				continue
			}
			if !router.rateLimitCounter.Allow("rule:"+m.Site+":"+m.ID, clientIP, a.Rate, a.Burst) {
				router.ruleRateLimited(w, r, sep, m)
				return true, skips
			}
		case ruleset.ActChallenge:
			if router.ruleChallenge(w, r, sep, m, clientIP) {
				return true, skips
			}
		}
	}
	return false, skips
}

func ruleHasTag(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// applyRespHeaders puts the response header changes of the rules on an answer the rules produce themselves
func applyRespHeaders(w http.ResponseWriter, r *http.Request) {
	if st := rulesStateFrom(r); st != nil {
		for _, h := range st.respHeaders {
			if h[1] == "" {
				w.Header().Del(h[0])
			} else {
				w.Header().Set(h[0], h[1])
			}
		}
	}
}

func statusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return strconv.Itoa(code) + " " + t
	}
	return strconv.Itoa(code)
}

func (router *Router) ruleBlock(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, m *ruleset.Matched) {
	a := &m.Action
	status := a.StatusOr(http.StatusForbidden)
	router.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "rule")
	router.logRequestDetail(r, false, status, "rule-block", r.Host, "", sep, m.Name)
	//Only a rule that asks for it feeds the automatic ban. An empty kind is "noted, nothing to report",
	//which also stops the 403 status from being counted as a plain forbidden response.
	if a.ReportAbuse {
		abuseNoteKind(r, abuse.KindForbidden)
	} else {
		abuseNoteKind(r, "")
	}
	applyRespHeaders(w, r)
	if a.Body != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		w.Write([]byte(a.Body))
		return
	}
	if status == http.StatusForbidden {
		serveProxyRequestError(w, r, status, router, ErrorTemplateForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write([]byte(statusText(status) + "\n"))
}

func (router *Router) ruleRedirect(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, m *ruleset.Matched) {
	a := &m.Action
	status := a.StatusOr(http.StatusFound)
	abuseNoteKind(r, "")
	router.logRequestDetail(r, true, status, "rule-redirect", r.Host, "", sep, m.Name)
	applyRespHeaders(w, r)
	w.Header().Set("Location", a.RedirectTarget(r))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
}

func (router *Router) ruleRateLimited(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, m *ruleset.Matched) {
	a := &m.Action
	status := a.StatusOr(http.StatusTooManyRequests)
	router.Option.Metrics.Event(metrics.EventRateLimited, endpointLabel(sep), "rule")
	router.logRequestDetail(r, false, status, "rule-ratelimit", r.Host, "", sep, m.Name)
	applyRespHeaders(w, r)
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(statusText(status) + "\n"))
}

// ---------------------------------------------------------------------
// challenge: the endpoint's CAPTCHA, remembered by a signed pass cookie (the approach of the WAF graduated
// response, with its own cookie and signing scope so passing a rule challenge does not pass a WAF challenge)

const ruleChallengeCookie = "zoraxy_rule_challenge"

func ruleChallengeScope(sep *ProxyEndpoint) string { return "ruleset|" + sep.RootOrMatchingDomain }

func (router *Router) ruleChallengeValid(r *http.Request, sep *ProxyEndpoint, clientIP string) bool {
	c, err := r.Cookie(ruleChallengeCookie)
	if err != nil {
		return false
	}
	return router.wafChallengeSigner().Validate(c.Value, ruleChallengeScope(sep), clientIP, r.UserAgent())
}

// ruleChallenge returns true when the request was answered (challenge page or fail-closed block)
func (router *Router) ruleChallenge(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, m *ruleset.Matched, clientIP string) bool {
	if !router.wafChallengeAvailable(sep) {
		//No CAPTCHA provider (or no session store): a challenge cannot be solved, so refuse. Failing open would
		//let exactly the requests the rule wants to hold back through.
		router.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "rule")
		router.logRequestDetail(r, false, http.StatusForbidden, "rule-challenge-unavailable", r.Host, "", sep, m.Name)
		abuseNoteKind(r, "")
		applyRespHeaders(w, r)
		serveProxyRequestError(w, r, http.StatusForbidden, router, ErrorTemplateForbidden)
		return true
	}
	if router.ruleChallengeValid(r, sep, clientIP) || !sep.CaptchaConfig.ChallengeAllowedOnPath(pathmatch.RequestTarget(r)) {
		return false
	}
	abuseNoteKind(r, "") //a challenge is not a block
	applyRespHeaders(w, r)
	w.Header().Set("X-Zoraxy-Captcha-Reason", "rule-challenge")
	domain := r.Host
	if domain == "" {
		domain = sep.RootOrMatchingDomain
	}
	captcha.RenderChallenge(w, r, sep.CaptchaConfig, domain, router.Option.WebDirectory)
	router.Option.Metrics.Event(metrics.EventCaptchaChallenge, endpointLabel(sep), "rule-challenge")
	router.logRequestDetail(r, false, http.StatusForbidden, "rule-challenge", r.Host, "", sep, m.Name)
	return true
}

// ruleChallengeEndpoints answers the CAPTCHA verification requests of a rule challenge (they are not
// forwarded). Returns true when the request was answered.
func (router *Router) ruleChallengeEndpoints(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, clientIP string) bool {
	if !router.wafChallengeAvailable(sep) {
		return false
	}
	if r.URL.Path == captcha.AltchaChallengePath && sep.CaptchaConfig.Provider == captcha.ProviderAltcha {
		captcha.HandleAltchaChallenge(w, r, sep.CaptchaConfig)
		return true
	}
	if r.URL.Path != captcha.VerifyPath {
		return false
	}
	ttl := time.Duration(router.Option.Rules.ChallengeTTLMinutes()) * time.Minute
	var base http.ResponseWriter = w
	if rt := sep.wafRT.Load(); rt != nil && rt.res.Config != nil && rt.res.Config.ChallengeEnabled() {
		//This path is also the verification endpoint of the WAF challenge band; this stage answers it first,
		//so it must leave the WAF pass cookie behind too or a visitor would be challenged in a loop
		base = &challengeCookieWriter{ResponseWriter: w, router: router, r: r, sep: sep, clientIP: clientIP, ttl: rt.res.Config.ChallengeTTL()}
	}
	cw := &ruleChallengeWriter{ResponseWriter: base, router: router, r: r, sep: sep, clientIP: clientIP, ttl: ttl}
	captcha.HandleVerification(cw, r, sep.CaptchaConfig, router.captchaSessionStore, clientIP)
	router.recordCaptchaVerification(w, sep)
	if !captchaVerifiedOK(w) {
		abuseNoteKind(r, abuse.KindCaptchaFail)
	}
	return true
}

// ruleChallengeWriter adds the pass cookie to a successful verification answer (see challengeCookieWriter)
type ruleChallengeWriter struct {
	http.ResponseWriter
	router   *Router
	r        *http.Request
	sep      *ProxyEndpoint
	clientIP string
	ttl      time.Duration
	done     bool
}

func (w *ruleChallengeWriter) addCookie() {
	if w.done {
		return
	}
	w.done = true
	if !captchaVerifiedOK(w.ResponseWriter) {
		return
	}
	value, expires := w.router.wafChallengeSigner().Issue(ruleChallengeScope(w.sep), w.clientIP, w.r.UserAgent(), w.ttl)
	http.SetCookie(w.ResponseWriter, &http.Cookie{
		Name: ruleChallengeCookie, Value: value, Path: "/", MaxAge: int(w.ttl.Seconds()), Expires: expires,
		HttpOnly: true, Secure: w.r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
}

func (w *ruleChallengeWriter) WriteHeader(code int) {
	w.addCookie()
	w.ResponseWriter.WriteHeader(code)
}

func (w *ruleChallengeWriter) Write(b []byte) (int, error) {
	w.addCookie()
	return w.ResponseWriter.Write(b)
}

func (w *ruleChallengeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
