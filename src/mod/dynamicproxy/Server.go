package dynamicproxy

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

/*
	Server.go

	Main server for dynamic proxy core

	Routing Handler Priority (High to Low)
	- Special Routing Rule (e.g. acme)
	- Redirectable
	- Subdomain Routing
		- Access Router
			- Blacklist
			- Whitelist
			- Exploit Detection
		- Rate Limitor
		- SSO Auth
		- Basic Auth
		- Plugin Router
		- Vitrual Directory Proxy
		- Subdomain Proxy
	- Root router (default site router)
*/

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Parent.echObserve(r)
	if h.Parent.Option.Metrics.Enabled() {
		var done func()
		w, r, done = h.Parent.metricsBegin(w, r, nil)
		defer done()
	}
	/*
		Special Routing Rules and Redirection Routing
	*/
	if h.handleSpecialAndRedirect(w, r) {
		return
	}

	/*
		Host Routing
	*/
	//Extract request host to see if any proxy rule is matched
	domainOnly := r.Host
	if strings.Contains(r.Host, ":") {
		hostPath := strings.Split(r.Host, ":")
		domainOnly = hostPath[0]
	}
	sep := h.Parent.GetProxyEndpointFromHostname(domainOnly)
	if sep != nil && !sep.Disabled {
		//Matching proxy rule found. Run the shared pre-proxy chain
		//Automatic abuse banning (off by default): reject banned clients, feed the detectors
		var abuseDone func()
		var abuseRejected bool
		if w, r, abuseDone, abuseRejected = h.Parent.abuseBegin(w, r, sep); abuseRejected {
			return
		}
		defer abuseDone()
		w = h.Parent.pluginWrapResponse(w, r, sep) //plugin response stage, no-op without response plugins
		w = h.Parent.opsBegin(w, r, sep)           //request vars + CORS / error page / bandwidth wrapper (ops_handlers.go)
		if h.runEndpointChain(w, r, sep, domainOnly) {
			return
		}

		//Check if any virtual directory rules matches
		proxyingPath := strings.TrimSpace(r.RequestURI)
		targetProxyEndpoint := sep.GetVirtualDirectoryHandlerFromRequestURI(proxyingPath)
		if targetProxyEndpoint != nil && !targetProxyEndpoint.Disabled {
			//Virtual directory routing rule found. Route via vdir mode
			h.vdirRequest(w, r, targetProxyEndpoint)
			return
		} else if !strings.HasSuffix(proxyingPath, "/") && sep.ProxyType != ProxyTypeRoot {
			potentialProxtEndpoint := sep.GetVirtualDirectoryHandlerFromRequestURI(proxyingPath + "/")
			if potentialProxtEndpoint != nil && !potentialProxtEndpoint.Disabled {
				//Missing tailing slash. Redirect to target proxy endpoint
				http.Redirect(w, r, r.RequestURI+"/", http.StatusTemporaryRedirect)
				if !sep.DisableLogging {
					clientIP := h.Parent.GetClientIPForEndpoint(r, sep)
					h.Parent.Option.Logger.LogHTTPRequest(r, "redirect", 307, r.Host, "", clientIP)
				}
				return
			}
		}

		//Fallback to handle by the host proxy forwarder
		h.hostRequest(w, r, sep)
		return
	}

	/*
		Root Router Handling
	*/

	//Automatic abuse banning for the default site
	var abuseDone func()
	var abuseRejected bool
	if w, r, abuseDone, abuseRejected = h.Parent.abuseBegin(w, r, h.Parent.Root); abuseRejected {
		return
	}
	defer abuseDone()

	//Root access control based on default rule
	blocked := h.handleAccessRouting("default", w, r, h.Parent.Root)
	if blocked {
		return
	}

	/* WAF for the default site (root endpoint) -- WAF-HOOK: keep in the shared pre-proxy chain */
	if h.Parent.wafInspect(w, r, h.Parent.Root) {
		return
	}

	//Clean up the request URI
	proxyingPath := strings.TrimSpace(r.RequestURI)
	if !strings.HasSuffix(proxyingPath, "/") {
		potentialProxtEndpoint := h.Parent.getTargetProxyEndpointFromRequestURI(proxyingPath + "/")
		if potentialProxtEndpoint != nil {
			//Missing tailing slash. Redirect to target proxy endpoint
			http.Redirect(w, r, r.RequestURI+"/", http.StatusTemporaryRedirect)
		} else {
			//Passthrough the request to root
			h.handleRootRouting(w, r)
		}
	} else {
		//No routing rules found.
		h.handleRootRouting(w, r)
	}
}

/*
handleRootRouting

This function handle root routing (aka default sites) situations where there are no subdomain
, vdir or special routing rule matches the requested URI.

Once entered this routing segment, the root routing options will take over
for the routing logic.
*/
func (h *ProxyHandler) handleRootRouting(w http.ResponseWriter, r *http.Request) {
	domainOnly := r.Host
	if strings.Contains(r.Host, ":") {
		hostPath := strings.Split(r.Host, ":")
		domainOnly = hostPath[0]
	}

	//Get the proxy root config
	proot := h.Parent.Root
	switch proot.DefaultSiteOption {
	case DefaultSite_InternalStaticWebServer:
		fallthrough
	case DefaultSite_ReverseProxy:
		//They both share the same behavior
		//Check if any virtual directory rules matches
		proxyingPath := strings.TrimSpace(r.RequestURI)
		targetProxyEndpoint := proot.GetVirtualDirectoryHandlerFromRequestURI(proxyingPath)
		if targetProxyEndpoint != nil && !targetProxyEndpoint.Disabled {
			//Virtual directory routing rule found. Route via vdir mode
			h.vdirRequest(w, r, targetProxyEndpoint)
			return
		} else if !strings.HasSuffix(proxyingPath, "/") && proot.ProxyType != ProxyTypeRoot {
			potentialProxtEndpoint := proot.GetVirtualDirectoryHandlerFromRequestURI(proxyingPath + "/")
			if potentialProxtEndpoint != nil && !targetProxyEndpoint.Disabled {
				//Missing tailing slash. Redirect to target proxy endpoint
				http.Redirect(w, r, r.RequestURI+"/", http.StatusTemporaryRedirect)
				return
			}
		}

		//Do not log default site requests to avoid flooding the logs
		//h.Parent.logRequest(r, false, 307, "root", domainOnly, "")

		//No vdir match. Route via root router
		h.hostRequest(w, r, h.Parent.Root)
	case DefaultSite_Redirect:
		redirectTarget := strings.TrimSpace(proot.DefaultSiteValue)
		if redirectTarget == "" {
			redirectTarget = "about:blank"
		}

		//Check if the default site values start with http or https
		if !strings.HasPrefix(redirectTarget, "http://") && !strings.HasPrefix(redirectTarget, "https://") {
			redirectTarget = "http://" + redirectTarget
		}

		//Check if it is an infinite loopback redirect
		parsedURL, err := url.Parse(redirectTarget)
		if err != nil {
			//Error when parsing target. Send to root
			h.hostRequest(w, r, h.Parent.Root)
			return
		}
		hostname := parsedURL.Hostname()
		if hostname == domainOnly {
			h.Parent.logRequest(r, false, 500, "root-redirect", domainOnly, "", h.Parent.Root)
			http.Error(w, "Loopback redirects due to invalid settings", 500)
			return
		}

		h.Parent.logRequest(r, false, 307, "root-redirect", domainOnly, "", h.Parent.Root)
		http.Redirect(w, r, redirectTarget, http.StatusTemporaryRedirect)
	case DefaultSite_NotFoundPage:
		//Serve the not found page, use template if exists
		h.Parent.logDefaultSiteRequest(r, http.StatusNotFound, "root-404") //opt-in, rate limited
		h.serve404PageWithTemplate(w, r)
	case DefaultSite_NoResponse:
		//No response. Just close the connection
		h.Parent.logRequest(r, false, 444, "root-no_resp", domainOnly, "", h.Parent.Root)
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		conn.Close()
	case DefaultSite_TeaPot:
		//I'm a teapot
		h.Parent.logRequest(r, false, 418, "root-teapot", domainOnly, "", h.Parent.Root)
		http.Error(w, "I'm a teapot", http.StatusTeapot)
	default:
		//Unknown routing option. Send empty response
		h.Parent.logRequest(r, false, 544, "root-unknown", domainOnly, "", h.Parent.Root)
		http.Error(w, "544 - No Route Defined", 544)
	}
}

// Serve 404 page with template if exists
func (h *ProxyHandler) serve404PageWithTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	template, err := os.ReadFile(filepath.Join(h.Parent.Option.WebDirectory, "templates/notfound.html"))
	if err != nil {
		w.Write(localizedPage(r, page_hosterror))
	} else {
		w.Write(template)
	}
}

/*
handleSpecialAndRedirect applies the routing steps that sit above host routing:
external special routing rules (e.g. ACME) and redirection rules.
Shared by the TLS handler and the non-TLS listeners.
Returns true if the request has been handled.
*/
func (h *ProxyHandler) handleSpecialAndRedirect(w http.ResponseWriter, r *http.Request) bool {
	//Check if there are external routing rule (rr) matches.
	//If yes, route them via external rr
	matchedRoutingRule := h.Parent.GetMatchingRoutingRule(r)
	if matchedRoutingRule != nil {
		//Matching routing rule found. Let the sub-router handle it
		matchedRoutingRule.Route(w, r)
		return true
	}

	//Check if this is a redirection url
	if h.Parent.Option.RedirectRuleTable != nil && h.Parent.Option.RedirectRuleTable.IsRedirectable(r) {
		statusCode := h.Parent.Option.RedirectRuleTable.HandleRedirect(w, r)
		h.Parent.logRequest(r, statusCode != 500, statusCode, "redirect", r.Host, "", nil)
		return true
	}
	return false
}

/*
runEndpointChain is the single pre-proxy protection chain for a matched proxy
endpoint, shared by the TLS handler (ServeHTTP) and the non-TLS handlers
(port 80 bypass and secondary listening ports) so the two can never drift apart.

Order: allowed peer set -> access (blacklist / whitelist) -> client cert -> path rules -> plugin pre_auth -> WAF -> exploit detection -> rate limit
-> captcha -> auth (basic / SSO) -> plugin routing.

Returns true if the request has been fully handled (blocked or answered).
*/
func (h *ProxyHandler) runEndpointChain(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, domainOnly string) bool {
	//Direct peer must be in the allowed set (upstream #761), checked before anything else
	if h.enforcePeerSet(w, r, sep) {
		return true
	}

	//Access Check (blacklist / whitelist)
	ruleID := sep.AccessFilterUUID
	if sep.AccessFilterUUID == "" {
		//Use default rule
		ruleID = "default"
	}
	if h.handleAccessRouting(ruleID, w, r, sep) {
		//Request handled by subroute
		return true
	}

	//CORS preflight and public static responses (robots.txt, health checks ...) are answered before the heavier checks
	if h.handleCORSPreflight(w, r, sep) || h.handleStaticResponses(w, r, sep, true) {
		return true
	}

	//Networking: client certificate policy (mTLS) and path scoped rules, see clientcert.go / pathrules.go
	if h.enforceClientCert(w, r, sep) || h.handlePathRules(w, r, sep) || h.handleHeaderRules(w, r, sep) || h.handleBotRules(w, r, sep) {
		return true
	}

	/* Plugin pre_auth stage: bot filters etc, before WAF / captcha / auth */
	if h.Parent.routePluginStage(w, r, sep, zoraxyPlugin.HookStagePreAuth) {
		return true
	}

	/* WAF (Coraza + OWASP CRS) -- WAF-HOOK: runs on both the TLS and non-TLS paths via this shared chain */
	if h.Parent.wafInspect(w, r, sep) {
		return true
	}

	/* Exploit Detection */
	if sep.detector != nil {
		if sep.detector.CheckIsAttackWithCaptcha(w, r, h.Parent.exploitCaptchaResponder(sep)) {
			statusCode := sep.detector.GetResponseStatusCode()
			detail := "AI crawler / bot signature"
			if sep.detector.CheckCommonExploits && sep.detector.RequestContainCommonExploits(r) {
				detail = "common exploit pattern"
			}
			h.Parent.logRequestDetail(r, false, statusCode, "exploit-blocked", domainOnly, "blocked", sep, detail)
			return true
		}
	}

	// Rate Limit
	if sep.RequireRateLimit {
		err := h.handleRateLimitRouting(w, r, sep)
		if err != nil {
			if !sep.DisableLogging {
				clientIP := h.Parent.GetClientIPForEndpoint(r, sep)
				h.Parent.Option.Logger.LogHTTPRequest(r, "host", 307, r.Host, "", clientIP)
			}
			return true
		}
	}

	// CAPTCHA Gating
	if handled, challenged := h.Parent.handleCaptchaGating(w, r, sep); handled {
		if challenged {
			h.Parent.logRequest(r, false, 403, "captcha-required", domainOnly, "captcha", sep)
		}
		return true
	}

	//Validate auth (basic auth or SSO auth)
	if handleAuthProviderRouting(sep, w, r, h) {
		//Request handled by subroute
		return true
	}

	//Static responses that sit behind authentication
	if h.handleStaticResponses(w, r, sep, false) {
		return true
	}

	//Lua script handler / hook and Sablier gate (platform_chain.go), both off unless configured on the rule
	if h.handlePlatformStages(w, r, sep) {
		return true
	}

	//Plugin routing
	if h.Parent.routePlugin(w, r, sep) {
		return true
	}
	return false
}

// routePlugin lets the plugin manager (if any) handle the request
func (router *Router) routePlugin(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if router.pluginRouteHook != nil {
		//Test seam, a real plugin.Manager needs running plugin processes
		return router.pluginRouteHook(w, r, sep)
	}
	return router.routePluginStage(w, r, sep, zoraxyPlugin.HookStagePostAuth)
}
