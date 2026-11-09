package dynamicproxy

import (
	"net/http"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	waf_response.go

	Glue between the proxy core (dpcore.ResponseGuard hook) and the response
	inspection of the waf package. responseGuard() is called when the
	ResponseRewriteRuleSet of a request is built and returns a nil interface
	(one nil check, no allocation) unless response protection is on for the endpoint.
*/

// responseGuard returns the response guard of a request, or nil when response protection is off
func (router *Router) responseGuard(r *http.Request, ep *ProxyEndpoint) dpcore.ResponseGuard {
	if ep == nil {
		return nil
	}
	rt := ep.wafRT.Load()
	if rt == nil || rt.resp == nil {
		return nil
	}
	return &responseGuardAdapter{router: router, ep: ep, rt: rt, r: r}
}

type responseGuardAdapter struct {
	router *Router
	ep     *ProxyEndpoint
	rt     *wafRuntime
	r      *http.Request
}

func (a *responseGuardAdapter) GuardResponse(req *http.Request, res *http.Response, streaming bool) int {
	r := a.r
	clientIP := a.router.GetClientIPForEndpoint(r, a.ep)
	// Trusted paths and allowed IPs skip the WAF, and with it response inspection
	if a.rt.res.Bypass && a.rt.state.BypassReason(r, clientIP) != "" {
		return 0
	}
	info := waf.ResponseInfo{
		Endpoint: a.ep.RootOrMatchingDomain,
		ClientIP: clientIP,
		Source:   a.rt.res.Label,
		Method:   r.Method,
		Host:     r.Host,
		Path:     r.URL.Path,
		URI:      r.URL.RequestURI(),
		// A blocked response notifies like a WAF block, but is not fed to the abuse detectors:
		// a leaking server is not a misbehaving client.
		OnBlock: func(waf.Event) {
			if BlockObserver != nil {
				BlockObserver(a.ep.RootOrMatchingDomain, "waf-response-blocked")
			}
		},
	}
	return a.rt.resp.Inspect(info, req, res, streaming)
}
