package dynamicproxy

import (
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/metrics"
)

/*
	Prometheus metrics glue

	Only called behind `Option.Metrics.Enabled()`, so a disabled registry costs
	one nil check and one atomic load per request. The endpoint label is always
	the configured rule name (RootOrMatchingDomain), never a raw Host header,
	path or client address.
*/

// DefaultSiteMetricsLabel is the endpoint label of requests that matched no proxy rule
const DefaultSiteMetricsLabel = "_default"

// endpointLabel returns the bounded metrics label of an endpoint
func endpointLabel(sep *ProxyEndpoint) string {
	if sep == nil || sep.RootOrMatchingDomain == "" {
		return DefaultSiteMetricsLabel
	}
	return sep.RootOrMatchingDomain
}

// metricsBegin resolves the endpoint (when the caller has not) and starts measuring
func (router *Router) metricsBegin(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) (http.ResponseWriter, *http.Request, func()) {
	if sep == nil {
		domainOnly := r.Host
		if i := strings.IndexByte(domainOnly, ':'); i >= 0 {
			domainOnly = domainOnly[:i]
		}
		if found := router.GetProxyEndpointFromHostname(domainOnly); found != nil && !found.Disabled {
			sep = found
		}
	}
	return router.Option.Metrics.Begin(w, r, endpointLabel(sep))
}

// recordCaptchaVerification counts the outcome of a /verify call. The captcha
// package signals success by setting the session cookie before it answers.
func (router *Router) recordCaptchaVerification(w http.ResponseWriter, sep *ProxyEndpoint) {
	m := router.Option.Metrics
	if !m.Enabled() {
		return
	}
	for _, c := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, captcha.CookieName+"=") {
			m.Event(metrics.EventCaptchaVerified, endpointLabel(sep), "ok")
			return
		}
	}
	m.Event(metrics.EventCaptchaFailed, endpointLabel(sep), "failed")
}
