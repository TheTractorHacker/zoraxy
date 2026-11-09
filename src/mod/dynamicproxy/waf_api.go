package dynamicproxy

import (
	"net/http"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	waf_api.go

	Glue between the proxy request chain and the API protection guard
	(waf/apiguard*.go). Called from wafInspect before the Coraza inspection.
*/

// buildAPIGuard resolves and compiles the API protection of an endpoint setting. An invalid
// configuration is an error (rejects the save); a spec that does not compile is not (see waf.Manager.NewGuard).
func buildAPIGuard(set waf.Setting, st *waf.State) (*waf.Guard, error) {
	return waf.Default.NewGuard(st.ResolveAPI(set))
}

// apiInspect runs the request through the API guard. Returns true if it was blocked and answered.
func (router *Router) apiInspect(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, rt *wafRuntime, clientIP string) bool {
	detail, status := "", http.StatusBadRequest
	blocked := rt.api.Inspect(w, r, waf.RequestInfo{
		OnEvent:  func(ev waf.Event) { detail, status = ev.BlockSummary(), waf.APIViolationStatus(ev.Violation) },
		Endpoint: sep.RootOrMatchingDomain,
		ClientIP: clientIP,
		Source:   rt.res.Label,
	})
	if blocked {
		// Counted as a WAF block: block log, notifications and the auto-ban (abuse.KindWAF)
		router.logRequestDetail(r, false, status, "waf-blocked", r.Host, "", sep, "api: "+detail)
	}
	return blocked
}
