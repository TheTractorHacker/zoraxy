package dynamicproxy

import (
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	waf_inspect.go

	Glue between the proxy request chain and the self-contained waf package.
	The only call-site in the request chain is wafInspect(), which is a nil
	check when the WAF is disabled for the endpoint.
*/

// InitializeWAF compiles (or fetches from the shared cache) the WAF for this
// endpoint. A nil or "off" config results in no WAF at all. An error is returned
// if the configuration or custom rules are invalid.
func (pe *ProxyEndpoint) InitializeWAF() error {
	inst, err := waf.Default.Get(pe.WAF)
	if err != nil {
		pe.wafInst = nil
		return err
	}
	pe.wafInst = inst
	return nil
}

// wafInspect runs the request through the WAF of the endpoint.
// Returns true if the request was blocked and a response has been written.
func (router *Router) wafInspect(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if sep == nil || sep.wafInst == nil {
		return false
	}
	clientIP := router.GetClientIPForEndpoint(r, sep)
	blocked := sep.wafInst.Inspect(w, r, waf.RequestInfo{
		Endpoint: sep.RootOrMatchingDomain,
		ClientIP: clientIP,
		OnBlock: func(w http.ResponseWriter, r *http.Request, txID string) {
			// Same 403 page (and template override) as the other access blocks.
			// Rule details are logged server side only, never sent to the client.
			serveWAFBlockPage(w, router, txID)
		},
	})
	if blocked {
		router.logRequest(r, false, http.StatusForbidden, "waf-blocked", r.Host, "", sep)
	}
	return blocked
}

// serveWAFBlockPage writes the 403 page (honouring templates/forbidden.html in
// the web root) with the transaction ID so an admin can find the audit event.
func serveWAFBlockPage(w http.ResponseWriter, router *Router, txID string) {
	page, name := ErrorTemplateForbidden.getTemplateContent()
	if router != nil && router.Option != nil && router.Option.WebDirectory != "" {
		if custom, err := os.ReadFile(filepath.Join(router.Option.WebDirectory, "templates", name)); err == nil {
			page = custom
		}
	}
	body := string(page)
	marker := `<div style="text-align:center;font-size:small;opacity:.7;padding:1em">Request ID: ` + html.EscapeString(txID) + `</div>`
	if i := strings.LastIndex(strings.ToLower(body), "</body>"); i >= 0 {
		body = body[:i] + marker + body[i:]
	} else {
		body += marker
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Request-Id", txID)
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(body))
}
