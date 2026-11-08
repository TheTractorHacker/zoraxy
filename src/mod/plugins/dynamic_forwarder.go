package plugins

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

// StartDynamicForwardRouter create and start a dynamic forward router for
// this plugin
func (p *Plugin) StartDynamicForwardRouter() error {
	// Create a new dpcore object to forward the traffic to the plugin
	targetURL, err := url.Parse("http://127.0.0.1:" + strconv.Itoa(p.AssignedPort) + p.Spec.DynamicCaptureIngress)
	if err != nil {
		fmt.Println("Failed to parse target URL: "+targetURL.String(), err)
		return err
	}
	thisRouter := dpcore.NewDynamicProxyCore(targetURL, "", &dpcore.DpcoreOptions{})
	p.dynamicRouteProxy = thisRouter
	return nil
}

// StopDynamicForwardRouter stops the dynamic forward router for this plugin
func (p *Plugin) StopDynamicForwardRouter() {
	if p.dynamicRouteProxy != nil {
		p.dynamicRouteProxy = nil
	}
}

// AcceptDynamicRoute returns whether this plugin accepts dynamic route
func (p *Plugin) AcceptDynamicRoute() bool {
	return p.Spec.DynamicCaptureSniff != "" && p.Spec.DynamicCaptureIngress != ""
}

// sniffPlugin asks the legacy dynamic capture sniff endpoint of the plugin whether it
// wants this request. A non-200 answer is a regular "skip"; only transport problems
// (connection refused, timeout) are failures and feed the circuit breaker.
func (m *Manager) sniffPlugin(p *Plugin, r *http.Request, clientIP string, reqID string) (accepted bool, err error) {
	if !p.AcceptDynamicRoute() {
		return false, nil
	}
	if !m.breakerAdmit(p) {
		return false, errBreakerOpen
	}
	forwardReq := zoraxy_plugin.EncodeForwardRequestPayload(r, clientIP)
	jsonData, err := json.Marshal(forwardReq)
	if err != nil {
		m.breakerRecord(p, nil)
		return false, nil
	}
	//The sniff endpoint has always been called with a trailing slash
	status, _, err := m.callPlugin(p, normalizeEndpoint(p.Spec.DynamicCaptureSniff)+"/", jsonData, reqID, 4096)
	m.breakerRecord(p, err)
	if err != nil {
		return false, err
	}
	return status == http.StatusOK, nil
}

func normalizeEndpoint(s string) string {
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return strings.TrimSuffix(s, "/")
}

// serveDynamicCapture proxies the whole request to the dynamic capture ingress of the plugin
func (p *Plugin) serveDynamicCapture(w http.ResponseWriter, r *http.Request, reqID string) {
	headers := [][]string{{"X-Zoraxy-RequestID", reqID}}
	if tok := p.invokeToken(); tok != "" {
		headers = append(headers, []string{zoraxy_plugin.InvokeTokenHeader, tok})
	}
	p.dynamicRouteProxy.ServeHTTP(w, r, &dpcore.ResponseRewriteRuleSet{
		UseTLS:          false,
		OriginalHost:    r.Host,
		ProxyDomain:     "127.0.0.1:" + strconv.Itoa(p.AssignedPort),
		NoCache:         true,
		PathPrefix:      normalizeEndpoint(p.Spec.DynamicCaptureIngress),
		AllowUpgrade:    true,
		UpstreamHeaders: headers,
	})
}
