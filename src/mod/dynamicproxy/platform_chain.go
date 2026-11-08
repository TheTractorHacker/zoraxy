package dynamicproxy

import "net/http"

// handlePlatformStages runs the optional per-rule stages added by the platform features, after authentication:
// Lua script handler / hook (script_handler.go) and the Sablier gate (sablier_gate.go).
// Returns true when the request was answered.
func (h *ProxyHandler) handlePlatformStages(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	return h.handleScript(w, r, sep) || h.handleSablier(w, r, sep)
}
