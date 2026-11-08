package plugins

import (
	"net/http"

	"github.com/armon/go-radix"
	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

// HandleRoute handles the request to the plugin at the post_auth stage: filter
// hooks first, then the legacy static / dynamic capture.
// return true if the request is handled by the plugin
// clientIP must be the trusted-proxy resolved client IP, not re-derived from raw request headers
func (m *Manager) HandleRoute(w http.ResponseWriter, r *http.Request, tags []string, clientIP string) bool {
	return m.HandleStage(w, r, tags, clientIP, zoraxyPlugin.HookStagePostAuth).Handled
}

// HandleStage runs one request stage (pre_auth or post_auth) for a request.
func (m *Manager) HandleStage(w http.ResponseWriter, r *http.Request, tags []string, clientIP string, stage zoraxyPlugin.HookStage) StageResult {
	if stage == zoraxyPlugin.HookStageResponse {
		return StageResult{}
	}
	if res := m.RunRequestStage(w, r, tags, clientIP, stage); res.Handled {
		return res
	}
	if stage != zoraxyPlugin.HookStagePostAuth {
		return StageResult{}
	}
	if m.handleLegacyCapture(w, r, tags, clientIP) {
		return StageResult{Handled: true}
	}
	return StageResult{}
}

// handleLegacyCapture is the original capture logic: static capture paths first, then dynamic sniff
func (m *Manager) handleLegacyCapture(w http.ResponseWriter, r *http.Request, tags []string, clientIP string) bool {
	//For each tag, check if the request path matches the static capture path
	var staticRoutehandlers []*Plugin          //The handler for the request, can be multiple plugins
	var longestPrefixAcrossAlltags string = "" //The longest prefix across all tags
	for _, tag := range tags {
		//Get the radix tree for the tag
		tree, ok := m.tagPluginMap.Load(tag)
		if ok {
			//Check if the request path matches the static capture path
			longestPrefix, pluginList, ok := tree.(*radix.Tree).LongestPrefix(r.URL.Path)
			if ok {
				if longestPrefix > longestPrefixAcrossAlltags {
					longestPrefixAcrossAlltags = longestPrefix
					staticRoutehandlers = pluginList.([]*Plugin)
				}
			}
		}
	}

	//Handle the static route if found
	if len(staticRoutehandlers) > 0 {
		//Handle the request
		staticRoutehandlers[0].HandleStaticRoute(w, r, longestPrefixAcrossAlltags)
		return true
	}

	//Dynamic capture: tagged and global plugins in priority order
	var dynamicRouteHandlers []*Plugin
	for _, plugin := range m.pluginsForRequest(tags) {
		if plugin.AcceptDynamicRoute() {
			dynamicRouteHandlers = append(dynamicRouteHandlers, plugin)
		}
	}
	if len(dynamicRouteHandlers) == 0 {
		return false
	}
	reqID := requestID(r)
	for _, plugin := range dynamicRouteHandlers {
		accepted, err := m.sniffPlugin(plugin, r, clientIP, reqID)
		if err != nil {
			if err != errBreakerOpen {
				m.logf(plugin, "dynamic capture sniff failed (request "+reqID+")", err)
			}
			if plugin.failsClosed() {
				writePluginError(w, http.StatusServiceUnavailable, "Service temporarily unavailable")
				return true
			}
			continue //fail open: let the next plugin handle the request
		}
		if accepted && plugin.dynamicRouteProxy != nil {
			plugin.serveDynamicCapture(w, r, reqID)
			return true
		}
	}
	return false
}
