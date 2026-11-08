package dynamicproxy

import (
	"net/http"

	"imuslab.com/zoraxy/mod/plugins"
	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

/*
	Plugin hook glue

	Thin adapters between the shared pre-proxy chain (runEndpointChain) and the
	plugin manager hook stages. All logic lives in the plugins package.
*/

// routePluginStage runs a request stage of the plugin filter hooks.
// It returns true if the request has been answered by a plugin.
func (router *Router) routePluginStage(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, stage zoraxyPlugin.HookStage) bool {
	if router.Option.PluginManager == nil {
		return false
	}
	res := router.Option.PluginManager.HandleStage(w, r, sep.Tags, router.GetClientIPForEndpoint(r, sep), stage)
	if res.Denied {
		router.logRequest(r, false, res.Status, "plugin-blocked", r.Host, res.PluginID, sep)
	}
	return res.Handled
}

// pluginWrapResponse installs the response stage of the plugin hooks (no-op when no
// plugin registered for it)
func (router *Router) pluginWrapResponse(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) http.ResponseWriter {
	if router.Option.PluginManager == nil {
		return w
	}
	var m *plugins.Manager = router.Option.PluginManager
	return m.WrapResponse(w, r, sep.Tags, router.GetClientIPForEndpoint(r, sep))
}
