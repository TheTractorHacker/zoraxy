package main

import "net/http"

// newPluginLoopbackHandler returns the handler for the plain HTTP loopback
// listener that is opened when the web UI itself is served over TLS. Plugins
// call back into Zoraxy through it, so it exposes the plugin API under
// /plugin/ and nothing else: the admin UI and the admin API must never be
// reachable over plain HTTP, not even on 127.0.0.1.
func newPluginLoopbackHandler(pluginAPI http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/plugin/", pluginAPI)
	mux.HandleFunc("/", http.NotFound)
	return mux
}
