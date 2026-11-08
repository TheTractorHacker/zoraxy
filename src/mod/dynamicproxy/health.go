package dynamicproxy

import (
	"net/http"

	"imuslab.com/zoraxy/mod/cluster"
)

/*
	health.go

	Serves /.zoraxy/health on the proxy listeners before any host routing so
	external load balancers and keepalived scripts get an answer regardless
	of the Host header. Only that exact path is intercepted.
*/

// sessionSecretFor returns the key input for session signing.
func sessionSecretFor(o *RouterOption) string {
	if o.SessionSecret != "" {
		return o.SessionSecret
	}
	return o.HostUUID
}

// activeEndpointCount counts enabled proxy endpoints.
func (router *Router) activeEndpointCount() int {
	n := 0
	router.ProxyEndpoints.Range(func(_, v any) bool {
		if ep, ok := v.(*ProxyEndpoint); ok && !ep.Disabled {
			n++
		}
		return true
	})
	return n
}

// ServeHealth answers the health request if it is one and returns true when
// the request was handled.
func (router *Router) ServeHealth(w http.ResponseWriter, r *http.Request) bool {
	h := router.Option.Health
	if h == nil || !cluster.IsHealthRequest(r) {
		return false
	}
	return h.Serve(w, r, router.Running && router.Root != nil, router.activeEndpointCount())
}

// withHealth wraps a handler so the health path is answered first.
func (router *Router) withHealth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if router.ServeHealth(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}
