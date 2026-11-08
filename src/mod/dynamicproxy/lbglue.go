package dynamicproxy

import (
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

/*
	Glue between the router and the load balancer

	Builds the per request selection options, and keeps the active health
	check goroutines of the load balancer in sync with the endpoints of this
	router (start with the router, stop with the router, follow endpoint
	changes and removals).
*/

// newSelectOptions builds the load balancer inputs for a request to the given endpoint
func (router *Router) newSelectOptions(r *http.Request, ep *ProxyEndpoint) *loadbalance.SelectOptions {
	return &loadbalance.SelectOptions{
		Config:              ep.LoadBalanceConfig,
		UseStickySession:    ep.UseStickySession,
		DisableAutoFallback: ep.DisableAutoFallback,
		ClientIP: func() string {
			return router.GetClientIPForEndpoint(r, ep)
		},
		ClientCountry: func() string {
			if router.Option.GeodbStore == nil {
				return ""
			}
			info, err := router.Option.GeodbStore.ResolveCountryCodeFromIP(router.GetClientIPForEndpoint(r, ep))
			if err != nil || info == nil {
				return ""
			}
			return info.CountryIsoCode
		},
	}
}

func healthCheckKey(ep *ProxyEndpoint) string {
	return strings.ToLower(ep.RootOrMatchingDomain)
}

// syncHealthChecks starts, updates or stops the active health checks of one endpoint.
// Checks only run while the router is running and the endpoint is enabled
func (router *Router) syncHealthChecks(ep *ProxyEndpoint) {
	if router == nil || router.loadBalancer == nil || ep == nil {
		return
	}
	if !router.Running || ep.Disabled {
		router.loadBalancer.StopHealthChecks(healthCheckKey(ep))
		return
	}
	router.loadBalancer.SyncHealthChecks(healthCheckKey(ep), ep.LoadBalanceConfig, ep.ActiveOrigins)
}

// syncAllHealthChecks syncs every endpoint, called after the router started
func (router *Router) syncAllHealthChecks() {
	router.ProxyEndpoints.Range(func(_, value interface{}) bool {
		router.syncHealthChecks(value.(*ProxyEndpoint))
		return true
	})
	if router.Root != nil {
		router.syncHealthChecks(router.Root)
	}
}

// stopAllHealthChecks stops every health check goroutine of the load balancer
func (router *Router) stopAllHealthChecks() {
	if router.loadBalancer != nil {
		router.loadBalancer.StopAllHealthChecks()
	}
}
