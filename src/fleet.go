package main

import (
	"net/http"
	"time"

	"imuslab.com/zoraxy/mod/cluster"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	fleet.go

	Glue for central management (Fleet, see DEVELOPMENT.md): the telemetry a
	node puts into its heartbeat and the audit actor of hub actions. Bounded
	numbers only; nothing per request leaves the node.
*/

// webUIFingerprint is the SHA-256 fingerprint of the admin TLS certificate
// (empty when the admin port is plain http), shown on the Fleet page so a
// joining node can be checked against it.
var webUIFingerprint string

// fleetActor names the logged in admin for the hub audit log.
func fleetActor(r *http.Request) string {
	if authAgent == nil {
		return ""
	}
	u, err := authAgent.GetUserName(nil, r)
	if err != nil {
		return ""
	}
	return u
}

// fleetNodeStats collects the heartbeat telemetry.
func fleetNodeStats() cluster.NodeStats {
	// request counting is off by default; the first heartbeat switches it on
	if !metricsRegistry.Enabled() {
		metricsRegistry.SetEnabled(true)
	}
	st := cluster.NodeStats{Health: "unavailable", UptimeSeconds: int64(metricsRegistry.Uptime().Seconds())}
	st.Requests, st.Errors = metricsRegistry.Totals()
	st.WAFEvents = waf.Default.Stats().Total
	if dynamicProxyRouter != nil {
		mode := waf.ModeOff
		rank := map[string]int{waf.ModeOff: 0, waf.ModeDetectionOnly: 1, waf.ModeBlock: 2}
		visit := func(ep *dynamicproxy.ProxyEndpoint) {
			if ep.WAF != nil && rank[ep.WAF.Mode] > rank[mode] {
				mode = ep.WAF.Mode
			}
		}
		dynamicProxyRouter.ProxyEndpoints.Range(func(_, v any) bool {
			if ep, ok := v.(*dynamicproxy.ProxyEndpoint); ok && !ep.Disabled {
				st.Endpoints++
				visit(ep)
			}
			return true
		})
		if dynamicProxyRouter.Root != nil {
			visit(dynamicProxyRouter.Root)
		}
		st.WAFMode = mode
		if dynamicProxyRouter.Running && dynamicProxyRouter.Root != nil {
			st.Health = "ok"
		}
	}
	if tlsCertManager != nil {
		var soonest time.Time
		for _, c := range tlsCertManager.LoadedCerts {
			if c == nil || c.Cert == nil || c.Cert.IsCA {
				continue
			}
			if soonest.IsZero() || c.Cert.NotAfter.Before(soonest) {
				soonest = c.Cert.NotAfter
			}
		}
		if !soonest.IsZero() {
			st.CertExpiry = soonest.Unix()
		}
	}
	return st
}
