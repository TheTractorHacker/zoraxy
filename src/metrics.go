package main

import (
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/cluster"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/metrics"
)

/*
	metrics.go

	Glue between Zoraxy and mod/metrics (Prometheus exposition). Off by default.

	  -metrics              record metrics and serve them on the admin API at /api/metrics (admin auth)
	  -metrics_port :9090   additionally serve GET /metrics on a separate listener (implies -metrics)
	  -metrics_token TOKEN  bearer token required on the separate listener
	                        (or env ZORAXY_METRICS_TOKEN, or {"token":"..."} in <conf>/metrics.json)
*/

var (
	metricsEnable = flag.Bool("metrics", false, "Record Prometheus metrics and serve them on the admin API at /api/metrics (admin authentication required)")
	metricsPort   = flag.String("metrics_port", "", "Serve Prometheus metrics (GET /metrics) on this separate listener, for example :9090 or 127.0.0.1:9090. Empty = off. Implies -metrics")
	metricsToken  = flag.String("metrics_token", "", "Bearer token required by the -metrics_port listener (env ZORAXY_METRICS_TOKEN or <conf>/metrics.json also work, prefer those as flags are visible in the process list)")

	// metricsRegistry is always non-nil; recording stays off until enabled
	metricsRegistry = metrics.New()
)

// metricsTokenValue resolves the listener bearer token: flag, env, conf file
func metricsTokenValue() string {
	if *metricsToken != "" {
		return *metricsToken
	}
	if v := strings.TrimSpace(os.Getenv("ZORAXY_METRICS_TOKEN")); v != "" {
		return v
	}
	if b, err := os.ReadFile(filepath.Join(CONF_FOLDER, "metrics.json")); err == nil {
		var c struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(b, &c) == nil {
			return strings.TrimSpace(c.Token)
		}
	}
	return ""
}

// startMetrics enables the registry and the optional listener. Must run after
// the proxy router and the managers exist (collectors read them lazily).
func startMetrics() {
	if !*metricsEnable && *metricsPort == "" {
		return
	}
	metricsRegistry.SetEnabled(true)
	metricsRegistry.AddCollector(collectZoraxyMetrics)
	if *metricsPort == "" {
		SystemWideLogger.Println("Metrics enabled on the admin API at /api/metrics")
		return
	}
	token := metricsTokenValue()
	ln, err := net.Listen("tcp", *metricsPort)
	if err != nil {
		SystemWideLogger.PrintAndLog("metrics", "Unable to start metrics listener on "+*metricsPort, err)
		return
	}
	if token == "" && !isLoopbackListener(ln) {
		SystemWideLogger.Println("WARNING: metrics listener " + *metricsPort + " is not bound to loopback and has no bearer token (-metrics_token); anyone who can reach it can read the metrics")
	}
	SystemWideLogger.Println("Metrics listening on " + ln.Addr().String() + "/metrics")
	srv := metricsRegistry.NewServer(*metricsPort, token)
	go srv.Serve(ln)
}

func isLoopbackListener(ln net.Listener) bool {
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		return a.IP.IsLoopback()
	}
	return false
}

// RegisterMetricsAPIs serves the exposition on the admin interface (admin auth).
func RegisterMetricsAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		metricsRegistry.Handler().ServeHTTP(w, r)
	})
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// collectZoraxyMetrics adds the scrape time metrics: build info, upstream
// state, WAF counters, certificate expiry and the cluster state.
func collectZoraxyMetrics(e *metrics.Emitter) {
	e.Gauge("zoraxy_build_info", "Build information; value is always 1.", 1,
		"version", SYSTEM_VERSION, "goversion", runtime.Version())

	// Upstreams (from the load balancer state)
	if dynamicProxyRouter != nil {
		now := time.Now()
		emit := func(endpoint string, ep *dynamicproxy.ProxyEndpoint) {
			for _, u := range ep.ActiveOrigins {
				st := u.GetState(now, ep.LoadBalanceConfig)
				up := st.State == "healthy" || st.State == "slow_start"
				e.Gauge("zoraxy_upstream_up", "1 if the upstream is receiving traffic (healthy or slow start), 0 if unhealthy, ejected or draining.", boolGauge(up),
					"endpoint", endpoint, "upstream", u.OriginIpOrDomain)
				e.Gauge("zoraxy_upstream_in_flight", "Requests currently being served by the upstream.", float64(st.InFlight),
					"endpoint", endpoint, "upstream", u.OriginIpOrDomain)
				e.Gauge("zoraxy_upstream_ewma_seconds", "Smoothed time to first byte of the upstream (0 = no sample).", st.EWMAMillis/1000,
					"endpoint", endpoint, "upstream", u.OriginIpOrDomain)
				e.Counter("zoraxy_upstream_ejections_total", "Passive health check ejections of the upstream.", float64(st.Ejections),
					"endpoint", endpoint, "upstream", u.OriginIpOrDomain)
			}
		}
		dynamicProxyRouter.ProxyEndpoints.Range(func(k, v any) bool {
			if ep, ok := v.(*dynamicproxy.ProxyEndpoint); ok && !ep.Disabled {
				emit(ep.RootOrMatchingDomain, ep)
			}
			return true
		})
		if dynamicProxyRouter.Root != nil {
			emit(dynamicproxy.DefaultSiteMetricsLabel, dynamicProxyRouter.Root)
		}
	}

	// WAF counters (cumulative since start)
	ws := waf.Default.Stats()
	e.Counter("zoraxy_waf_events_all_total", "WAF events (rule matches that produced a decision).", float64(ws.Total))
	e.Counter("zoraxy_waf_blocked_total", "WAF events that blocked the request.", float64(ws.Blocked))
	e.Counter("zoraxy_waf_challenged_total", "WAF requests answered with a CAPTCHA challenge (graduated response).", float64(ws.Challenged))
	e.Counter("zoraxy_waf_challenge_passed_total", "WAF requests in the challenge band let through by a solved challenge.", float64(ws.Passed))
	e.Counter("zoraxy_waf_api_events_total", "API protection events (limit, allow-list and OpenAPI violations), also counted in the WAF totals.", float64(ws.API))
	e.Counter("zoraxy_waf_api_blocked_total", "API protection events that blocked the request.", float64(ws.APIBlocked))
	eps := make([]string, 0, len(ws.PerEndpoint))
	for k := range ws.PerEndpoint {
		eps = append(eps, k)
	}
	sort.Strings(eps)
	for _, k := range eps {
		e.Counter("zoraxy_waf_events_total", "WAF events by endpoint.", float64(ws.PerEndpoint[k]), "endpoint", k)
	}
	// Rule ids are a bounded set but keep only the busiest ones
	type kv struct {
		k string
		v uint64
	}
	rules := make([]kv, 0, len(ws.PerRule))
	for k, v := range ws.PerRule {
		rules = append(rules, kv{k, v})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].v != rules[j].v {
			return rules[i].v > rules[j].v
		}
		return rules[i].k < rules[j].k
	})
	if len(rules) > 200 {
		rules = rules[:200]
	}
	for _, r := range rules {
		e.Counter("zoraxy_waf_rule_hits_total", "WAF rule matches by rule id (top 200 rules).", float64(r.v), "rule", r.k)
	}

	// Central WAF: policy switch and endpoint coverage by effective mode (3 label values, bounded)
	if dynamicProxyRouter != nil {
		enabled := 0.0
		if dynamicProxyRouter.WAFState().Policy.Enabled {
			enabled = 1
		}
		e.Gauge("zoraxy_waf_policy_enabled", "1 if the global WAF policy is enabled.", enabled)
		byMode := map[string]float64{waf.ModeOff: 0, waf.ModeDetectionOnly: 0, waf.ModeBlock: 0}
		for _, c := range dynamicProxyRouter.WAFCoverage() {
			byMode[c.Mode]++
		}
		for _, m := range []string{waf.ModeOff, waf.ModeDetectionOnly, waf.ModeBlock} {
			e.Gauge("zoraxy_waf_endpoints", "Proxy endpoints by effective WAF mode.", byMode[m], "mode", m)
		}
	}

	// TLS certificate expiry (one leaf per certificate file)
	if tlsCertManager != nil {
		for _, c := range tlsCertManager.LoadedCerts {
			if c == nil || c.Cert == nil || c.Cert.IsCA {
				continue
			}
			name := strings.TrimSuffix(filepath.Base(c.PubKey), ".pem")
			e.Gauge("zoraxy_tls_certificate_expiry_days", "Days until the certificate expires (negative = expired).", time.Until(c.Cert.NotAfter).Hours()/24,
				"certificate", name, "cn", c.Cert.Subject.CommonName)
			e.Gauge("zoraxy_tls_certificate_not_after_timestamp_seconds", "Expiry time of the certificate as unix timestamp.", float64(c.Cert.NotAfter.Unix()),
				"certificate", name, "cn", c.Cert.Subject.CommonName)
		}
	}

	// Cluster
	if clusterMgr != nil {
		role := clusterMgr.Role()
		for _, r := range []string{cluster.RoleStandalone, cluster.RolePrimary, cluster.RoleFollower} {
			e.Gauge("zoraxy_cluster_role", "Cluster role of this node (1 for the active role).", boolGauge(r == role), "role", r)
		}
		switch role {
		case cluster.RoleFollower:
			e.Gauge("zoraxy_cluster_snapshot_version", "Config snapshot version applied (follower) or published (primary).", float64(clusterMgr.Status().AppliedVersion))
		case cluster.RolePrimary:
			if v, err := clusterMgr.CurrentSnapshotVersion(); err == nil {
				e.Gauge("zoraxy_cluster_snapshot_version", "Config snapshot version applied (follower) or published (primary).", float64(v))
			}
		}
	}
}
