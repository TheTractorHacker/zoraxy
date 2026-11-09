package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"imuslab.com/zoraxy/mod/webuitls"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/cluster"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	cluster.go

	Glue between Zoraxy and mod/cluster (high availability, issue #81).
	All of it is inert unless a cluster secret / role is configured.
*/

var (
	fleetTLSCert          *webuitls.CertInfo //set when -webui_tls is on
	clusterSecretFlag     = flag.String("cluster_secret", "", "Shared cluster secret (min 32 chars). Replaces the node UUID as key input for user facing session cookies (CAPTCHA, load balancer stickiness) so any node accepts them. Overrides conf/cluster.json. Visible in the process list, prefer the Cluster page or conf/cluster.json")
	clusterGenSecret      = flag.Bool("cluster_gen_secret", false, "Print a new random cluster secret and exit")
	clusterAllowLocalEdit = flag.Bool("cluster_allow_local_edits", false, "On a cluster follower, allow editing synced objects locally (they are overwritten by the next primary change)")
	fleetPort             = flag.String("fleet_port", "", "Optional separate listener that serves only the Fleet node endpoints (join, config, heartbeat), for example :8010 (HTTPS with the admin certificate when -webui_tls is on, plain HTTP otherwise). Lets nodes outside your network reach the hub without exposing the admin UI: put a reverse proxy rule with a real certificate in front of it and use that https URL as the hub URL")
	healthPort            = flag.String("health_port", "", "Optional separate listener for the health endpoint, for example :8081 (serves "+cluster.HealthPath+")")

	clusterMgr *cluster.Manager
)

var nodeIDInvalid = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// initCluster loads the cluster configuration. It must run after nodeUUID is
// known and before startupSequence(), which builds the session stores.
func initCluster() {
	id := nodeIDInvalid.ReplaceAllString(strings.TrimSpace(nodeUUID), "_")
	if len(id) > 64 {
		id = id[:64]
	}
	name, _ := os.Hostname()
	mgr, err := cluster.NewManager(cluster.Options{
		ConfDir:         CONF_FOLDER,
		NodeID:          id,
		NodeName:        name,
		Version:         SYSTEM_VERSION,
		FlagSecret:      *clusterSecretFlag,
		AllowLocalEdits: *clusterAllowLocalEdit,
		Reload:          clusterReload,
		Validate:        validateClusterPayload,
		Actor:           fleetActor,
		Stats:           fleetNodeStats,
		HubFingerprint:  func() string { return webUIFingerprint },
		Logf: func(format string, a ...any) {
			if SystemWideLogger != nil {
				SystemWideLogger.Println(fmt.Sprintf(format, a...))
			}
		},
	})
	if err != nil {
		fmt.Println("Invalid cluster configuration:", err)
		os.Exit(1)
	}
	clusterMgr = mgr
}

// validateClusterPayload checks a snapshot against the real config schemas so
// a file that is valid JSON but would stop Zoraxy from starting is rejected
// before anything is written.
func validateClusterPayload(p *cluster.Payload) error {
	for _, f := range p.Files {
		switch {
		case f.Path == "trusted_proxies.json":
			var tp []access.TrustedProxy
			if err := json.Unmarshal(f.Data, &tp); err != nil {
				return fmt.Errorf("%s: %w", f.Path, err)
			}
		case f.Path == "waf_central.json":
			var wc wafCentralFile
			if err := json.Unmarshal(f.Data, &wc); err != nil {
				return fmt.Errorf("%s: %w", f.Path, err)
			}
			if _, err := waf.NewState(wc.Policy, wc.Profiles); err != nil {
				return fmt.Errorf("%s: %w", f.Path, err)
			}
		case strings.HasPrefix(f.Path, "proxy/") && strings.HasSuffix(f.Path, ".config"):
			ep := dynamicproxy.GetDefaultProxyEndpoint()
			if err := json.Unmarshal(f.Data, &ep); err != nil {
				return fmt.Errorf("%s: %w", f.Path, err)
			}
		}
	}
	return nil
}

// startCluster starts the follower sync loop and the optional health listener.
func startCluster() {
	clusterMgr.Start()
	//Confirm a pending snapshot apply once this start proved stable
	time.AfterFunc(cluster.HealthyAfter, clusterMgr.MarkHealthy)
	if *fleetPort != "" {
		go func() {
			ln, err := net.Listen("tcp", *fleetPort)
			if err != nil {
				SystemWideLogger.PrintAndLog("cluster", "Unable to start the Fleet node listener on "+*fleetPort, err)
				return
			}
			var l net.Listener = ln
			if fleetTLSCert != nil {
				//-webui_tls is on: serve the Fleet port over https with the same certificate (and fingerprint) as the admin UI
				l = webuitls.NewSniffListener(ln, webuitls.ServerTLSConfig(fleetTLSCert))
				SystemWideLogger.Println("Fleet node endpoints (join, config, heartbeat only) listening on " + *fleetPort + " over HTTPS, certificate fingerprint " + fleetTLSCert.Fingerprint)
			} else {
				SystemWideLogger.Println("Fleet node endpoints (join, config, heartbeat only) listening on " + *fleetPort + " over plain HTTP; start with -webui_tls auto or custom to serve HTTPS")
			}
			srv := &http.Server{Handler: clusterMgr.FleetHandler(), ReadHeaderTimeout: 5 * time.Second}
			srv.Serve(l)
		}()
	}
	if *healthPort != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc(cluster.HealthPath, func(w http.ResponseWriter, r *http.Request) {
				if dynamicProxyRouter == nil || !dynamicProxyRouter.ServeHealth(w, r) {
					if !clusterMgr.Health().Serve(w, r, false, 0) {
						http.NotFound(w, r)
					}
				}
			})
			ln, err := net.Listen("tcp", *healthPort)
			if err != nil {
				SystemWideLogger.PrintAndLog("cluster", "Unable to start health listener on "+*healthPort, err)
				return
			}
			SystemWideLogger.Println("Health endpoint listening on " + *healthPort + cluster.HealthPath)
			srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			srv.Serve(ln)
		}()
	}
}

// clusterReload makes the process pick up synced configuration. Zoraxy has no
// in-place reload of every module, so it restarts itself (same binary, same
// arguments). The delay lets the sync request finish and report first.
func clusterReload() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	go func() {
		SystemWideLogger.Println("Cluster sync applied new configuration. Restarting in 3 seconds...")
		time.Sleep(3 * time.Second)
		ShutdownSeq()
		restartSelf(exe)
	}()
	return nil
}

// RegisterClusterAPIs registers the admin UI APIs (admin authenticated).
func RegisterClusterAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/cluster/status", clusterMgr.HandleStatus)
	authRouter.HandleFunc("/api/cluster/config", clusterMgr.HandleConfig)
	authRouter.HandleFunc("/api/cluster/generateSecret", clusterMgr.HandleGenerateSecret)
	authRouter.HandleFunc("/api/cluster/syncNow", clusterMgr.HandleSyncNow)
	authRouter.HandleFunc("/api/cluster/nodes", clusterMgr.HandleNodes)
	// Fleet (central management): hub admin API and node side join/leave/info
	authRouter.HandleFunc(cluster.FleetAPIPrefix, clusterMgr.HandleFleetHub)
	authRouter.HandleFunc("/api/fleet/node/info", clusterMgr.HandleFleetNodeInfo)
	authRouter.HandleFunc("/api/fleet/node/probe", clusterMgr.HandleFleetProbe)
	authRouter.HandleFunc("/api/fleet/node/join", clusterMgr.HandleFleetJoin)
	authRouter.HandleFunc("/api/fleet/node/leave", clusterMgr.HandleFleetLeave)
	authRouter.HandleFunc("/api/fleet/node/syncNow", clusterMgr.HandleFleetNodeSync)
}
