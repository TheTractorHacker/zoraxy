package main

/*
	dnsresponder_glue.go

	Wires the opt-in split-horizon DNS responder (mod/dnsresponder) into the host:
	config persistence, the hosted-name source (proxy endpoints incl. aliases),
	the admin API and start / stop hooks.

	GET  /api/tools/dnsresponder           -> {"config": {...}, "status": {...}}
	POST /api/tools/dnsresponder  config=<JSON>

	Config is stored in the "settings" table under the key "dnsResponder".
*/

import (
	"net/http"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/dnsresponder"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

var (
	dnsResponderMgr *dnsresponder.Manager
	dnsResponderMu  sync.RWMutex
)

// dnsResponderNames lists the enabled proxy rule hostnames and aliases (wildcards included)
func dnsResponderNames() []string {
	if dynamicProxyRouter == nil || dynamicProxyRouter.ProxyEndpoints == nil {
		return nil
	}
	var names []string
	dynamicProxyRouter.ProxyEndpoints.Range(func(_, v interface{}) bool {
		ep, ok := v.(*dynamicproxy.ProxyEndpoint)
		if !ok || ep.Disabled {
			return true
		}
		names = append(names, strings.ToLower(ep.RootOrMatchingDomain))
		for _, a := range ep.MatchingDomainAlias {
			names = append(names, strings.ToLower(a))
		}
		return true
	})
	return names
}

// startDNSResponder loads the stored config and starts the responder when enabled (default: off)
func startDNSResponder() {
	cfg := dnsresponder.DefaultConfig()
	sysdb.Read("settings", "dnsResponder", &cfg)
	cfg.Normalize()
	mgr := dnsresponder.NewManager(cfg, dnsResponderNames, func(c dnsresponder.Config) error {
		return sysdb.Write("settings", "dnsResponder", c)
	}, func(msg string, err error) {
		if err != nil {
			SystemWideLogger.PrintAndLog("dns-responder", msg, err)
		} else {
			SystemWideLogger.Println(msg)
		}
	})
	dnsResponderMu.Lock()
	dnsResponderMgr = mgr
	dnsResponderMu.Unlock()
	if cfg.Enabled {
		mgr.Start()
	}
}

func stopDNSResponder() {
	dnsResponderMu.RLock()
	mgr := dnsResponderMgr
	dnsResponderMu.RUnlock()
	if mgr != nil {
		mgr.Stop()
	}
}

// HandleDNSResponder is the admin API (auth + CSRF come from the router it is registered on)
func HandleDNSResponder(w http.ResponseWriter, r *http.Request) {
	dnsResponderMu.RLock()
	mgr := dnsResponderMgr
	dnsResponderMu.RUnlock()
	if mgr == nil {
		utils.SendErrorResponse(w, "DNS responder is not ready yet")
		return
	}
	mgr.HandleAPI(w, r)
}
