package dynamicproxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

/*
	peerset.go

	"Direct peer must be in this IP set" (upstream #761).

	ProxyEndpoint.AllowedPeerCIDRs restricts an endpoint to connections whose TCP peer address
	(the socket address, r.RemoteAddr) is inside the list, for example "only my CDN / upstream load
	balancer may talk to this endpoint". Forwarded headers (X-Forwarded-For, CF-Connecting-IP...) are
	never consulted, so they can not be used to get around the rule. Everything else gets a 403 before
	any other check of the chain runs. It is applied on the TLS listener and on the plain HTTP paths
	(port 80 bypass, secondary ports) alike because it lives in runEndpointChain.

	When Zoraxy itself sits behind a PROXY protocol load balancer ("Use PROXY protocol" listener option)
	the peer is the client address announced in the PROXY header, as that is what the listener reports.
	An empty list disables the rule.
*/

func parsePeerSet(entries []string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		p, err := parseScopePrefix(e)
		if err != nil {
			return nil, err
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("%q matches every address, remove the rule instead", strings.TrimSpace(e))
		}
		out = append(out, p)
	}
	if len(out) > 5000 {
		return nil, errors.New("too many entries")
	}
	return out, nil
}

// ValidatePeerSet checks the list before it is stored
func ValidatePeerSet(entries []string) error {
	_, err := parsePeerSet(entries)
	return err
}

func (pe *ProxyEndpoint) initPeerSet() {
	pe.peerSet = nil
	pe.peerSetErr = nil
	if len(compactStrings(pe.AllowedPeerCIDRs)) == 0 {
		return
	}
	set, err := parsePeerSet(pe.AllowedPeerCIDRs)
	if err != nil {
		pe.peerSetErr = err
		return
	}
	pe.peerSet = set
}

func peerAddr(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err == nil {
		return ap.Addr().WithZone("").Unmap(), true
	}
	//Unix sockets / test servers may give a bare address
	a, err := netip.ParseAddr(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

// enforcePeerSet returns true when the request was refused
func (h *ProxyHandler) enforcePeerSet(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if sep.peerSetErr != nil {
		h.Parent.Option.Logger.PrintAndLog("proxy-peerset", "Allowed peer list of "+sep.RootOrMatchingDomain+" is invalid, refusing requests", sep.peerSetErr)
		http.Error(w, "503 - Allowed peer list misconfigured", http.StatusServiceUnavailable)
		return true
	}
	if len(sep.peerSet) == 0 {
		return false
	}
	if a, ok := peerAddr(r); ok {
		for _, p := range sep.peerSet {
			if p.Contains(a) {
				return false
			}
		}
	}
	h.Parent.logRequest(r, false, 403, "peer-not-allowed", r.Host, "", sep)
	serveProxyRequestError(w, http.StatusForbidden, h.Parent, ErrorTemplateForbidden)
	return true
}

// initNetworkOptions compiles every networking option of the endpoint
func (pe *ProxyEndpoint) initNetworkOptions() {
	pe.initClientCert()
	pe.initPathRules()
	pe.initPeerSet()
	pe.initHeaderRules()
	pe.initBasicScope()
}
