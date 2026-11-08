package dynamicproxy

import (
	"crypto/tls"
)

/*
	secondarytls.go

	TLS on secondary listening ports (upstream #1042).

	Secondary ports (ProxyEndpoint.ListeningPorts) used to be plain HTTP only. When an endpoint has
	SecondaryPortsTLS set, the listeners of its secondary ports speak TLS, with the certificates of the
	normal SNI certificate store (tlscert.Manager.GetCert), the global minimum TLS version / cipher
	profile, and the per-endpoint client certificate policy.

	A listener (address) is shared by every endpoint that lists it, and a port can not be both. The rule is:
	the listener is TLS as soon as ONE of the endpoints using it asks for TLS (the others are then also
	reachable over TLS only); this is logged as a warning when the endpoints disagree.
*/

// addrWantsTLS reports whether the secondary listener at addr must use TLS, and whether endpoints disagree
func (router *Router) addrWantsTLS(addr string) (useTLS bool, mixed bool) {
	plain := false
	router.ProxyEndpoints.Range(func(key, value interface{}) bool {
		ep, ok := value.(*ProxyEndpoint)
		if !ok || ep.Disabled || !router.isDomainListeningOnPort(ep, addr) {
			return true
		}
		if ep.SecondaryPortsTLS {
			useTLS = true
		} else {
			plain = true
		}
		return true
	})
	return useTLS, useTLS && plain
}

// secondaryTLSConfig builds the TLS config of secondary TLS listeners
func (router *Router) secondaryTLSConfig() *tls.Config {
	minVersion := uint16(tls.VersionTLS12)
	if router.Option.MinTLSVersion != 0 {
		minVersion = uint16(router.Option.MinTLSVersion)
	}
	cfg := &tls.Config{
		GetCertificate: router.Option.TlsManager.GetCert,
		MinVersion:     minVersion,
	}
	ApplyTlsCipherProfile(cfg, router.Option.TlsCipherProfile)
	cfg.GetConfigForClient = router.clientCertGetConfig(cfg)
	return cfg
}

// SecondaryListenerModes returns "tls" or "http" per active secondary listener address (for the UI / tests)
func (router *Router) SecondaryListenerModes() map[string]string {
	router.secondaryServerMutex.RLock()
	defer router.secondaryServerMutex.RUnlock()
	out := map[string]string{}
	for addr := range router.secondaryServers {
		if router.secondaryTLS[addr] {
			out[addr] = "tls"
		} else {
			out[addr] = "http"
		}
	}
	return out
}
