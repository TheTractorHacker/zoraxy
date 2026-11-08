package dynamicproxy

import (
	"crypto/tls"
	"net/http"
)

/*
	ech_glue.go

	Encrypted Client Hello wiring. Key management lives in mod/ech; the router only gets a callback
	(RouterOption.EchKeys) that crypto/tls calls per handshake, so enabling / rotating keys needs no restart.

	The callback is installed on the listener config before the per-SNI clones (client certificates) are made;
	tls.Config.Clone copies GetEncryptedClientHelloKeys, and ECH is decrypted before GetConfigForClient runs
	anyway, so mTLS endpoints see the inner SNI. HTTP/3 clones the same config.
*/

func (router *Router) applyEch(cfg *tls.Config) {
	if router.Option.EchKeys != nil {
		cfg.GetEncryptedClientHelloKeys = router.Option.EchKeys
	}
}

func (router *Router) echObserve(r *http.Request) {
	if router.Option.EchObserve != nil && r.TLS != nil {
		router.Option.EchObserve(r.TLS.ECHAccepted)
	}
}
