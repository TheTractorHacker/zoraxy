package dynamicproxy

import (
	"crypto/tls"
	"testing"
)

// The per-SNI mTLS clones must keep the ECH key callback, and the secondary TLS listener config must carry it too.
func TestEchKeysSurviveClientCertClones(t *testing.T) {
	called := 0
	r := &Router{Option: &RouterOption{EchKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		called++
		return []tls.EncryptedClientHelloKey{}, nil
	}}}
	base := &tls.Config{}
	r.applyEch(base)
	if base.GetEncryptedClientHelloKeys == nil {
		t.Fatal("applyEch did not install the callback")
	}
	rt := &clientCertRuntime{}
	cl := rt.tlsConfigFor(base, &tls.ClientHelloInfo{SupportedProtos: []string{"h2"}})
	if cl.GetEncryptedClientHelloKeys == nil {
		t.Fatal("per-SNI clone lost the ECH callback")
	}
	_, _ = cl.GetEncryptedClientHelloKeys(nil)
	if called != 1 {
		t.Fatal("clone does not call the shared callback")
	}
	//Disabled by default: no callback unless the option is provided
	none := &Router{Option: &RouterOption{}}
	cfg := &tls.Config{}
	none.applyEch(cfg)
	if cfg.GetEncryptedClientHelloKeys != nil {
		t.Fatal("ECH callback installed without the option")
	}
}
