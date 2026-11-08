package dynamicproxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/ech"
	"imuslab.com/zoraxy/mod/tlscert"
)

// End to end: a real TLS listener of the router with ECH keys installed, an endpoint that requires a client certificate
// (per-SNI GetConfigForClient clone), and a client that hides the inner SNI behind the public name.
func TestEchWithClientCertEndpointEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	router, sep, _ := newNonTLSTestRouter(t)
	certDir := t.TempDir()
	mgr, err := tlscert.NewManager(certDir, router.Option.Logger)
	if err != nil {
		t.Fatal(err)
	}
	router.Option.TlsManager = mgr

	ca := newTestCA(t, "server root", nil)
	writeCertPair(t, certDir, "app.example.com", ca.issue(t, issueOpt{cn: "app.example.com", dns: []string{"app.example.com"}, server: true}))
	writeCertPair(t, certDir, "ech.example.com", ca.issue(t, issueOpt{cn: "ech.example.com", dns: []string{"ech.example.com"}, server: true}))
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	clientCA := newTestCA(t, "client root", nil)
	clientCert := clientCA.issue(t, issueOpt{cn: "alice"})

	em, err := ech.Open(filepath.Join(t.TempDir(), "ech"))
	if err != nil {
		t.Fatal(err)
	}
	if err := em.SetSettings(ech.Settings{Enabled: true, PublicName: "ech.example.com"}); err != nil {
		t.Fatal(err)
	}
	router.Option.EchKeys = func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { return em.TLSKeys(), nil }
	accepted := 0
	router.Option.EchObserve = func(a bool) {
		if a {
			accepted++
		}
	}

	port := freeTCPPort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	sep.RootOrMatchingDomain = "app.example.com"
	sep.ListeningPorts = []string{addr}
	sep.SecondaryPortsTLS = true
	sep.ClientCert = &ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: clientCA.pem}
	sep.initNetworkOptions()
	router.ProxyEndpoints.Store("app.example.com", sep)
	router.Running = true
	router.Root = &ProxyEndpoint{}
	router.secondaryServers = map[string]*http.Server{}
	router.secondaryStopChans = map[string]chan bool{}
	t.Cleanup(func() {
		router.secondaryServerMutex.Lock()
		for _, s := range router.secondaryServers {
			s.Close()
		}
		router.secondaryServerMutex.Unlock()
	})
	router.startSecondaryListeners()

	list, _ := base64.StdEncoding.DecodeString(em.ConfigListBase64())
	get := func(withCert bool) (int, bool, error) {
		cfg := &tls.Config{ServerName: "app.example.com", RootCAs: roots, MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list}
		if withCert {
			c := clientCert
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }
		}
		var state tls.ConnectionState
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: cfg, DisableKeepAlives: true,
			DialTLSContext: nil,
			Dial:           func(network, _ string) (net.Conn, error) { return net.Dial(network, addr) },
		}}
		req, _ := http.NewRequest("GET", "https://app.example.com/", nil)
		resp, err := client.Do(req)
		if err != nil {
			return 0, false, err
		}
		defer resp.Body.Close()
		if resp.TLS != nil {
			state = *resp.TLS
		}
		return resp.StatusCode, state.ECHAccepted, nil
	}
	var code int
	var ok bool
	for i := 0; i < 100; i++ {
		code, ok, err = get(true)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || code != 299 || !ok {
		t.Fatalf("ECH + mTLS request: code=%d echAccepted=%v err=%v", code, ok, err)
	}
	if accepted == 0 {
		t.Fatal("ECH outcome not observed by the router")
	}
	//The per-SNI policy of the *inner* name applies: no client certificate, no access
	if _, _, err := get(false); err == nil {
		t.Fatal("mTLS endpoint accepted a client without certificate over ECH")
	}
	//Disabling ECH at runtime (no restart): clients fall back to the outer name and fail certificate checks
	s := em.Settings()
	s.Enabled = false
	if err := em.SetSettings(s); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := get(true); err == nil && ok {
		t.Fatal("ECH still accepted after it was disabled")
	}
}
