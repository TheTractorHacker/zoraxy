package dynamicproxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/tlscert"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeCertPair(t *testing.T, dir, name string, c tls.Certificate) {
	t.Helper()
	var chain []byte
	for _, der := range c.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".pem"), chain, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
}

func dialTLSGet(t *testing.T, addr, serverName string, roots *x509.CertPool, clientCert *tls.Certificate) (int, error) {
	t.Helper()
	cfg := &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		c := *clientCert
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: cfg, DisableKeepAlives: true,
		Dial: func(network, _ string) (net.Conn, error) { return net.Dial(network, addr) },
	}}
	resp, err := client.Get("https://" + serverName + "/")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func dialPlainGet(addr string) (int, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Host = "app.example.com"
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// Secondary listening ports can serve TLS with the certificates of the SNI store (upstream #1042)
func TestSecondaryPortTLS(t *testing.T) {
	t.Chdir(t.TempDir()) //tlscert.NewManager writes ./tmp/localhost.*
	router, sep, _ := newNonTLSTestRouter(t)
	certDir := t.TempDir()
	mgr, err := tlscert.NewManager(certDir, router.Option.Logger)
	if err != nil {
		t.Fatal(err)
	}
	router.Option.TlsManager = mgr

	serverCA := newTestCA(t, "server root", nil)
	writeCertPair(t, certDir, "app.example.com", serverCA.issue(t, issueOpt{cn: "app.example.com", dns: []string{"app.example.com"}, server: true}))
	roots := x509.NewCertPool()
	roots.AddCert(serverCA.cert)

	clientCA := newTestCA(t, "client root", nil)
	clientCert := clientCA.issue(t, issueOpt{cn: "alice"})

	port := freeTCPPort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	sep.RootOrMatchingDomain = "app.example.com"
	sep.ListeningPorts = []string{addr}
	sep.SecondaryPortsTLS = true
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

	waitFor := func(fn func() bool) bool {
		for i := 0; i < 100; i++ {
			if fn() {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}

	router.startSecondaryListeners()
	if !waitFor(func() bool {
		c, err := dialTLSGet(t, addr, "app.example.com", roots, nil)
		return err == nil && c == 299
	}) {
		t.Fatal("secondary TLS listener does not answer a TLS request with the store certificate")
	}
	if code, err := dialPlainGet(addr); err == nil && code == 299 {
		t.Fatal("plain HTTP was served on a TLS secondary port")
	}
	if got := router.secondaryTLS[addr]; !got {
		t.Fatal("listener not recorded as TLS")
	}

	//Client certificate policy applies on the secondary TLS port as well (SNI selected)
	sep.ClientCert = &ClientCertConfig{Mode: ClientCertModeRequireAndVerify, CAPEM: clientCA.pem}
	sep.initNetworkOptions()
	if _, err := dialTLSGet(t, addr, "app.example.com", roots, nil); err == nil {
		t.Error("mTLS endpoint on a secondary TLS port accepted a client without certificate")
	}
	if code, err := dialTLSGet(t, addr, "app.example.com", roots, &clientCert); err != nil || code != 299 {
		t.Errorf("mTLS with valid certificate on secondary port: %d %v", code, err)
	}
	sep.ClientCert = nil
	sep.initNetworkOptions()

	//Switching the option off turns the listener back into plain HTTP
	sep.SecondaryPortsTLS = false
	router.UpdateSecondaryListeners()
	if !waitFor(func() bool { c, err := dialPlainGet(addr); return err == nil && c == 299 }) {
		t.Fatal("secondary listener did not become plain HTTP after the TLS option was removed")
	}
	if _, err := dialTLSGet(t, addr, "app.example.com", roots, nil); err == nil {
		t.Error("TLS still served after the option was removed")
	}

	//And back on
	sep.SecondaryPortsTLS = true
	router.UpdateSecondaryListeners()
	if !waitFor(func() bool {
		c, err := dialTLSGet(t, addr, "app.example.com", roots, nil)
		return err == nil && c == 299
	}) {
		t.Fatal("secondary listener did not switch to TLS")
	}
}

// Default behaviour is unchanged: plain HTTP on secondary ports
func TestSecondaryPortPlainByDefault(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	port := freeTCPPort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	sep.RootOrMatchingDomain = "app.example.com"
	sep.ListeningPorts = []string{addr}
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
	ok := false
	for i := 0; i < 100 && !ok; i++ {
		req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
		req.Host = "app.example.com"
		if resp, err := http.DefaultClient.Do(req); err == nil {
			ok = resp.StatusCode == 299
			resp.Body.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatal("plain secondary listener does not serve the endpoint")
	}
	if router.SecondaryListenerModes()[addr] != "http" {
		t.Fatalf("modes = %v", router.SecondaryListenerModes())
	}
}
