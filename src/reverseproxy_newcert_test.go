package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/tlscert"
)

// A new proxy rule can name the stored certificate to serve ("certificate" form field of /api/proxy/add).
// The choice is stored with creation, is the certificate a TLS handshake really gets, and an unknown name
// creates nothing.
func setupNewCertTest(t *testing.T) *tlscert.Manager {
	t.Helper()
	oldConf, oldLB, oldRouter, oldLogger, oldAC, oldTM := CONF_HTTP_PROXY, loadBalancer, dynamicProxyRouter, SystemWideLogger, accessController, tlsCertManager
	t.Cleanup(func() {
		CONF_HTTP_PROXY, loadBalancer, dynamicProxyRouter, SystemWideLogger, accessController, tlsCertManager = oldConf, oldLB, oldRouter, oldLogger, oldAC, oldTM
	})
	setupBlocklistImportTest(t) //access controller with the default rule
	SystemWideLogger, _ = logger.NewFmtLogger()
	CONF_HTTP_PROXY = t.TempDir()
	loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{SystemUUID: "newcert-test", Logger: SystemWideLogger})
	router, err := dynamicproxy.NewDynamicProxy(dynamicproxy.RouterOption{LoadBalancer: loadBalancer})
	if err != nil {
		t.Fatal(err)
	}
	dynamicProxyRouter = router

	dir := t.TempDir()
	m, err := tlscert.NewManagerWithTmp(filepath.Join(dir, "certs"), filepath.Join(dir, "tmp"), SystemWideLogger)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"cert-a", "cert-b"} {
		//both cover the test hosts, so only the choice tells them apart
		if err := m.GenerateSelfSignedCertificate(n+".example", []string{"test.local", "alias.local", "*.wild.local"}, n+".pem", n+".key"); err != nil {
			t.Fatal(err)
		}
	}
	m.UpdateLoadedCertList()
	m.SetHostSpecificTlsBehavior(func(host string) (*tlscert.HostSpecificTlsBehavior, error) {
		return router.ResolveHostSpecificTlsBehaviorForHostname(host)
	})
	tlsCertManager = m
	return m
}

func addRuleForm(host, certificate string) url.Values {
	f := url.Values{"type": {"host"}, "ep": {"127.0.0.1:9"}, "rootname": {host}, "tls": {"false"}, "tlsval": {"false"},
		"bypassGlobalTLS": {"false"}, "cred": {""}, "enableUtm": {"false"}}
	if certificate != "" {
		f.Set("certificate", certificate)
	}
	return f
}

func postAddRule(f url.Values) string {
	r := authProviderForm(f)
	w := httptest.NewRecorder()
	ReverseProxyHandleAddEndpoint(w, r)
	return strings.TrimSpace(w.Body.String())
}

func servedCertFile(t *testing.T, m *tlscert.Manager, host string) string {
	t.Helper()
	pub, _, err := m.GetCertificateByHostname(host)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Base(pub)
}

func readSavedTls(t *testing.T, host string) *tlscert.HostSpecificTlsBehavior {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(CONF_HTTP_PROXY, host+".config"))
	if err != nil {
		t.Fatalf("rule %s was not saved: %v", host, err)
	}
	var ep dynamicproxy.ProxyEndpoint
	if err := json.Unmarshal(b, &ep); err != nil {
		t.Fatal(err)
	}
	return ep.TlsOptions
}

func TestAddRuleWithCertificateStoresAndServesIt(t *testing.T) {
	m := setupNewCertTest(t)
	if got := postAddRule(addRuleForm("test.local", "cert-b")); got != `"OK"` {
		t.Fatalf("create with a valid certificate failed: %s", got)
	}
	to := readSavedTls(t, "test.local")
	if to == nil || to.PreferredCertificate["test.local"] != "cert-b" || !to.DisableSNI {
		t.Fatalf("the choice must be saved with the rule (preference + SNI off), got %+v", to)
	}
	if got := servedCertFile(t, m, "test.local"); got != "cert-b.pem" {
		t.Errorf("the chosen certificate must be the one served, got %s", got)
	}
	//the runtime rule (what the TLS handshake consults) has it too
	ept := dynamicProxyRouter.GetProxyEndpointFromHostname("test.local")
	if ept == nil || ept.TlsOptions.PreferredCertificate["test.local"] != "cert-b" {
		t.Errorf("the live rule does not carry the choice: %+v", ept)
	}
}

func TestAddRuleWithCertificateCoversAliasesAndWildcards(t *testing.T) {
	m := setupNewCertTest(t)
	if got := postAddRule(addRuleForm("test.local, alias.local", "cert-b")); got != `"OK"` {
		t.Fatalf("create failed: %s", got)
	}
	for _, h := range []string{"test.local", "alias.local"} {
		if got := servedCertFile(t, m, h); got != "cert-b.pem" {
			t.Errorf("%s: want cert-b.pem served, got %s", h, got)
		}
	}
	if got := postAddRule(addRuleForm("*.wild.local", "cert-a")); got != `"OK"` {
		t.Fatalf("wildcard create failed: %s", got)
	}
	if got := servedCertFile(t, m, "x.wild.local"); got != "cert-a.pem" {
		t.Errorf("a wildcard rule must serve the chosen certificate for its names, got %s", got)
	}
}

func TestAddRuleWithUnknownCertificateCreatesNothing(t *testing.T) {
	setupNewCertTest(t)
	for _, bad := range []string{"nope", "../cert-a", "cert-a/../cert-a"} {
		got := postAddRule(addRuleForm("test.local", bad))
		if !strings.Contains(got, "error") {
			t.Errorf("%q must be refused, got %s", bad, got)
		}
		if _, err := os.Stat(filepath.Join(CONF_HTTP_PROXY, "test.local.config")); err == nil {
			t.Fatalf("%q: a config file was created", bad)
		}
		if dynamicProxyRouter.GetProxyEndpointFromHostname("test.local") != nil {
			t.Fatalf("%q: a live rule was created", bad)
		}
	}
}

// A certificate only means something for a host rule. Any other type must say so instead of ignoring the field.
func TestAddRuleCertificateOnNonHostRuleIsRefused(t *testing.T) {
	setupNewCertTest(t)
	f := addRuleForm("test.local", "cert-a")
	f.Set("type", "root")
	if got := postAddRule(f); !strings.Contains(got, "error") {
		t.Errorf("a certificate on a root rule must be refused, got %s", got)
	}
}

// Without a choice the rule is exactly what it was before this field existed.
func TestAddRuleWithoutCertificateIsUnchanged(t *testing.T) {
	m := setupNewCertTest(t)
	const want = `{"DisableSNI":false,"DisableLegacyCertificateMatching":false,"EnableAutoHTTPS":false,"PreferredCertificate":{}}`
	for _, c := range []struct{ host, cert string }{{"plain.local", ""}, {"blank.local", "   "}} {
		f := addRuleForm(c.host, "")
		if c.cert != "" {
			f.Set("certificate", c.cert)
		}
		if got := postAddRule(f); got != `"OK"` {
			t.Fatalf("%s: %s", c.host, got)
		}
		js, _ := json.Marshal(readSavedTls(t, c.host))
		if string(js) != want {
			t.Errorf("%s: TlsOptions changed: %s", c.host, js)
		}
	}
	//and the automatic choice still serves by hostname match, not by a preference
	if got := servedCertFile(t, m, "plain.local"); got == "" {
		t.Error("no certificate resolved")
	}
}
