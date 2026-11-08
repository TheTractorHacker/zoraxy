package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy"
)

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func postNet(t *testing.T, h http.HandlerFunc, values url.Values) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return strings.TrimSpace(w.Body.String())
}

func TestNetworkingAPIs(t *testing.T) {
	router := setupEditTest(t)
	ca := testCAPEM(t)
	live := func() *dynamicproxy.ProxyEndpoint {
		ep, err := router.LoadProxy("app.example.com")
		if err != nil {
			t.Fatal(err)
		}
		return ep
	}
	savedConfig := func() string {
		b, err := os.ReadFile(filepath.Join(CONF_HTTP_PROXY, "app.example.com.config"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	//Off by default
	if live().ClientCert != nil || len(live().PathRules) != 0 || len(live().AllowedPeerCIDRs) != 0 || live().SecondaryPortsTLS {
		t.Fatal("networking options are not off by default")
	}

	//Client certificate
	cfg, _ := json.Marshal(dynamicproxy.ClientCertConfig{Mode: dynamicproxy.ClientCertModeRequireAndVerify, CAPEM: ca, AllowList: []string{"cn:alice"}})
	if out := postNet(t, HandleNetworkingClientCert, url.Values{"ep": {"app.example.com"}, "config": {string(cfg)}}); !strings.Contains(out, "OK") {
		t.Fatalf("set client cert: %s", out)
	}
	if cc := live().ClientCert; cc == nil || cc.Mode != dynamicproxy.ClientCertModeRequireAndVerify || len(cc.AllowList) != 1 {
		t.Fatalf("client cert not applied: %+v", cc)
	}
	if !strings.Contains(savedConfig(), "ClientCert") {
		t.Error("client cert not persisted")
	}
	bad, _ := json.Marshal(dynamicproxy.ClientCertConfig{Mode: dynamicproxy.ClientCertModeRequireAndVerify, CAPEM: "nope"})
	if out := postNet(t, HandleNetworkingClientCert, url.Values{"ep": {"app.example.com"}, "config": {string(bad)}}); !strings.Contains(out, "error") {
		t.Fatalf("invalid CA accepted: %s", out)
	}
	if live().ClientCert.CAPEM != ca {
		t.Fatal("failed update changed the stored config")
	}

	//Path rules
	rules, _ := json.Marshal([]dynamicproxy.PathRule{{Pattern: "/admin", Action: dynamicproxy.PathRuleDeny}, {Pattern: "/api", Action: dynamicproxy.PathRuleRateLimit, RateLimit: 5}})
	if out := postNet(t, HandleNetworkingPathRules, url.Values{"ep": {"app.example.com"}, "rules": {string(rules)}}); !strings.Contains(out, "OK") {
		t.Fatalf("set rules: %s", out)
	}
	if len(live().PathRules) != 2 {
		t.Fatal("rules not applied")
	}
	badRules, _ := json.Marshal([]dynamicproxy.PathRule{{Pattern: "admin", Action: dynamicproxy.PathRuleDeny}})
	if out := postNet(t, HandleNetworkingPathRules, url.Values{"ep": {"app.example.com"}, "rules": {string(badRules)}}); !strings.Contains(out, "error") {
		t.Fatalf("invalid rule accepted: %s", out)
	}
	if len(live().PathRules) != 2 {
		t.Fatal("failed update changed the stored rules")
	}

	//Peers
	if out := postNet(t, HandleNetworkingPeers, url.Values{"ep": {"app.example.com"}, "cidrs": {`["203.0.113.0/24"]`}}); !strings.Contains(out, "OK") {
		t.Fatalf("set peers: %s", out)
	}
	if out := postNet(t, HandleNetworkingPeers, url.Values{"ep": {"app.example.com"}, "cidrs": {`["0.0.0.0/0"]`}}); !strings.Contains(out, "error") {
		t.Fatalf("match-all peer set accepted: %s", out)
	}

	//Secondary TLS
	if out := postNet(t, HandleNetworkingSecondaryTLS, url.Values{"ep": {"app.example.com"}, "enable": {"true"}}); !strings.Contains(out, "OK") {
		t.Fatalf("set secondary tls: %s", out)
	}
	if !live().SecondaryPortsTLS {
		t.Fatal("secondary TLS not applied")
	}

	//An ordinary edit of the rule keeps all networking options
	if out := postEdit(t, url.Values{"rootname": {"app.example.com"}, "ss": {"false"}}); strings.Contains(out, "error") {
		t.Fatalf("edit: %s", out)
	}
	ep := live()
	if ep.ClientCert == nil || len(ep.PathRules) != 2 || len(ep.AllowedPeerCIDRs) != 1 || !ep.SecondaryPortsTLS {
		t.Fatalf("regular edit dropped networking options: %s", endpointJSON(t, ep))
	}

	//GET
	r := httptest.NewRequest(http.MethodGet, "/api/proxy/networking/get?ep=app.example.com", nil)
	w := httptest.NewRecorder()
	HandleNetworkingGet(w, r)
	var got struct {
		ClientCert        dynamicproxy.ClientCertConfig
		PathRules         []dynamicproxy.PathRule
		AllowedPeerCIDRs  []string
		SecondaryPortsTLS bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.ClientCert.Mode == "" || len(got.PathRules) != 2 || !got.SecondaryPortsTLS {
		t.Fatalf("get: %v %s", err, w.Body.String())
	}

	//Turning the client certificate off clears it
	off, _ := json.Marshal(dynamicproxy.ClientCertConfig{})
	postNet(t, HandleNetworkingClientCert, url.Values{"ep": {"app.example.com"}, "config": {string(off)}})
	if live().ClientCert != nil {
		t.Fatal("client cert not cleared")
	}

	//CA inspect
	out := postNet(t, HandleNetworkingCAInspect, url.Values{"pem": {ca}})
	if !strings.Contains(out, "api test ca") {
		t.Fatalf("inspect: %s", out)
	}
	if out := postNet(t, HandleNetworkingCAInspect, url.Values{"pem": {"junk"}}); !strings.Contains(out, "error") {
		t.Fatalf("inspect junk: %s", out)
	}

	//Unknown rule
	if out := postNet(t, HandleNetworkingSecondaryTLS, url.Values{"ep": {"nope.example.com"}, "enable": {"true"}}); !strings.Contains(out, "error") {
		t.Fatalf("unknown rule: %s", out)
	}
}
