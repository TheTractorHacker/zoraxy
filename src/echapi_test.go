package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/ech"
)

func TestEchFallbackHookAndAPI(t *testing.T) {
	withEchMgr(t, true) // own public name ech.example.test
	oldTab, oldR := echFallbacks, dynamicProxyRouter
	echFallbacks = ech.NewFallbackTable()
	dynamicProxyRouter = &dynamicproxy.Router{ProxyEndpoints: &sync.Map{}}
	dynamicProxyRouter.ProxyEndpoints.Store("app.example.com", &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "app.example.com", MatchingDomainAlias: []string{"alias.example.com"}})
	dynamicProxyRouter.ProxyEndpoints.Store("*.wild.example.com", &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "*.wild.example.com"})
	t.Cleanup(func() { echFallbacks, dynamicProxyRouter = oldTab, oldR })

	for _, n := range []string{"app.example.com", "alias.example.com", "x.wild.example.com"} {
		echFallbackHook(n) // rules, aliases and wildcards are not fallback misses
	}
	for _, n := range []string{"cloudflare-ech.com", "ech.example.test", "", "scan.example.net"} {
		echFallbackHook(n)
	}
	rec := httptest.NewRecorder()
	HandleEchFallbacks(rec, httptest.NewRequest(http.MethodGet, "/api/ech/fallbacks", nil))
	var out struct {
		Entries []struct {
			Name, Class string
			Count       int
		}
		HasForeignECH bool
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	got := map[string]string{}
	for _, e := range out.Entries {
		got[e.Name] = e.Class
	}
	want := map[string]string{"cloudflare-ech.com": ech.FallbackForeignECH, "ech.example.test": ech.FallbackOwnECH, "": ech.FallbackNoSNI, "scan.example.net": ech.FallbackUnknown}
	if len(got) != len(want) {
		t.Fatalf("entries %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%q: %q want %q", k, got[k], v)
		}
	}
	if !out.HasForeignECH || out.Entries[0].Name != "cloudflare-ech.com" {
		t.Errorf("foreign ECH must be flagged and listed first: %+v", out)
	}
}

func TestEchFallbacksAdminOnly(t *testing.T) {
	if auth.ViewerAllowed(http.MethodGet, "/api/ech/fallbacks") {
		t.Fatal("viewers must not read the fallback table")
	}
	if !auth.ViewerAllowed(http.MethodGet, "/api/ech/status") {
		t.Fatal("status stays readable for viewers")
	}
}

func withEchMgr(t *testing.T, enable bool) {
	t.Helper()
	m, err := ech.Open(filepath.Join(t.TempDir(), "ech"))
	if err != nil {
		t.Fatal(err)
	}
	if enable {
		if err := m.SetSettings(ech.Settings{Enabled: true, PublicName: "ech.example.test"}); err != nil {
			t.Fatal(err)
		}
	}
	old := echMgr
	echMgr = m
	t.Cleanup(func() { echMgr = old })
}

func TestEchStatusHasRecordsField(t *testing.T) {
	withEchMgr(t, true)
	rec := httptest.NewRecorder()
	HandleEchStatus(rec, httptest.NewRequest(http.MethodGet, "/api/ech/status", nil))
	var out map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("status is not JSON: %v: %s", err, rec.Body.String())
	}
	for _, k := range []string{"Settings", "Keys", "ConfigList", "RecordExample", "PublicNameCert", "TLSEnabled", "Records", "PublicNameCheck", "OuterHandshakes"} {
		if _, ok := out[k]; !ok {
			t.Errorf("status lacks %s", k)
		}
	}
	if string(out["PublicNameCert"]) != "false" {
		t.Errorf("without a certificate manager the public name must not be reported as covered, got %s", out["PublicNameCert"])
	}
	if string(out["Records"]) != "[]" {
		t.Errorf("Records without proxy rules should be an empty array, got %s", out["Records"])
	}
}

func TestEchSelfCheckRefusals(t *testing.T) {
	withEchMgr(t, false)
	rec := httptest.NewRecorder()
	HandleEchSelfCheck(rec, httptest.NewRequest(http.MethodGet, "/api/ech/selfcheck", nil))
	if !strings.Contains(rec.Body.String(), "no active ECH key") {
		t.Errorf("expected a clear error without a key, got %s", rec.Body.String())
	}
	withEchMgr(t, true)
	rec = httptest.NewRecorder()
	HandleEchSelfCheck(rec, httptest.NewRequest(http.MethodGet, "/api/ech/selfcheck", nil))
	if !strings.Contains(rec.Body.String(), "not running in TLS mode") {
		t.Errorf("expected a TLS mode error, got %s", rec.Body.String())
	}
}
