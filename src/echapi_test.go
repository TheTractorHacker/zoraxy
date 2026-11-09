package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/ech"
)

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
