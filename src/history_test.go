package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/apitoken"
	"imuslab.com/zoraxy/mod/confhistory"
)

// A REST API v1 change made with a token creates a version attributed to the token,
// read requests and refused (read-only token) requests do not.
func TestHistoryCapturesAPIv1TokenChanges(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "conf")
	os.MkdirAll(filepath.Join(conf, "proxy"), 0o755)
	m, err := confhistory.New(confhistory.Options{ConfDir: conf, Debounce: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	old := historyMgr
	historyMgr = m
	defer func() { historyMgr = old }()
	os.WriteFile(filepath.Join(conf, "proxy", "a.config"), []byte(`{"RootOrMatchingDomain":"a.example.com"}`), 0o644)
	m.Start()
	base := len(m.IDs())

	tokens, err := apitoken.NewManager(&v1KV{m: map[string][]byte{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stub := func(w http.ResponseWriter, r *http.Request) {
		os.WriteFile(filepath.Join(conf, "proxy", "b.config"), []byte(`{"RootOrMatchingDomain":"b.example.com"}`), 0o644)
		w.Write([]byte(`"OK"`))
	}
	read := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }
	h := newAPIv1Handler(tokens, v1Backend{ProxyList: read, ProxyAdd: stub, ProxyEdit: stub, ProxyDelete: stub, ProxyToggle: stub,
		AccessList: read, RedirectList: read, CertList: read, StatsSummary: read, WAF: read, StatsBlocked: read},
		func(next http.Handler) http.Handler { return next })
	ro, _, _ := tokens.Create("ro", apitoken.ScopeRead, 0, nil)
	rw, _, _ := tokens.Create("deploy-bot", apitoken.ScopeReadWrite, 0, nil)

	if rec := v1Do(h, "GET", "/api/v1/proxy-rules", rw, ""); rec.Code != 200 {
		t.Fatalf("list: %d", rec.Code)
	}
	if rec := v1Do(h, "POST", "/api/v1/proxy-rules", ro, `{"rootname":"b.example.com"}`); rec.Code != 403 {
		t.Fatalf("read-only token must be refused, got %d", rec.Code)
	}
	time.Sleep(300 * time.Millisecond)
	if len(m.IDs()) != base {
		t.Fatal("reads and refused writes must not create versions")
	}
	if rec := v1Do(h, "POST", "/api/v1/proxy-rules", rw, `{"rootname":"b.example.com","ep":"1.1.1.1:80"}`); rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(m.IDs()) == base && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	ids := m.IDs()
	if len(ids) != base+1 {
		t.Fatalf("token change must create one version, got %d", len(ids)-base)
	}
	v, _ := m.Get(ids[len(ids)-1])
	if v.Actor != "token deploy-bot" || !strings.Contains(v.Summary, "REST API") || len(v.Changes) != 1 || v.Changes[0].Path != "proxy/b.config" {
		t.Fatalf("version: %+v", v)
	}
	// the wrapper is a no-op without a manager
	historyMgr = nil
	if historyWrapV1(http.NotFoundHandler()) == nil || historyWrap(http.NotFoundHandler()) == nil {
		t.Fatal("wrappers must pass through")
	}
	rec := httptest.NewRecorder()
	historyWrap(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest("POST", "/api/x", nil))
	if rec.Code != 404 {
		t.Fatal("pass through")
	}
}
