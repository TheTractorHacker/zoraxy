package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type pair struct {
	primary, follower *Manager
	pDir, fDir        string
	server            *httptest.Server
	pClock, fClock    *fakeClock
	reloads           atomic.Int32
	failReload        atomic.Bool
}

func newPair(t *testing.T, syncCerts bool) *pair {
	t.Helper()
	p := &pair{pDir: t.TempDir(), fDir: t.TempDir()}
	start := time.Unix(1_700_000_000, 0)
	p.pClock, p.fClock = &fakeClock{t: start}, &fakeClock{t: start}
	writeTree(t, p.pDir)

	var err error
	p.primary, err = NewManager(Options{ConfDir: p.pDir, NodeID: "primary-1", Version: "1.0", Now: p.pClock.Now})
	if err != nil {
		t.Fatal(err)
	}
	role, sc := RolePrimary, syncCerts
	if err := p.primary.Update(ConfigUpdate{Role: &role, Secret: strPtr(testSecret), SyncCerts: &sc}); err != nil {
		t.Fatal(err)
	}
	p.server = httptest.NewServer(p.primary.SyncHandler())
	t.Cleanup(p.server.Close)

	p.follower, err = NewManager(Options{
		ConfDir: p.fDir, NodeID: "follower-1", NodeName: "fol", Version: "1.0", Now: p.fClock.Now,
		Reload: func() error {
			p.reloads.Add(1)
			if p.failReload.Load() {
				return errors.New("boom")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	frole := RoleFollower
	if err := p.follower.Update(ConfigUpdate{Role: &frole, Secret: strPtr(testSecret), PrimaryURL: strPtr(p.server.URL)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.follower.Stop)
	return p
}

func strPtr(s string) *string { return &s }

func (p *pair) sync(t *testing.T) error {
	t.Helper()
	return p.follower.SyncOnce(context.Background(), false)
}

func TestPrimaryFollowerEndToEnd(t *testing.T) {
	p := newPair(t, false)

	// first sync applies everything and reloads once
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if p.reloads.Load() != 1 {
		t.Fatalf("want 1 reload got %d", p.reloads.Load())
	}
	if got := readFile(t, p.fDir, "proxy/a.config"); got != `{"RootOrMatchingDomain":"a.example.com"}` {
		t.Fatalf("a.config not synced: %q", got)
	}
	for _, mustNot := range []string{"webui/webui.key", "updater/pending.json", "sys.uuid", "auth_users.json", "certs/a.key"} {
		if readFile(t, p.fDir, mustNot) != "<missing>" {
			t.Errorf("%s was synced to the follower", mustNot)
		}
	}
	st := p.follower.Status()
	if st.LastResult != "applied" || st.AppliedVersion == 0 || st.LastError != "" {
		t.Fatalf("bad status %+v", st)
	}

	// heartbeat reached the primary
	nodes := p.primary.Nodes()
	if len(nodes) != 1 || nodes[0].ID != "follower-1" || nodes[0].AppliedVersion != st.AppliedVersion || nodes[0].Name != "fol" {
		t.Fatalf("primary node list wrong: %+v", nodes)
	}

	// unchanged: no new apply, no reload
	p.fClock.Add(time.Second)
	p.pClock.Add(time.Second)
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if p.reloads.Load() != 1 || p.follower.Status().LastResult != "unchanged" {
		t.Fatalf("expected no-op, reloads=%d %+v", p.reloads.Load(), p.follower.Status())
	}

	// primary edit -> new, higher version
	os.WriteFile(filepath.Join(p.pDir, "proxy", "c.config"), []byte(`{"RootOrMatchingDomain":"c.example.com"}`), 0o600)
	os.Remove(filepath.Join(p.pDir, "proxy", "b.config"))
	p.fClock.Add(time.Second)
	p.pClock.Add(time.Second)
	prevVersion := p.follower.Status().AppliedVersion
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if p.reloads.Load() != 2 || p.follower.Status().AppliedVersion <= prevVersion {
		t.Fatalf("edit not applied/versioned: reloads=%d %+v", p.reloads.Load(), p.follower.Status())
	}
	if readFile(t, p.fDir, "proxy/c.config") == "<missing>" || readFile(t, p.fDir, "proxy/b.config") != "<missing>" {
		t.Fatal("follower did not mirror the primary change")
	}

	// the follower never writes to the primary
	if _, err := os.Stat(filepath.Join(p.pDir, "proxy", "follower-1")); err == nil {
		t.Fatal("unexpected write on primary")
	}
}

func TestFollowerReloadFailureRollsBack(t *testing.T) {
	p := newPair(t, false)
	os.MkdirAll(filepath.Join(p.fDir, "proxy"), 0o755)
	os.WriteFile(filepath.Join(p.fDir, "proxy", "local.config"), []byte(`{"local":true}`), 0o600)
	p.failReload.Store(true)

	err := p.sync(t)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("want rollback error got %v", err)
	}
	if readFile(t, p.fDir, "proxy/local.config") != `{"local":true}` || readFile(t, p.fDir, "proxy/a.config") != "<missing>" {
		t.Fatal("follower config not restored after failed reload")
	}
	st := p.follower.Status()
	if st.AppliedVersion != 0 || st.LastResult != "error" || st.LastError == "" {
		t.Fatalf("status should record the failure and keep the old version: %+v", st)
	}

	// recovers on the next try
	p.failReload.Store(false)
	p.fClock.Add(time.Second)
	p.pClock.Add(time.Second)
	if err := p.sync(t); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if readFile(t, p.fDir, "proxy/a.config") == "<missing>" || p.follower.Status().AppliedVersion == 0 {
		t.Fatal("retry did not apply")
	}
}

func TestFollowerRefusesStaleVersion(t *testing.T) {
	p := newPair(t, false)
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	// pretend the follower already applied a much newer snapshot (primary rebuilt)
	p.follower.mu.Lock()
	p.follower.status.AppliedVersion += 1_000_000
	p.follower.status.AppliedHash = "other"
	p.follower.mu.Unlock()
	reloads := p.reloads.Load()
	os.WriteFile(filepath.Join(p.pDir, "access", "new.json"), []byte(`{}`), 0o600)
	p.pClock.Add(time.Second)
	p.fClock.Add(time.Second)

	// without "have" shortcut: stale must be refused
	err := p.follower.SyncOnce(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("want stale refusal got %v", err)
	}
	if p.reloads.Load() != reloads {
		t.Fatal("stale snapshot was applied")
	}
	// operator override
	if err := p.follower.SyncOnce(context.Background(), true); err != nil {
		t.Fatalf("forced sync failed: %v", err)
	}
	if readFile(t, p.fDir, "access/new.json") == "<missing>" {
		t.Fatal("forced sync did not apply")
	}
}

func TestFollowerWrongSecretAndTamperedBody(t *testing.T) {
	p := newPair(t, false)
	wrong := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	p.follower.Update(ConfigUpdate{Secret: &wrong})
	if err := p.sync(t); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if readFile(t, p.fDir, "proxy/a.config") != "<missing>" {
		t.Fatal("applied with wrong secret")
	}

	// A man in the middle flips a byte in the body
	mitm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		p.primary.SyncHandler().ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		if rec.Code == 200 {
			var env Envelope
			json.Unmarshal(body, &env)
			env.Data = env.Data[:20] + "AAAA" + env.Data[24:]
			body, _ = json.Marshal(env)
		}
		w.WriteHeader(rec.Code)
		w.Write(body)
	}))
	defer mitm.Close()
	good := testSecret
	u := mitm.URL
	p.follower.Update(ConfigUpdate{Secret: &good, PrimaryURL: &u})
	if err := p.sync(t); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
	if readFile(t, p.fDir, "proxy/a.config") != "<missing>" {
		t.Fatal("applied tampered snapshot")
	}
}

func TestACMENeutralizedWhenCertsSynced(t *testing.T) {
	p := newPair(t, true)
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p.fDir, "certs/a.key") != "KEY-A" {
		t.Fatal("certs not synced although enabled")
	}
	var acme map[string]any
	json.Unmarshal([]byte(readFile(t, p.fDir, "acme_conf.json")), &acme)
	if acme["Enabled"] != false || acme["Email"] != "ops@example.com" {
		t.Fatalf("follower must not auto-renew when the primary is the single issuer: %v", acme)
	}
	var orig map[string]any
	json.Unmarshal([]byte(readFile(t, p.pDir, "acme_conf.json")), &orig)
	if orig["Enabled"] != true {
		t.Fatal("primary acme_conf was modified")
	}
	// second sync must not loop
	reloads := p.reloads.Load()
	p.fClock.Add(time.Second)
	p.pClock.Add(time.Second)
	if err := p.sync(t); err != nil || p.reloads.Load() != reloads {
		t.Fatalf("sync loop: err=%v reloads=%d->%d", err, reloads, p.reloads.Load())
	}
}

// --- raw HTTP level: role gating, token expiry, replay, rate limit ---

func rawGet(t *testing.T, h http.Handler, m *Manager, clock *fakeClock, path, tokenSecret string, tokenAt time.Time) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "198.51.100.7:4000"
	if tokenSecret != "" {
		r.Header.Set("Authorization", "Bearer "+MakeToken(tokenSecret, "GET", path, "node-x", tokenAt))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSyncEndpointsRoleGating(t *testing.T) {
	for _, role := range []string{RoleStandalone, RoleFollower} {
		dir := t.TempDir()
		writeTree(t, dir)
		m, err := NewManager(Options{ConfDir: dir, NodeID: "n"})
		if err != nil {
			t.Fatal(err)
		}
		if role == RoleFollower {
			m.Update(ConfigUpdate{Role: &role, Secret: strPtr(testSecret), PrimaryURL: strPtr("http://127.0.0.1:1")})
			defer m.Stop()
		}
		h := m.SyncHandler()
		now := time.Now()
		for _, path := range []string{SnapshotPath, HeartbeatPath} {
			// even a perfectly valid token gets nothing: the endpoint looks absent
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", "Bearer "+MakeToken(testSecret, "GET", path, "n", now))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Errorf("role %s %s: want 404 got %d", role, path, w.Code)
			}
		}
	}
}

func TestSnapshotEndpointAuth(t *testing.T) {
	p := newPair(t, false)
	h := p.primary.SyncHandler()
	now := p.pClock.Now()

	if w := rawGet(t, h, p.primary, p.pClock, SnapshotPath, "", now); w.Code != 401 {
		t.Fatalf("no token: want 401 got %d", w.Code)
	}
	if w := rawGet(t, h, p.primary, p.pClock, SnapshotPath, "wrong-secret-wrong-secret-wrong-secret!", now); w.Code != 401 {
		t.Fatalf("wrong secret: want 401 got %d", w.Code)
	}
	if w := rawGet(t, h, p.primary, p.pClock, SnapshotPath, testSecret, now.Add(-2*TokenWindow)); w.Code != 401 {
		t.Fatalf("expired token: want 401 got %d", w.Code)
	}
	if w := rawGet(t, h, p.primary, p.pClock, SnapshotPath, testSecret, now.Add(2*TokenWindow)); w.Code != 401 {
		t.Fatalf("future token: want 401 got %d", w.Code)
	}
	// valid
	r := httptest.NewRequest("GET", SnapshotPath, nil)
	r.RemoteAddr = "198.51.100.8:1"
	r.Header.Set("Authorization", "Bearer "+MakeToken(testSecret, "GET", SnapshotPath, "node-x", now))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("valid token: want 200 got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "a.example.com") {
		t.Fatal("snapshot body is not encrypted")
	}
	// replay of the same token
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r)
	if w2.Code != 401 {
		t.Fatalf("replayed token: want 401 got %d", w2.Code)
	}
	// wrong method
	r3 := httptest.NewRequest("POST", SnapshotPath, nil)
	r3.RemoteAddr = "198.51.100.9:1"
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, r3)
	if w3.Code != 405 {
		t.Fatalf("POST snapshot: want 405 got %d", w3.Code)
	}
}

func TestSyncEndpointRateLimit(t *testing.T) {
	p := newPair(t, false)
	h := p.primary.SyncHandler()
	var last int
	limited := false
	for i := 0; i < syncRateLimit+5; i++ {
		w := rawGet(t, h, p.primary, p.pClock, SnapshotPath, "bad-secret-bad-secret-bad-secret-xx", p.pClock.Now())
		last = w.Code
		if w.Code == http.StatusTooManyRequests {
			limited = true
			if i < syncRateLimit {
				t.Fatalf("limited too early at %d", i)
			}
		}
	}
	if !limited {
		t.Fatalf("rate limit never kicked in (last status %d)", last)
	}
	// another client is unaffected
	r := httptest.NewRequest("GET", SnapshotPath, nil)
	r.RemoteAddr = "203.0.113.50:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("other client: want 401 got %d", w.Code)
	}
}

func TestTokenClockSkewBetweenNodes(t *testing.T) {
	p := newPair(t, false)
	p.fClock.Add(2 * TokenWindow) // follower clock far ahead of primary
	err := p.sync(t)
	if err == nil {
		t.Fatal("sync succeeded despite a clock skew beyond the replay window")
	}
}

// --- admin API ---

func TestStatusAndGenerateNeverLeakSecret(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(Options{ConfDir: dir, NodeID: "n", Version: "1"})

	w := httptest.NewRecorder()
	m.HandleStatus(w, httptest.NewRequest("GET", "/api/cluster/status", nil))
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	if st["role"] != "standalone" || st["secretSet"] != false {
		t.Fatalf("default status wrong: %v", st)
	}

	w = httptest.NewRecorder()
	m.HandleGenerateSecret(w, httptest.NewRequest("GET", "/api/cluster/generateSecret", nil))
	if !strings.Contains(w.Body.String(), "POST required") {
		t.Fatal("generateSecret must be POST only")
	}
	w = httptest.NewRecorder()
	m.HandleGenerateSecret(w, httptest.NewRequest("POST", "/api/cluster/generateSecret", nil))
	var gen map[string]any
	json.Unmarshal(w.Body.Bytes(), &gen)
	secret, _ := gen["secret"].(string)
	if len(secret) != 64 {
		t.Fatalf("no secret returned: %s", w.Body.String())
	}
	if gen["restartRequired"] != true {
		t.Fatal("changing the secret must flag a restart")
	}

	w = httptest.NewRecorder()
	m.HandleStatus(w, httptest.NewRequest("GET", "/api/cluster/status", nil))
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("status leaked the cluster secret")
	}
	w = httptest.NewRecorder()
	m.HandleNodes(w, httptest.NewRequest("GET", "/api/cluster/nodes", nil))
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("nodes leaked the cluster secret")
	}
	// file is private and survives a reload
	fi, err := os.Stat(filepath.Join(dir, "cluster.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cluster.json must be 0600: %v %v", err, fi)
	}
	m2, err := NewManager(Options{ConfDir: dir, NodeID: "n"})
	if err != nil || m2.secret() != secret || m2.RestartRequired() {
		t.Fatalf("reload failed: %v", err)
	}
	// session key material switches only after a restart
	if m.KeyMaterial("uuid", PurposeCaptchaSession) != "uuid" {
		t.Fatal("key material changed at runtime before restart")
	}
	if m2.KeyMaterial("uuid", PurposeCaptchaSession) == "uuid" {
		t.Fatal("key material not derived from the secret after restart")
	}
}

func TestConfigValidation(t *testing.T) {
	m, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "n"})
	post := func(vals url.Values) string {
		r := httptest.NewRequest("POST", "/api/cluster/config", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		m.HandleConfig(w, r)
		return w.Body.String()
	}
	if out := post(url.Values{"role": {"primary"}}); !strings.Contains(out, "secret is required") {
		t.Fatalf("primary without secret accepted: %s", out)
	}
	if out := post(url.Values{"secret": {"short"}}); !strings.Contains(out, "at least 32") {
		t.Fatalf("short secret accepted: %s", out)
	}
	post(url.Values{"secret": {testSecret}})
	if out := post(url.Values{"role": {"follower"}, "primaryUrl": {"ftp://x"}}); !strings.Contains(out, "primary URL") {
		t.Fatalf("bad primary url accepted: %s", out)
	}
	if out := post(url.Values{"role": {"bogus"}}); !strings.Contains(out, "role must be") {
		t.Fatalf("bad role accepted: %s", out)
	}
	if out := post(url.Values{"healthAllow": {"nope"}}); !strings.Contains(out, "allow list") {
		t.Fatalf("bad allow list accepted: %s", out)
	}
	if out := post(url.Values{"role": {"primary"}, "syncInterval": {"1"}, "healthAllow": {"10.0.0.0/8, 192.168.0.1"}}); strings.Contains(out, "error") {
		t.Fatalf("valid config rejected: %s", out)
	}
	cfg := m.Config()
	if cfg.Role != RolePrimary || cfg.SyncIntervalSeconds != MinSyncInterval || len(cfg.HealthAllow) != 2 {
		t.Fatalf("config not applied/clamped: %+v", cfg)
	}
}

func TestFollowerGuardRefusesEditsOfSyncedObjects(t *testing.T) {
	p := newPair(t, false)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	g := p.follower.GuardLocalEdits(next)
	do := func(h http.Handler, method, path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w.Code
	}
	for _, path := range []string{"/api/proxy/add", "/api/proxy/del", "/api/redirect/add", "/api/access/create", "/api/blacklist/ip/add", "/api/streamprox/add", "/api/trustedproxy/add", "/api/pathrule/add", "/api/conf/import", "/api/acme/autoRenew/setDomains"} {
		if c := do(g, "POST", path); c != 403 {
			t.Errorf("POST %s on follower: want 403 got %d", path, c)
		}
	}
	for _, c := range []struct{ m, path string }{
		{"GET", "/api/proxy/list"}, {"GET", "/api/redirect/list"}, {"POST", "/api/proxy/enable"},
		{"POST", "/api/cluster/syncNow"}, {"POST", "/api/auth/login"}, {"POST", "/api/cert/upload"},
	} {
		if code := do(g, c.m, c.path); code != 204 {
			t.Errorf("%s %s should pass on a follower (certs not synced): got %d", c.m, c.path, code)
		}
	}
	// standalone passes everything
	sm, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "s"})
	if do(sm.GuardLocalEdits(next), "POST", "/api/proxy/add") != 204 {
		t.Fatal("standalone node must never be restricted")
	}
	// -cluster_allow_local_edits
	lm, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "l", AllowLocalEdits: true})
	lm.Update(ConfigUpdate{Role: strPtr(RoleFollower), Secret: strPtr(testSecret), PrimaryURL: strPtr("http://127.0.0.1:1")})
	defer lm.Stop()
	if do(lm.GuardLocalEdits(next), "POST", "/api/proxy/add") != 204 {
		t.Fatal("allow local edits flag ignored")
	}
}

func TestFollowerGuardBlocksCertWritesOnlyWhenSynced(t *testing.T) {
	p := newPair(t, true)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	g := p.follower.GuardLocalEdits(next)
	if err := p.sync(t); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("POST", "/api/cert/upload", nil))
	if w.Code != 403 {
		t.Fatalf("cert upload on a cert-syncing follower: want 403 got %d", w.Code)
	}
}

func TestStandaloneStatusAndNoStateFiles(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Options{ConfDir: dir, NodeID: "n"})
	if err != nil {
		t.Fatal(err)
	}
	m.Start()
	defer m.Stop()
	if m.Role() != RoleStandalone {
		t.Fatal("default role must be standalone")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("a standalone node must not create files, found %v", entries)
	}
	if err := m.SyncOnce(context.Background(), false); err == nil {
		t.Fatal("standalone node ran a follower sync")
	}
}

func TestFlagSecretNotPersisted(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Options{ConfDir: dir, NodeID: "n", FlagSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	if m.KeyMaterial("u", PurposeCaptchaSession) == "u" {
		t.Fatal("flag secret not used")
	}
	hc := true
	if err := m.Update(ConfigUpdate{HealthDisabled: &hc}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "cluster.json"))
	if strings.Contains(string(b), testSecret) {
		t.Fatal("secret from the command line was written to disk")
	}
	if err := m.Update(ConfigUpdate{Secret: strPtr(strings.Repeat("a", 40))}); err == nil {
		t.Fatal("UI changed a flag-provided secret")
	}
}
