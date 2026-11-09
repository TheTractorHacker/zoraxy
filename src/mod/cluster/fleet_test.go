package cluster

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------
// harness

type fnode struct {
	m       *Manager
	dir     string
	reloads atomic.Int32
	fail    atomic.Bool
	health  atomic.Value // string
	reqs    atomic.Uint64
}

type fleetEnv struct {
	t     *testing.T
	hub   *Manager
	dir   string
	srv   *httptest.Server
	clock *fakeClock
	nodes map[string]*fnode
}

func newFleetEnv(t *testing.T) *fleetEnv {
	t.Helper()
	e := &fleetEnv{t: t, dir: t.TempDir(), clock: &fakeClock{t: time.Unix(1_700_000_000, 0)}, nodes: map[string]*fnode{}}
	writeTree(t, e.dir)
	var err error
	e.hub, err = NewManager(Options{ConfDir: e.dir, NodeID: "hub-1", Version: "1.0", Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	role := RoleHub
	if err := e.hub.Update(ConfigUpdate{Role: &role}); err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(e.hub.FleetHandler())
	t.Cleanup(e.srv.Close)
	t.Cleanup(e.hub.Stop)
	return e
}

func (e *fleetEnv) addNode(id, group string) *fnode {
	e.t.Helper()
	n := &fnode{dir: e.t.TempDir()}
	n.health.Store("ok")
	var err error
	n.m, err = NewManager(Options{ConfDir: n.dir, NodeID: id, NodeName: id, Version: "1.0", Now: e.clock.Now,
		Reload: func() error {
			n.reloads.Add(1)
			if n.fail.Load() {
				return errors.New("boom")
			}
			return nil
		},
		Stats: func() NodeStats {
			return NodeStats{UptimeSeconds: 100, Health: n.health.Load().(string), Endpoints: 2, Requests: n.reqs.Load(), WAFMode: "block"}
		}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(n.m.Stop)
	tok, _, err := e.hub.hub.CreateJoinToken("tester", time.Minute, "", group)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := n.m.Join(context.Background(), JoinRequest{HubURL: e.srv.URL, Token: tok, AllowHTTP: true}); err != nil {
		e.t.Fatal(err)
	}
	e.nodes[id] = n
	return n
}

func (e *fleetEnv) setGroup(name string, scopes []string, tags ...string) {
	e.t.Helper()
	if err := e.hub.hub.SetGroup("tester", name, ScopeSel{Scopes: scopes, ProxyTags: tags}, nil); err != nil {
		e.t.Fatal(err)
	}
}

func (e *fleetEnv) publish(group, strategy string) *Rollout {
	e.t.Helper()
	e.clock.Add(time.Second) //backup folders are named after the clock
	r, err := e.hub.hub.Publish("tester", PublishRequest{Group: group, Strategy: strategy, HealthySeconds: 30, TimeoutSeconds: 120})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (n *fnode) sync(t *testing.T) error {
	t.Helper()
	return n.m.FleetSyncOnce(context.Background(), false)
}

func (n *fnode) heartbeat(t *testing.T) {
	t.Helper()
	if _, err := n.m.sendFleetHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func fileAt(dir, rel string) string {
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func mustWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------
// join tokens

func TestJoinTokenLifecycle(t *testing.T) {
	e := newFleetEnv(t)
	h := e.hub.hub
	tok, _, err := h.CreateJoinToken("a", time.Minute, "edge-1", "edge-eu")
	if err != nil {
		t.Fatal(err)
	}
	// wrong secret
	bad := tok[:len(tok)-1] + "0"
	if tok[len(tok)-1] == '0' {
		bad = tok[:len(tok)-1] + "1"
	}
	if _, err := h.Join(bad, "n1", "x", "1", "1.1.1.1"); err != ErrJoinInvalid {
		t.Fatalf("wrong secret accepted: %v", err)
	}
	res, err := h.Join(tok, "n1", "ignored", "1", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Group != "edge-eu" || len(res.NodeKey) != 64 {
		t.Fatalf("unexpected join result %+v", res)
	}
	if h.st.Nodes["n1"].Name != "edge-1" {
		t.Fatal("preselected node name not applied")
	}
	// single use, also for another node id (replay)
	if _, err := h.Join(tok, "n2", "x", "1", "1.1.1.1"); err != ErrJoinInvalid {
		t.Fatal("token was usable twice")
	}
	// expiry
	tok2, _, _ := h.CreateJoinToken("a", time.Minute, "", "")
	e.clock.Add(2 * time.Minute)
	if _, err := h.Join(tok2, "n3", "x", "1", "1.1.1.1"); err != ErrJoinInvalid {
		t.Fatal("expired token accepted")
	}
	// revoked
	tok3, t3, _ := h.CreateJoinToken("a", time.Minute, "", "")
	h.RevokeJoinToken("a", t3.ID)
	if _, err := h.Join(tok3, "n4", "x", "1", "1.1.1.1"); err != ErrJoinInvalid {
		t.Fatal("revoked token accepted")
	}
	// ttl bound and garbage
	if _, _, err := h.CreateJoinToken("a", 48*time.Hour, "", ""); err == nil {
		t.Fatal("ttl above 24h accepted")
	}
	for _, g := range []string{"", "zj1.x.y", "zj1.00000000.short", "nope"} {
		if _, err := h.Join(g, "n5", "x", "1", "1.1.1.1"); err != ErrJoinInvalid {
			t.Fatalf("garbage token %q accepted", g)
		}
	}
	// only a hash is stored
	b, _ := os.ReadFile(h.stateFile())
	secret := tok[strings.LastIndex(tok, ".")+1:]
	if bytes.Contains(b, []byte(secret)) {
		t.Fatal("join token secret persisted in clear")
	}
}

func TestJoinRequiresHubRoleAndRateLimit(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewManager(Options{ConfDir: dir, NodeID: "x"})
	srv := httptest.NewServer(m.FleetHandler())
	defer srv.Close()
	for _, p := range []string{FleetJoinPath, FleetConfigPath, FleetHeartbeatPath} {
		resp, _ := http.Post(srv.URL+p, "application/json", strings.NewReader("{}"))
		if resp.StatusCode != 404 {
			t.Fatalf("%s answered %d on a non-hub", p, resp.StatusCode)
		}
	}
	e := newFleetEnv(t)
	last := 0
	for i := 0; i < joinRateLimit+3; i++ {
		resp, _ := http.Post(e.srv.URL+FleetJoinPath, "application/json", strings.NewReader(`{"token":"zj1.00000000.00000000000000000000000000000000","nodeId":"n"}`))
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("join was not rate limited (last status %d)", last)
	}
}

// ---------------------------------------------------------------------
// per node auth, revocation, rotation

func TestPerNodeAuthRevokeAndReplay(t *testing.T) {
	e := newFleetEnv(t)
	a := e.addNode("node-a", "g1")
	b := e.addNode("node-b", "g1")
	if err := a.sync(t); err != nil {
		t.Fatal(err)
	}
	// node keys differ and one node's key cannot act as the other
	ca, _ := a.m.loadCreds()
	cb, _ := b.m.loadCreds()
	if ca.NodeKey == cb.NodeKey {
		t.Fatal("nodes share a key")
	}
	now := e.clock.Now()
	forged := MakeToken(ca.NodeKey, "GET", FleetConfigPath, "node-b", now)
	req, _ := http.NewRequest("GET", e.srv.URL+FleetConfigPath, nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatalf("token signed with another node's key accepted: %d", resp.StatusCode)
	}
	// replay of a valid token
	good := MakeToken(cb.NodeKey, "GET", FleetConfigPath, "node-b", now)
	do := func() int {
		req, _ := http.NewRequest("GET", e.srv.URL+FleetConfigPath, nil)
		req.Header.Set("Authorization", "Bearer "+good)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	if c := do(); c != 200 && c != 204 {
		t.Fatalf("valid token refused: %d", c)
	}
	if c := do(); c != 401 {
		t.Fatalf("replayed token accepted: %d", c)
	}
	// stale timestamp
	old := MakeToken(cb.NodeKey, "GET", FleetConfigPath, "node-b", now.Add(-5*time.Minute))
	req, _ = http.NewRequest("GET", e.srv.URL+FleetConfigPath, nil)
	req.Header.Set("Authorization", "Bearer "+old)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatal("stale token accepted")
	}
	// wrong path binding
	wrong := MakeToken(cb.NodeKey, "POST", FleetHeartbeatPath, "node-b", now)
	req, _ = http.NewRequest("GET", e.srv.URL+FleetConfigPath, nil)
	req.Header.Set("Authorization", "Bearer "+wrong)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatal("token for another endpoint accepted")
	}

	// revocation takes effect immediately and only for that node
	if err := e.hub.hub.RevokeNode("tester", "node-b"); err != nil {
		t.Fatal(err)
	}
	if err := b.sync(t); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("revoked node still syncs: %v", err)
	}
	if _, err := b.m.sendFleetHeartbeat(context.Background()); err == nil {
		t.Fatal("revoked node can still send heartbeats")
	}
	if err := a.sync(t); err != nil {
		t.Fatalf("other node affected by revocation: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	e := newFleetEnv(t)
	a := e.addNode("node-a", "g1")
	if err := a.sync(t); err != nil {
		t.Fatal(err)
	}
	old, _ := a.m.loadCreds()
	if err := e.hub.hub.RotateNode("tester", "node-a"); err != nil {
		t.Fatal(err)
	}
	if err := a.sync(t); err != nil {
		t.Fatal(err)
	}
	cur, _ := a.m.loadCreds()
	if cur.NodeKey == old.NodeKey || len(cur.NodeKey) != 64 {
		t.Fatal("node key not rotated")
	}
	// the node proves it holds the new key: hub drops the old one
	a.heartbeat(t)
	if n := e.hub.hub.st.Nodes["node-a"]; n.Key != cur.NodeKey || n.NextKey != "" {
		t.Fatal("hub did not complete the rotation")
	}
	req, _ := http.NewRequest("GET", e.srv.URL+FleetConfigPath, nil)
	req.Header.Set("Authorization", "Bearer "+MakeToken(old.NodeKey, "GET", FleetConfigPath, "node-a", e.clock.Now()))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatal("old key still works after rotation")
	}
	// key files are private
	fi, err := os.Stat(a.m.nodeCredFile())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("node key file mode %v err %v", fi, err)
	}
	fi, _ = os.Stat(e.hub.hub.stateFile())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("hub state mode %v", fi.Mode())
	}
}

// ---------------------------------------------------------------------
// scopes: managed vs local

func TestManagedScopesNeverClobberLocal(t *testing.T) {
	e := newFleetEnv(t)
	n := e.addNode("node-a", "g1")
	mustWrite(t, n.dir, "proxy/local.config", `{"RootOrMatchingDomain":"local.example.com"}`)
	mustWrite(t, n.dir, "proxy/a.config", `{"RootOrMatchingDomain":"stale-local-a"}`)
	mustWrite(t, n.dir, "redirect/mine.json", `{"local":true}`)
	mustWrite(t, n.dir, "sys.uuid", "NODE-UUID")
	e.setGroup("g1", []string{"proxy"})
	e.publish("g1", StrategyImmediate)
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	if got := fileAt(n.dir, "proxy/a.config"); got != `{"RootOrMatchingDomain":"a.example.com"}` {
		t.Fatalf("hub did not win on identical key: %s", got)
	}
	if fileAt(n.dir, "proxy/b.config") == "<missing>" {
		t.Fatal("managed rule missing")
	}
	if fileAt(n.dir, "proxy/local.config") == "<missing>" {
		t.Fatal("node local proxy rule was removed")
	}
	if fileAt(n.dir, "redirect/mine.json") == "<missing>" || fileAt(n.dir, "sys.uuid") != "NODE-UUID" {
		t.Fatal("unmanaged scope or node data touched")
	}
	if fileAt(n.dir, "redirect/r1.json") != "<missing>" {
		t.Fatal("unmanaged redirect scope was applied")
	}
	info := n.m.FleetInfo()
	if !info.Managed || len(info.Conflicts) != 1 || info.Conflicts[0].Key != "proxy/a.config" {
		t.Fatalf("conflict not reported: %+v", info)
	}
	// hub drops b: it disappears, local rule stays
	os.Remove(filepath.Join(e.dir, "proxy", "b.config"))
	e.publish("g1", StrategyImmediate)
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	if fileAt(n.dir, "proxy/b.config") != "<missing>" {
		t.Fatal("rule removed on the hub still present on node")
	}
	if fileAt(n.dir, "proxy/local.config") == "<missing>" {
		t.Fatal("local rule lost when the hub removed a managed rule")
	}
	// enabling another scope later manages it
	e.setGroup("g1", []string{"proxy", "redirect"})
	e.publish("g1", StrategyImmediate)
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	if fileAt(n.dir, "redirect/r1.json") == "<missing>" || fileAt(n.dir, "redirect/mine.json") != "<missing>" {
		t.Fatal("redirect scope should now mirror the hub")
	}
}

func TestProxyTagFilter(t *testing.T) {
	e := newFleetEnv(t)
	mustWrite(t, e.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a","Tags":["edge","eu"]}`)
	mustWrite(t, e.dir, "proxy/b.config", `{"RootOrMatchingDomain":"b","Tags":["internal"]}`)
	mustWrite(t, e.dir, "proxy/c.config", `{"RootOrMatchingDomain":"c"}`)
	n := e.addNode("node-a", "edge")
	e.setGroup("edge", []string{"proxy"}, "EDGE")
	e.publish("edge", StrategyImmediate)
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	if fileAt(n.dir, "proxy/a.config") == "<missing>" || fileAt(n.dir, "proxy/b.config") != "<missing>" || fileAt(n.dir, "proxy/c.config") != "<missing>" {
		t.Fatal("tag filter did not select exactly the tagged rules")
	}
	// the per node override beats the group
	if err := e.hub.hub.SetNodeScopes("tester", "node-a", &ScopeSel{Scopes: []string{"proxy"}, ProxyTags: []string{"internal"}}); err != nil {
		t.Fatal(err)
	}
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	if fileAt(n.dir, "proxy/b.config") == "<missing>" || fileAt(n.dir, "proxy/a.config") != "<missing>" {
		t.Fatal("node override not applied")
	}
}

func TestSnapshotsNeverContainNodeSecrets(t *testing.T) {
	e := newFleetEnv(t)
	e.addNode("node-a", "g1")
	e.setGroup("g1", ScopeNames())
	v, _, err := e.hub.hub.Capture("t", "")
	if err != nil {
		t.Fatal(err)
	}
	for p := range v.Files {
		for _, bad := range []string{"sys.uuid", "auth_users", "webui", "updater", "cluster.json", ".cluster", "log_conf", "geodb", "plugin_groups"} {
			if strings.Contains(p, bad) {
				t.Fatalf("version contains %s", p)
			}
		}
		if strings.HasPrefix(p, "certs/") {
			t.Fatal("certificates captured although CaptureCerts is off")
		}
	}
	// at rest the stored version is encrypted
	raw, _ := os.ReadFile(e.hub.hub.versionFile(v.ID))
	if bytes.Contains(raw, []byte("a.example.com")) || bytes.Contains(raw, []byte("ops@example.com")) {
		t.Fatal("version stored in clear")
	}
	fi, _ := os.Stat(e.hub.hub.versionFile(v.ID))
	if fi.Mode().Perm() != 0o600 {
		t.Fatal("version file not 0600")
	}
}

// ---------------------------------------------------------------------
// variables

func TestVariableSubstitution(t *testing.T) {
	good := []byte(`{"Upstream":"{{node.upstream_ip}}:8080","N":"{{node.name}}"}`)
	out, err := Substitute("proxy/a.config", good, map[string]string{"upstream_ip": "10.0.0.7", "name": "edge-1"})
	if err != nil || string(out) != `{"Upstream":"10.0.0.7:8080","N":"edge-1"}` {
		t.Fatalf("got %s %v", out, err)
	}
	bad := map[string]string{
		"quote":     `1.2.3.4","Admin":"x`,
		"brace":     `{{node.id}}`,
		"backslash": `a\b`,
		"newline":   "a\nb",
		"space":     "a b",
		"dollar":    "$(id)",
		"semicolon": "a;b",
	}
	for n, v := range bad {
		if err := ValidateVars(map[string]string{"upstream_ip": v}); err == nil {
			t.Fatalf("%s value %q accepted", n, v)
		}
		if _, err := Substitute("proxy/a.config", good, map[string]string{"upstream_ip": v, "name": "x"}); err == nil {
			t.Fatalf("%s value %q substituted", n, v)
		}
	}
	for _, name := range []string{"Bad", "1x", "a-b", "id", "name", "group", strings.Repeat("a", 40), ""} {
		if err := ValidateVars(map[string]string{name: "x"}); err == nil {
			t.Fatalf("variable name %q accepted", name)
		}
	}
	if _, err := Substitute("p.config", []byte(`{"a":"{{node.missing}}"}`), map[string]string{}); err == nil {
		t.Fatal("undefined variable accepted")
	}
	for _, m := range []string{`{"a":"{{node.X}}"}`, `{"a":"{{node.x"}`, `{"a":"{{node.}}"}`} {
		if _, err := PlaceholdersIn([]byte(m)); err == nil {
			t.Fatalf("malformed placeholder %s accepted", m)
		}
	}
	// certificates are never templated
	r, err := ResolveFiles([]FileEntry{{Path: "certs/a.pem", Data: []byte("{{node.x}}")}}, nil)
	if err != nil || string(r[0].Data) != "{{node.x}}" {
		t.Fatal("cert content was touched")
	}
}

func TestVariablesEndToEnd(t *testing.T) {
	e := newFleetEnv(t)
	mustWrite(t, e.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a.example.com","Upstream":"{{node.upstream_ip}}","Who":"{{node.name}}-{{node.group}}"}`)
	n1 := e.addNode("node-a", "g1")
	n2 := e.addNode("node-b", "g1")
	e.setGroup("g1", []string{"proxy"})
	// no variables yet: the publish is refused and nothing changes
	if _, err := e.hub.hub.Publish("t", PublishRequest{Group: "g1"}); err == nil || !strings.Contains(err.Error(), "upstream_ip") {
		t.Fatalf("publish with missing variables: %v", err)
	}
	if err := e.hub.hub.SetNodeVars("t", "node-a", map[string]string{"upstream_ip": "10.1.0.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.hub.hub.Publish("t", PublishRequest{Group: "g1"}); err == nil {
		t.Fatal("publish succeeded although node-b has no value")
	}
	if err := e.hub.hub.SetGroup("t", "g1", ScopeSel{Scopes: []string{"proxy"}}, map[string]string{"upstream_ip": "10.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	e.publish("g1", StrategyImmediate)
	n1.sync(t)
	n2.sync(t)
	if got := fileAt(n1.dir, "proxy/a.config"); !strings.Contains(got, `"Upstream":"10.1.0.1"`) || !strings.Contains(got, "node-a-g1") {
		t.Fatalf("node-a: %s", got)
	}
	if got := fileAt(n2.dir, "proxy/a.config"); !strings.Contains(got, `"Upstream":"10.9.9.9"`) {
		t.Fatalf("node-b should use the group value: %s", got)
	}
	// a hostile bundle (hub misbehaving) is rejected on the node as well
	if err := e.hub.hub.SetNodeVars("t", "node-a", map[string]string{"upstream_ip": `x","y":"z`}); err == nil {
		t.Fatal("hub accepted an injection value")
	}
	e.hub.hub.mu.Lock()
	e.hub.hub.st.Nodes["node-a"].Vars = map[string]string{"upstream_ip": `x","y":"z`}
	e.hub.hub.mu.Unlock()
	n1.m.mu.Lock()
	n1.m.status.AppliedHash = "" //force a re-fetch
	n1.m.mu.Unlock()
	if err := n1.sync(t); err == nil {
		t.Fatal("node applied a bundle with an injection value")
	}
	if got := fileAt(n1.dir, "proxy/a.config"); strings.Contains(got, `"y":"z`) {
		t.Fatal("injection reached the config")
	}
}

func TestCaptureRejectsMalformedPlaceholders(t *testing.T) {
	e := newFleetEnv(t)
	mustWrite(t, e.dir, "proxy/a.config", `{"x":"{{node.UP}}"}`)
	if _, _, err := e.hub.hub.Capture("t", ""); err == nil {
		t.Fatal("malformed placeholder captured")
	}
}

// ---------------------------------------------------------------------
// rollout state machine (hub only, nodes simulated by heartbeats)

type simHub struct {
	t     *testing.T
	e     *fleetEnv
	h     *Hub
	nodes []string
}

func newSim(t *testing.T, ids ...string) *simHub {
	e := newFleetEnv(t)
	s := &simHub{t: t, e: e, h: e.hub.hub, nodes: ids}
	for _, id := range ids {
		tok, _, _ := s.h.CreateJoinToken("t", time.Minute, "", "g")
		if _, err := s.h.Join(tok, id, id, "1", "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
	}
	e.setGroup("g", []string{"proxy"})
	return s
}

// beat simulates a heartbeat of a node that runs the hash it is told to run.
func (s *simHub) beat(id string, mutate func(*fleetHeartbeat)) {
	_, want := s.h.DesiredHash(id)
	s.h.mu.Lock()
	hb := fleetHeartbeat{}
	if rt := s.h.rt[id]; rt != nil {
		hb = rt.HB
	}
	s.h.mu.Unlock()
	hb.Stats.Health = "ok"
	if mutate != nil {
		mutate(&hb)
	}
	_ = want
	s.h.touchAt(id, s.e.clock.Now())
	s.h.recordHeartbeat(id, hb, s.e.clock.Now())
	s.h.Tick(s.e.clock.Now())
}

func (h *Hub) touchAt(id string, now time.Time) {
	h.mu.Lock()
	h.rtFor(id).LastSeen = now.Unix()
	h.mu.Unlock()
}

func (s *simHub) applied(id string) func(*fleetHeartbeat) {
	_, hash := s.h.DesiredHash(id)
	return func(hb *fleetHeartbeat) { hb.AppliedHash, hb.AttemptHash, hb.LastResult = hash, hash, "applied" }
}

func (s *simHub) group() *FleetGroup { return s.h.st.Groups["g"] }

func TestCanaryPromotesAfterHealthyWindow(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	stable, err := s.h.Publish("t", PublishRequest{Group: "g"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range s.nodes {
		s.beat(id, s.applied(id))
	}
	mustWrite(t, s.e.dir, "proxy/new.config", `{"RootOrMatchingDomain":"new"}`)
	r, err := s.h.Publish("t", PublishRequest{Group: "g", Strategy: StrategyCanary, HealthySeconds: 30, TimeoutSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	if r.CanaryNode != "a" || r.State != RolloutCanary {
		t.Fatalf("unexpected rollout %+v", r)
	}
	// only the canary is pointed at the new version
	if v, _ := s.h.DesiredHash("a"); v != r.Version {
		t.Fatal("canary does not get the new version")
	}
	if v, _ := s.h.DesiredHash("b"); v != stable.Version {
		t.Fatal("other nodes must stay on the stable version")
	}
	s.beat("a", s.applied("a")) // applied and healthy: window starts
	s.e.clock.Add(20 * time.Second)
	s.beat("a", nil)
	if s.group().Rollout.State != RolloutCanary {
		t.Fatal("promoted before the healthy window elapsed")
	}
	s.e.clock.Add(15 * time.Second)
	s.beat("a", nil)
	if s.group().Rollout.State != RolloutComplete || s.group().Desired != r.Version {
		t.Fatalf("not promoted: %+v", s.group().Rollout)
	}
	if v, _ := s.h.DesiredHash("b"); v != r.Version {
		t.Fatal("rest of the group not pointed at the new version")
	}
}

func TestCanaryFailedApplyHaltsAndRollsBack(t *testing.T) {
	s := newSim(t, "a", "b")
	stable, _ := s.h.Publish("t", PublishRequest{Group: "g"})
	s.beat("a", s.applied("a"))
	s.beat("b", s.applied("b"))
	mustWrite(t, s.e.dir, "proxy/new.config", `{"RootOrMatchingDomain":"new"}`)
	r, err := s.h.Publish("t", PublishRequest{Group: "g", Strategy: StrategyCanary})
	if err != nil {
		t.Fatal(err)
	}
	_, newHash := s.h.DesiredHash("a")
	s.beat("a", func(hb *fleetHeartbeat) {
		hb.AttemptHash, hb.LastResult, hb.LastError = newHash, "error", "validation failed"
	})
	g := s.group()
	if g.Rollout.State != RolloutHalted || !strings.Contains(g.Rollout.Reason, "validation failed") {
		t.Fatalf("rollout not halted: %+v", g.Rollout)
	}
	if g.Desired != stable.Version {
		t.Fatal("stable version changed by a failed rollout")
	}
	if v, _ := s.h.DesiredHash("a"); v != stable.Version {
		t.Fatal("canary not returned to the stable version")
	}
	_ = r
	// a new rollout can start after a halt
	if _, err := s.h.Publish("t", PublishRequest{Group: "g", Strategy: StrategyImmediate}); err != nil {
		t.Fatalf("cannot publish after halt: %v", err)
	}
}

func TestCanaryUnhealthyAndTimeoutHalt(t *testing.T) {
	s := newSim(t, "a")
	s.h.Publish("t", PublishRequest{Group: "g"})
	s.beat("a", s.applied("a"))
	mustWrite(t, s.e.dir, "proxy/new.config", `{"RootOrMatchingDomain":"new"}`)
	s.h.Publish("t", PublishRequest{Group: "g", Strategy: StrategyCanary})
	s.beat("a", s.applied("a"))
	s.beat("a", func(hb *fleetHeartbeat) { hb.Stats.Health = "unavailable" })
	if s.group().Rollout.State != RolloutCanary {
		t.Fatal("halted inside the grace period")
	}
	s.e.clock.Add(40 * time.Second)
	s.beat("a", func(hb *fleetHeartbeat) { hb.Stats.Health = "unavailable" })
	if s.group().Rollout.State != RolloutHalted || !strings.Contains(s.group().Rollout.Reason, "unhealthy") {
		t.Fatalf("unhealthy canary did not halt: %+v", s.group().Rollout)
	}

	// timeout: canary never applies
	mustWrite(t, s.e.dir, "proxy/new2.config", `{"RootOrMatchingDomain":"new2"}`)
	s.h.Publish("t", PublishRequest{Group: "g", Strategy: StrategyCanary, TimeoutSeconds: 60})
	s.e.clock.Add(30 * time.Second)
	s.beat("a", func(hb *fleetHeartbeat) { hb.AppliedHash = "old" })
	if s.group().Rollout.State != RolloutCanary {
		t.Fatal("halted early")
	}
	s.e.clock.Add(40 * time.Second)
	s.beat("a", func(hb *fleetHeartbeat) { hb.AppliedHash = "old" })
	if s.group().Rollout.State != RolloutHalted || !strings.Contains(s.group().Rollout.Reason, "did not apply") {
		t.Fatalf("timeout did not halt: %+v", s.group().Rollout)
	}
}

func TestManualApprovalAndHold(t *testing.T) {
	s := newSim(t, "a", "b")
	s.h.Publish("t", PublishRequest{Group: "g"})
	s.beat("a", s.applied("a"))
	s.beat("b", s.applied("b"))
	stable := s.group().Desired
	mustWrite(t, s.e.dir, "proxy/new.config", `{"RootOrMatchingDomain":"new"}`)
	r, err := s.h.Publish("t", PublishRequest{Group: "g", Strategy: StrategyManual})
	if err != nil {
		t.Fatal(err)
	}
	if r.State != RolloutPendingApproval || s.group().Desired != stable {
		t.Fatal("manual publish changed nodes before approval")
	}
	if _, err := s.h.Publish("t", PublishRequest{Group: "g"}); err == nil {
		t.Fatal("second rollout allowed while one waits")
	}
	if err := s.h.Approve("t", "g"); err != nil {
		t.Fatal(err)
	}
	if s.group().Desired != r.Version {
		t.Fatal("approval did not publish")
	}
	// canary with hold
	mustWrite(t, s.e.dir, "proxy/new3.config", `{"RootOrMatchingDomain":"new3"}`)
	r2, err := s.h.Publish("t", PublishRequest{Group: "g", Strategy: StrategyCanary, HoldForApproval: true, HealthySeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	s.beat(r2.CanaryNode, s.applied(r2.CanaryNode))
	s.e.clock.Add(15 * time.Second)
	s.beat(r2.CanaryNode, nil)
	if s.group().Rollout.State != RolloutAwaitPromotion || s.group().Desired == r2.Version {
		t.Fatalf("hold not respected: %+v", s.group().Rollout)
	}
	if err := s.h.Approve("t", "g"); err != nil || s.group().Desired != r2.Version {
		t.Fatalf("approve after hold failed: %v", err)
	}
	// abort
	mustWrite(t, s.e.dir, "proxy/new4.config", `{"RootOrMatchingDomain":"new4"}`)
	s.h.Publish("t", PublishRequest{Group: "g", Strategy: StrategyManual})
	if err := s.h.Abort("t", "g"); err != nil || s.group().Rollout.State != RolloutAborted {
		t.Fatal("abort failed")
	}
}

func TestVersionHistoryDiffAndRollback(t *testing.T) {
	s := newSim(t, "a")
	h := s.h
	r1, _ := h.Publish("t", PublishRequest{Group: "g"})
	mustWrite(t, s.e.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a2.example.com"}`)
	os.Remove(filepath.Join(s.e.dir, "proxy", "b.config"))
	mustWrite(t, s.e.dir, "proxy/c.config", `{"RootOrMatchingDomain":"c"}`)
	r2, _ := h.Publish("t", PublishRequest{Group: "g"})
	if r2.Version <= r1.Version {
		t.Fatal("version ids not increasing")
	}
	d, err := h.Diff(r1.Version, r2.Version)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, x := range d {
		got[x.Path] = x.Change
	}
	if got["proxy/a.config"] != "changed" || got["proxy/b.config"] != "removed" || got["proxy/c.config"] != "added" {
		t.Fatalf("diff %v", got)
	}
	for _, x := range d {
		if x.Path == "proxy/a.config" && (!strings.Contains(x.Old, "a.example.com") || !strings.Contains(x.New, "a2.example.com")) {
			t.Fatal("diff content missing")
		}
	}
	// one click rollback goes back to the previous stable version
	rb, err := h.Rollback("t", "g", 0, StrategyImmediate)
	if err != nil {
		t.Fatal(err)
	}
	if s.group().Desired != r1.Version || rb.Version != r1.Version {
		t.Fatalf("rollback went to v%d want v%d", s.group().Desired, r1.Version)
	}
	// identical capture does not create a new version
	n := len(h.st.Versions)
	if _, created, _ := h.Capture("t", ""); created {
		t.Fatal("capture of unchanged config created a version")
	}
	if len(h.st.Versions) != n {
		t.Fatal("version count changed")
	}
	// retention keeps referenced versions
	h.SetSettings("t", HubSettings{KeepVersions: 2, HeartbeatSecs: 20, HealthGraceSec: 30})
	for i := 0; i < 4; i++ {
		mustWrite(t, s.e.dir, "proxy/z.config", `{"RootOrMatchingDomain":"z`+string(rune('a'+i))+`"}`)
		h.Capture("t", "")
	}
	if len(h.st.Versions) > 3 {
		t.Fatalf("history not pruned: %d", len(h.st.Versions))
	}
	if _, ok := h.versionMeta(r1.Version); !ok {
		t.Fatal("version in use was pruned")
	}
	if err := h.Preflight("g", r1.Version); err != nil {
		t.Fatalf("kept version unusable: %v", err)
	}
}

func TestDriftAndAggregation(t *testing.T) {
	s := newSim(t, "a", "b")
	r, _ := s.h.Publish("t", PublishRequest{Group: "g"})
	s.beat("a", s.applied("a"))
	s.beat("b", func(hb *fleetHeartbeat) { hb.AppliedHash = "something-else"; hb.AppliedVer = r.Version - 1 })
	ov := s.h.Overview()
	byID := map[string]NodeView{}
	for _, n := range ov["nodes"].([]NodeView) {
		byID[n.ID] = n
	}
	if byID["a"].Drift || !byID["b"].Drift {
		t.Fatalf("drift a=%v b=%v", byID["a"].Drift, byID["b"].Drift)
	}
	if byID["a"].Status != StatusOnline {
		t.Fatalf("status %s", byID["a"].Status)
	}
	// local edit of a managed file shows as drift too
	s.beat("a", func(hb *fleetHeartbeat) { hb.LocalDrift = true })
	for _, n := range s.h.Overview()["nodes"].([]NodeView) {
		if n.ID == "a" && !n.Drift {
			t.Fatal("local drift not reported")
		}
	}

	// status by heartbeat age
	s.e.clock.Add(2 * time.Minute)
	if st := s.h.Overview()["nodes"].([]NodeView)[0].Status; st != StatusDegraded {
		t.Fatalf("2 min old heartbeat is %s", st)
	}
	s.e.clock.Add(5 * time.Minute)
	if st := s.h.Overview()["nodes"].([]NodeView)[0].Status; st != StatusOffline {
		t.Fatalf("7 min old heartbeat is %s", st)
	}

	// rates and aggregation from cumulative counters
	s2 := newSim(t, "x", "y")
	clk := s2.e.clock
	for i, id := range []string{"x", "y"} {
		base := uint64(1000 * (i + 1))
		s2.beat(id, func(hb *fleetHeartbeat) {
			hb.Stats = NodeStats{Health: "ok", Requests: base, Errors: 0, WAFEvents: 0, Endpoints: 3, WAFMode: "block"}
		})
	}
	clk.Add(60 * time.Second)
	s2.beat("x", func(hb *fleetHeartbeat) {
		hb.Stats = NodeStats{Health: "ok", Requests: 1600, Errors: 60, WAFEvents: 6, Endpoints: 3, WAFMode: "block"}
	})
	s2.beat("y", func(hb *fleetHeartbeat) {
		hb.Stats = NodeStats{Health: "ok", Requests: 2300, Errors: 0, WAFEvents: 0, Endpoints: 3, WAFMode: "detection_only"}
	})
	agg := s2.h.Overview()["aggregate"].(Aggregate)
	if agg.ReqPerMin < 899 || agg.ReqPerMin > 901 || agg.ErrPerMin < 59 || agg.ErrPerMin > 61 {
		t.Fatalf("rates req=%v err=%v", agg.ReqPerMin, agg.ErrPerMin)
	}
	if agg.ErrorRate < 0.066 || agg.ErrorRate > 0.067 || agg.Endpoints != 6 || agg.WAFByMode["block"] != 1 || agg.WAFByMode["detection_only"] != 1 {
		t.Fatalf("aggregate %+v", agg)
	}
	// a counter reset (node restart) does not produce negative or huge rates
	clk.Add(60 * time.Second)
	s2.beat("x", func(hb *fleetHeartbeat) { hb.Stats = NodeStats{Health: "ok", Requests: 30} })
	for _, n := range s2.h.Overview()["nodes"].([]NodeView) {
		if n.ID == "x" && (n.ReqPerMin < 0 || n.ReqPerMin > 31) {
			t.Fatalf("rate after reset %v", n.ReqPerMin)
		}
	}
}

func TestAuditLog(t *testing.T) {
	e := newFleetEnv(t)
	e.addNode("node-a", "g1")
	e.hub.hub.RotateNode("alice", "node-a")
	e.hub.hub.RevokeNode("bob", "node-a")
	log := e.hub.hub.AuditLog(50)
	var seen = map[string]string{}
	for _, a := range log {
		seen[a.Action] = a.Actor
	}
	if seen["node.rotate-key"] != "alice" || seen["node.revoke"] != "bob" || seen["join"] == "" || seen["join-token.create"] != "tester" {
		t.Fatalf("audit %v", seen)
	}
	b, _ := os.ReadFile(e.hub.hub.auditFile())
	if bytes.Contains(b, []byte(e.hub.hub.st.Nodes["node-a"].Key)) {
		t.Fatal("key in audit log")
	}
	// survives a restart
	m2, _ := NewManager(Options{ConfDir: e.dir, NodeID: "hub-1", Now: e.clock.Now})
	if len(m2.hub.AuditLog(50)) != len(log) {
		t.Fatal("audit log lost on restart")
	}
	if len(m2.hub.st.Nodes) != 1 || m2.Role() != RoleHub {
		t.Fatal("hub state lost on restart")
	}
}

// ---------------------------------------------------------------------
// registry

type fakeScope struct {
	committed, undone atomic.Int32
	failCommit        bool
}

func (f *fakeScope) Name() string  { return "extdb" }
func (f *fakeScope) Label() string { return "WAF" }
func (f *fakeScope) OwnsPath(p string) bool {
	return strings.HasPrefix(p, "waf:")
}
func (f *fakeScope) Export(env *ScopeEnv, sel Selection) ([]FileEntry, error) {
	return []FileEntry{{Path: "waf:policy.json", Data: []byte(`{"mode":"block"}`)}}, nil
}
func (f *fakeScope) Validate(items []FileEntry) error {
	for _, i := range items {
		if !strings.HasPrefix(i.Path, "waf:") {
			return errors.New("bad item")
		}
	}
	return nil
}
func (f *fakeScope) Apply(env *ScopeEnv, items []FileEntry, prev []string) (*ScopePlan, error) {
	return &ScopePlan{Commit: func() error {
		if f.failCommit {
			return errors.New("db down")
		}
		f.committed.Add(1)
		return nil
	}, Undo: func() { f.undone.Add(1) }}, nil
}

func TestPluggableScope(t *testing.T) {
	fs := &fakeScope{}
	RegisterScope(fs)
	defer UnregisterScope("extdb")
	e := newFleetEnv(t)
	n := e.addNode("node-a", "g1")
	e.setGroup("g1", []string{"extdb"})
	e.publish("g1", StrategyImmediate)
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	if fs.committed.Load() != 1 {
		t.Fatal("non file scope was not applied")
	}
	// a failing reload undoes the scope commit and keeps the old state
	n.fail.Store(true)
	fs.committed.Store(0)
	e.hub.hub.SetNodeVars("t", "node-a", map[string]string{"x": "1"}) // changes the bundle hash
	if err := n.sync(t); err == nil {
		t.Fatal("reload failure not reported")
	}
	if fs.undone.Load() != 1 {
		t.Fatal("scope commit not undone after reload failure")
	}
	// a failing commit leaves the files alone
	n.fail.Store(false)
	fs.failCommit = true
	mustWrite(t, n.dir, "proxy/local.config", `{"keep":1}`)
	if err := n.sync(t); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("commit failure: %v", err)
	}
}

func TestApplyFailureRollsBackAndReports(t *testing.T) {
	e := newFleetEnv(t)
	n := e.addNode("node-a", "g1")
	e.setGroup("g1", []string{"proxy"})
	e.publish("g1", StrategyImmediate)
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	before := fileAt(n.dir, "proxy/a.config")
	mustWrite(t, e.dir, "proxy/a.config", `{"RootOrMatchingDomain":"changed"}`)
	e.publish("g1", StrategyImmediate)
	n.fail.Store(true)
	if err := n.sync(t); err == nil {
		t.Fatal("expected failure")
	}
	if fileAt(n.dir, "proxy/a.config") != before {
		t.Fatal("files not rolled back after a failed reload")
	}
	n.heartbeat(t)
	_, want := e.hub.hub.DesiredHash("node-a")
	rt := e.hub.hub.rt["node-a"]
	if rt.HB.AttemptHash != want || rt.HB.LastResult != "error" {
		t.Fatalf("failure not reported: %+v", rt.HB)
	}
}

// ---------------------------------------------------------------------
// legacy mode

func TestLegacyModesUnchanged(t *testing.T) {
	p := newPair(t, false)
	if p.primary.Role() != RolePrimary || p.follower.Role() != RoleFollower {
		t.Fatal("roles")
	}
	if err := p.follower.SyncOnce(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p.fDir, "proxy/a.config") != `{"RootOrMatchingDomain":"a.example.com"}` {
		t.Fatal("legacy sync broke")
	}
	// the fleet endpoints do not exist on a legacy primary
	resp, _ := http.Post(p.server.URL+FleetJoinPath, "application/json", strings.NewReader("{}"))
	if resp != nil && resp.StatusCode == 200 {
		t.Fatal("legacy primary answers fleet endpoints")
	}
	// legacy nodes cannot be switched to node without credentials, and cannot join while in legacy mode
	role := RoleNode
	if err := p.follower.Update(ConfigUpdate{Role: &role}); err == nil {
		t.Fatal("node role without credentials accepted")
	}
	if err := p.follower.Join(context.Background(), JoinRequest{HubURL: "http://127.0.0.1:1", Token: "x", AllowHTTP: true}); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("join in legacy mode: %v", err)
	}
	if p.follower.FleetInfo().Managed {
		t.Fatal("legacy follower reports fleet management")
	}
}

func TestJoinSecurityChecks(t *testing.T) {
	m, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "n"})
	if err := m.Join(context.Background(), JoinRequest{HubURL: "http://hub:8000", Token: "x"}); err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("plain http join allowed without opt-in: %v", err)
	}
	if err := m.Join(context.Background(), JoinRequest{HubURL: "https://user:pw@hub:8000", Token: "x"}); err == nil {
		t.Fatal("credentials in url accepted")
	}
	if err := m.Join(context.Background(), JoinRequest{HubURL: "https://hub:8000", Token: "x", Fingerprint: "zz"}); err == nil {
		t.Fatal("bad fingerprint accepted")
	}
	// a node never keeps credentials from a failed join
	if _, err := os.Stat(m.nodeCredFile()); err == nil {
		t.Fatal("credentials stored after failed join")
	}
}

func TestTLSPinningOnJoin(t *testing.T) {
	e := newFleetEnv(t)
	ts := httptest.NewTLSServer(e.hub.FleetHandler())
	defer ts.Close()
	probe, err := ProbeHub(context.Background(), ts.URL)
	if err != nil || !probe.HTTPS || len(probe.Fingerprint) != 64 || probe.TrustedByCA {
		t.Fatalf("probe %+v %v", probe, err)
	}
	mk := func() *Manager {
		m, _ := NewManager(Options{ConfDir: t.TempDir(), NodeID: "pinned", NodeName: "p", Now: e.clock.Now})
		t.Cleanup(m.Stop)
		return m
	}
	tok := func() string { s, _, _ := e.hub.hub.CreateJoinToken("t", time.Minute, "", ""); return s }
	// no pin and a self-signed cert: refused
	if err := mk().Join(context.Background(), JoinRequest{HubURL: ts.URL, Token: tok()}); err == nil {
		t.Fatal("self-signed hub accepted without a pin")
	}
	// wrong pin: refused
	if err := mk().Join(context.Background(), JoinRequest{HubURL: ts.URL, Token: tok(), Fingerprint: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("wrong pin accepted")
	}
	// right pin: works, and the pin is stored for later requests
	m := mk()
	if err := m.Join(context.Background(), JoinRequest{HubURL: ts.URL, Token: tok(), Fingerprint: probe.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	if m.Config().PrimaryFingerprint != probe.Fingerprint || !m.FleetInfo().Pinned {
		t.Fatal("pin not stored")
	}
	if err := m.FleetSyncOnce(context.Background(), false); err != nil {
		t.Fatalf("sync over pinned TLS: %v", err)
	}
}

func TestHubAndTwoNodesEndToEnd(t *testing.T) {
	e := newFleetEnv(t)
	a := e.addNode("node-a", "edge")
	b := e.addNode("node-b", "edge")
	e.setGroup("edge", []string{"proxy", "redirect", "access", "streamproxy", "acme", "pathrules"})
	stable := e.publish("edge", StrategyImmediate)
	for _, n := range []*fnode{a, b} {
		if err := n.sync(t); err != nil {
			t.Fatal(err)
		}
		n.heartbeat(t)
	}
	for _, rel := range []string{"proxy/a.config", "redirect/r1.json", "access/default.json", "streamproxy/s1.config", "rules/pathrules/p1.json", "trusted_proxies.json", "acme_conf.json"} {
		if fileAt(a.dir, rel) != fileAt(e.dir, rel) || fileAt(b.dir, rel) != fileAt(e.dir, rel) {
			t.Fatalf("%s not mirrored", rel)
		}
	}
	// node specific data stays
	mustWrite(t, a.dir, "sys.uuid", "A")
	if fileAt(a.dir, "sys.uuid") != "A" || fileAt(a.dir, "certs/a.pem") != "<missing>" {
		t.Fatal("unmanaged data changed")
	}
	if a.reloads.Load() != 1 {
		t.Fatalf("expected one reload, got %d", a.reloads.Load())
	}
	// no change -> no reload
	a.sync(t)
	if a.reloads.Load() != 1 {
		t.Fatal("unchanged sync reloaded")
	}

	// canary: change the hub, node-a goes first
	mustWrite(t, e.dir, "proxy/a.config", `{"RootOrMatchingDomain":"a-v2.example.com"}`)
	r, err := e.hub.hub.Publish("t", PublishRequest{Group: "edge", Strategy: StrategyCanary, CanaryNode: "node-a", HealthySeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	b.sync(t)
	if !strings.Contains(fileAt(b.dir, "proxy/a.config"), "a.example.com") {
		t.Fatal("non canary node got the new version early")
	}
	a.sync(t)
	a.heartbeat(t)
	if !strings.Contains(fileAt(a.dir, "proxy/a.config"), "a-v2") {
		t.Fatal("canary did not apply")
	}
	e.clock.Add(35 * time.Second)
	a.heartbeat(t)
	e.clock.Add(35 * time.Second)
	a.heartbeat(t)
	if e.hub.hub.st.Groups["edge"].Desired != r.Version {
		t.Fatalf("not promoted: %+v", e.hub.hub.st.Groups["edge"].Rollout)
	}
	// the heartbeat tells node-b it is out of date
	rep, err := b.m.sendFleetHeartbeat(context.Background())
	if err != nil || rep.DesiredHash == "" {
		t.Fatalf("reply %+v %v", rep, err)
	}
	b.sync(t)
	b.heartbeat(t)
	if !strings.Contains(fileAt(b.dir, "proxy/a.config"), "a-v2") {
		t.Fatal("promotion did not reach node-b")
	}
	// rollback to the first version
	if _, err := e.hub.hub.Rollback("t", "edge", stable.Version, StrategyImmediate); err != nil {
		t.Fatal(err)
	}
	a.sync(t)
	b.sync(t)
	a.heartbeat(t)
	b.heartbeat(t)
	if !strings.Contains(fileAt(b.dir, "proxy/a.config"), `"a.example.com"`) || !strings.Contains(fileAt(a.dir, "proxy/a.config"), `"a.example.com"`) {
		t.Fatal("rollback not applied")
	}
	for _, n := range e.hub.hub.Overview()["nodes"].([]NodeView) {
		if n.Drift || n.Status != StatusOnline || n.Endpoints != 2 || n.WAFMode != "block" {
			t.Fatalf("node view %+v", n)
		}
	}
	// node UI info
	info := a.m.FleetInfo()
	if !info.Managed || info.Group != "edge" || len(info.ProxyKeys) == 0 {
		t.Fatalf("fleet info %+v", info)
	}
	// leaving keeps the files as local config
	if err := a.m.Leave(); err != nil {
		t.Fatal(err)
	}
	if a.m.Role() != RoleStandalone || fileAt(a.dir, "proxy/a.config") == "<missing>" {
		t.Fatal("leave removed managed files or kept the role")
	}
	if _, err := os.Stat(a.m.nodeCredFile()); err == nil {
		t.Fatal("node key kept after leaving")
	}
}

func TestEditGuardForManagedObjects(t *testing.T) {
	e := newFleetEnv(t)
	n := e.addNode("node-a", "g")
	mustWrite(t, n.dir, "proxy/local.config", `{"RootOrMatchingDomain":"local.example.com"}`)
	e.setGroup("g", []string{"proxy", "redirect"})
	e.publish("g", StrategyImmediate)
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	h := n.m.GuardLocalEdits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	do := func(method, path, body string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if do("POST", "/api/proxy/edit", "ep=a") != 403 {
		t.Fatal("managed proxy rule editable")
	}
	if do("POST", "/api/proxy/edit", "ep=local.example.com") != 200 && do("POST", "/api/proxy/edit", "ep=local") != 200 {
		t.Fatal("node local proxy rule blocked")
	}
	if do("POST", "/api/redirect/add", "x=1") != 403 {
		t.Fatal("managed redirect scope editable")
	}
	if do("POST", "/api/streamprox/add", "x=1") != 200 {
		t.Fatal("unmanaged scope blocked")
	}
	if do("GET", "/api/redirect/list", "") != 200 {
		t.Fatal("reads must pass")
	}
}

// The central WAF policy and profiles live in <conf>/waf_central.json; the hub
// can push them to nodes with the built-in "waf" scope.
func TestWAFScopeSyncsCentralPolicy(t *testing.T) {
	found := false
	for _, si := range ScopeList() {
		if si.Name == "waf" {
			found = true
		}
	}
	if !found {
		t.Fatal(`built-in "waf" scope is not registered`)
	}
	e := newFleetEnv(t)
	n := e.addNode("node-a", "g1")
	e.setGroup("g1", []string{"waf"})
	mustWrite(t, e.dir, "waf_central.json", `{"Policy":{"Enabled":true,"Mode":"detection_only"},"Profiles":[]}`)
	mustWrite(t, n.dir, "proxy/local.config", `{"keep":1}`) // local, unmanaged: must survive
	e.publish("g1", StrategyImmediate)
	if err := n.sync(t); err != nil {
		t.Fatal(err)
	}
	if got := fileAt(n.dir, "waf_central.json"); !strings.Contains(got, "detection_only") {
		t.Fatalf("node did not receive the central WAF policy: %q", got)
	}
	if fileAt(n.dir, "proxy/local.config") == "<missing>" {
		t.Fatal("unmanaged local proxy rule was touched by the waf scope")
	}
	// A node outside the group must not receive it.
	other := e.addNode("node-b", "g2")
	e.setGroup("g2", []string{"proxy"})
	e.publish("g2", StrategyImmediate)
	if err := other.sync(t); err != nil {
		t.Fatal(err)
	}
	if fileAt(other.dir, "waf_central.json") != "<missing>" {
		t.Fatal("node in another group received the WAF policy")
	}
}

func TestPausedNodeGetsNothingAndKeepsDetails(t *testing.T) {
	s := newSim(t, "a", "b")
	if _, err := s.h.Publish("t", PublishRequest{Group: "g"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.h.DesiredHash("a"); v == 0 {
		t.Fatal("a synced node should have a desired version")
	}
	if err := s.h.SetNodePaused("t", "a", true); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.h.DesiredHash("a"); v != 0 {
		t.Fatalf("paused node desired version = %d, want 0", v)
	}
	if v, _ := s.h.DesiredHash("b"); v == 0 {
		t.Fatal("pausing a must not affect b")
	}
	if _, err := s.h.pickCanaryLocked("g", "a"); err == nil {
		t.Fatal("a paused node must not be a canary")
	}
	if err := s.h.SetNodePaused("t", "a", false); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.h.DesiredHash("a"); v == 0 {
		t.Fatal("resuming sync should restore the desired version")
	}

	for _, bad := range []string{"javascript:alert(1)", "ftp://x", "http://"} {
		if err := s.h.SetNodeInfo("t", "a", "", bad, ""); err == nil {
			t.Fatalf("admin address %q must be rejected", bad)
		}
	}
	if err := s.h.SetNodeInfo("t", "a", "edge-1", "https://10.1.0.25:3000", "rack 2"); err != nil {
		t.Fatal(err)
	}
	n := s.h.st.Nodes["a"]
	if n.Name != "edge-1" || n.AdminURL != "https://10.1.0.25:3000" || n.Notes != "rack 2" {
		t.Fatalf("node = %+v", n)
	}
}
