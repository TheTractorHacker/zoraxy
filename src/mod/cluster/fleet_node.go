package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

/*
	Fleet node side

	A node enrolls with a one time join token and receives its own random
	node key (<conf>/.cluster/fleet-node.json, 0600, never logged, never
	synced). From then on it polls the hub for a bundle sealed with that key
	and sends heartbeats. The node never executes anything the hub sends: a
	bundle is data that is validated, applied atomically and rolled back
	locally on any failure. Only scopes the hub manages are touched.
*/

type nodeCreds struct {
	HubID    string `json:"hubId"`
	NodeKey  string `json:"nodeKey"`
	Group    string `json:"group"`
	JoinedAt int64  `json:"joinedAt"`
}

func (m *Manager) nodeCredFile() string {
	return filepath.Join(m.opt.ConfDir, StateDirName, "fleet-node.json")
}

func (m *Manager) loadCreds() (nodeCreds, bool) {
	m.mu.RLock()
	if m.creds.NodeKey != "" {
		c := m.creds
		m.mu.RUnlock()
		return c, true
	}
	m.mu.RUnlock()
	b, err := os.ReadFile(m.nodeCredFile())
	if err != nil {
		return nodeCreds{}, false
	}
	var c nodeCreds
	if json.Unmarshal(b, &c) != nil || c.NodeKey == "" {
		return nodeCreds{}, false
	}
	m.mu.Lock()
	m.creds = c
	m.mu.Unlock()
	return c, true
}

func (m *Manager) saveCreds(c nodeCreds) error {
	b, _ := json.Marshal(c)
	if err := writeFileAtomic(m.nodeCredFile(), b, 0o600); err != nil {
		return err
	}
	m.mu.Lock()
	m.creds = c
	m.mu.Unlock()
	return nil
}

// ProbeResult is what the join dialog shows before the admin confirms.
type ProbeResult struct {
	HTTPS       bool   `json:"https"`
	Fingerprint string `json:"fingerprint,omitempty"` //SHA-256 of the leaf certificate
	TrustedByCA bool   `json:"trustedByCA"`
	Subject     string `json:"subject,omitempty"`
	NotAfter    int64  `json:"notAfter,omitempty"`
}

// ProbeHub connects to the hub's admin port and reports its certificate so
// the admin can compare the fingerprint with the one shown on the hub.
func ProbeHub(ctx context.Context, rawURL string) (*ProbeResult, error) {
	if err := validatePrimaryURL(rawURL); err != nil {
		return nil, errors.New("hub URL must look like https://host:8000 (no credentials)")
	}
	u, _ := url.Parse(rawURL)
	if u.Scheme != "https" {
		return &ProbeResult{}, nil
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to the hub: %w", sanitizeErr(err))
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, errors.New("the hub presented no certificate")
	}
	leaf := st.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	res := &ProbeResult{HTTPS: true, Fingerprint: hex.EncodeToString(sum[:]), Subject: leaf.Subject.CommonName, NotAfter: leaf.NotAfter.Unix()}
	pool := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: u.Hostname(), Intermediates: pool}); err == nil {
		res.TrustedByCA = true
	}
	return res, nil
}

// JoinRequest is the node side of enrollment.
type JoinRequest struct {
	HubURL      string
	Token       string
	Fingerprint string //confirmed by the admin; required for https hubs with a self-signed certificate
	AllowHTTP   bool   //explicit opt in to an unencrypted hub URL
}

// Join enrolls this node at a hub. On success the node key is stored (0600)
// and the role switches to node.
func (m *Manager) Join(ctx context.Context, jr JoinRequest) error {
	hubURL := strings.TrimRight(strings.TrimSpace(jr.HubURL), "/")
	if err := validatePrimaryURL(hubURL); err != nil {
		return errors.New("hub URL must look like https://host:8000 (no credentials)")
	}
	u, _ := url.Parse(hubURL)
	if u.Scheme == "http" && !jr.AllowHTTP {
		return errors.New("the hub URL is plain http: the join token and node key would cross the network unencrypted. Use https (and pin the certificate), or confirm that you accept this")
	}
	pin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(jr.Fingerprint), ":", ""))
	if pin != "" && (len(pin) != 64 || !isHex(pin)) {
		return errors.New("fingerprint must be a SHA-256 hex string (64 characters)")
	}
	if m.Role() == RolePrimary || m.Role() == RoleFollower {
		return errors.New("this node uses the legacy shared-secret cluster mode; switch it to standalone before joining a fleet")
	}
	if m.Role() == RoleHub {
		return errors.New("a hub cannot join another hub")
	}
	body, _ := json.Marshal(map[string]string{"token": strings.TrimSpace(jr.Token), "nodeId": m.opt.NodeID, "name": m.opt.NodeName, "version": m.opt.Version})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hubURL+FleetJoinPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := m.opt.HTTPClient
	if client == nil {
		client = newPinnedClient(pin)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the hub: %w", sanitizeErr(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the hub refused the join (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(trimTo(string(raw), 200)))
	}
	var res JoinResult
	if json.Unmarshal(raw, &res) != nil || len(res.NodeKey) < 64 || res.NodeID != m.opt.NodeID {
		return errors.New("the hub answered with an unexpected join response")
	}
	if err := m.saveCreds(nodeCreds{HubID: res.HubID, NodeKey: res.NodeKey, Group: res.Group, JoinedAt: m.opt.Now().Unix()}); err != nil {
		return fmt.Errorf("cannot store the node key: %w", err)
	}
	role := RoleNode
	if err := m.Update(ConfigUpdate{Role: &role, PrimaryURL: &hubURL, PrimaryFingerprint: &pin}); err != nil {
		os.Remove(m.nodeCredFile())
		return err
	}
	m.mu.Lock()
	m.status.FleetGroup = res.Group
	m.saveStatusLocked()
	m.mu.Unlock()
	m.opt.Logf("[fleet] joined hub %s as node %s (group %s)", hubURL, m.opt.NodeID, res.Group)
	return nil
}

// Leave detaches the node from the hub. Everything the hub managed stays in
// place as ordinary local configuration.
func (m *Manager) Leave() error {
	if m.Role() != RoleNode {
		return errors.New("this node is not part of a fleet")
	}
	role := RoleStandalone
	if err := m.Update(ConfigUpdate{Role: &role}); err != nil {
		return err
	}
	os.Remove(m.nodeCredFile())
	m.mu.Lock()
	m.creds = nodeCreds{}
	m.status.Managed, m.status.ManagedHash, m.status.FleetScopes, m.status.Conflicts = nil, "", nil, nil
	m.status.AppliedHash, m.status.AttemptHash = "", ""
	m.saveStatusLocked()
	m.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------
// polling

func (m *Manager) fleetRequest(ctx context.Context, cfg Config, method, p string, body []byte) (*http.Request, error) {
	c, ok := m.loadCreds()
	if !ok {
		return nil, errors.New("this node has no hub credentials; join the fleet again")
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(cfg.PrimaryURL, "/")+p, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+MakeToken(c.NodeKey, method, p, m.opt.NodeID, m.opt.Now()))
	req.Header.Set("User-Agent", "zoraxy-fleet/"+m.opt.Version)
	return req, nil
}

func (m *Manager) fleetLoop(ctx context.Context) {
	wait := 3*time.Second + time.Duration(rand.Intn(3000))*time.Millisecond
	hb := DefaultHeartbeat
	var lastSync time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		syncEvery := time.Duration(m.Config().SyncIntervalSeconds) * time.Second
		if lastSync.IsZero() || m.opt.Now().Sub(lastSync) >= syncEvery {
			if err := m.FleetSyncOnce(ctx, false); err != nil {
				m.opt.Logf("[fleet] sync failed: %v", err)
			}
			lastSync = m.opt.Now()
		}
		reply, err := m.sendFleetHeartbeat(ctx)
		if err == nil && reply != nil {
			if reply.HeartbeatS >= 5 && reply.HeartbeatS <= 300 {
				hb = time.Duration(reply.HeartbeatS) * time.Second
			}
			m.mu.RLock()
			applied := m.status.AppliedHash
			m.mu.RUnlock()
			if reply.SyncNow || (reply.DesiredHash != "" && reply.DesiredHash != applied) {
				if err := m.FleetSyncOnce(ctx, false); err != nil {
					m.opt.Logf("[fleet] sync failed: %v", err)
				}
				lastSync = m.opt.Now()
				m.sendFleetHeartbeat(ctx)
			}
		}
		wait = hb + time.Duration(rand.Int63n(int64(hb)/5+1))
	}
}

func (m *Manager) sendFleetHeartbeat(ctx context.Context) (*fleetHeartbeatReply, error) {
	cfg := m.Config()
	m.mu.RLock()
	st := m.status
	m.mu.RUnlock()
	var stats NodeStats
	if m.opt.Stats != nil {
		stats = m.opt.Stats()
	}
	hb := fleetHeartbeat{Name: m.opt.NodeName, Version: m.opt.Version, AppliedVer: st.AppliedVersion, AppliedHash: st.AppliedHash,
		AttemptHash: st.AttemptHash, LastResult: st.LastResult, LastError: st.LastError, Conflicts: st.Conflicts,
		LocalDrift: m.localDrift(st), Stats: stats}
	for _, k := range st.Managed {
		hb.ManagedCount += len(k)
	}
	body, _ := json.Marshal(hb)
	req, err := m.fleetRequest(ctx, cfg, http.MethodPost, FleetHeartbeatPath, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.httpClient(cfg).Do(req)
	if err != nil {
		return nil, sanitizeErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("hub answered HTTP %d to the heartbeat", resp.StatusCode)
	}
	var reply fleetHeartbeatReply
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&reply) != nil {
		return nil, errors.New("bad heartbeat reply")
	}
	return &reply, nil
}

// localDrift reports whether managed files were edited on the node since the
// hub's configuration was applied.
func (m *Manager) localDrift(st followerStatus) bool {
	if st.ManagedHash == "" {
		return false
	}
	var files []FileEntry
	for _, keys := range st.Managed {
		for _, k := range keys {
			if !validEntryPath(k, ManagedRoots(true)) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(m.opt.ConfDir, filepath.FromSlash(k)))
			if err != nil {
				return true
			}
			files = append(files, FileEntry{Path: k, Data: b})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return HashFiles(files) != st.ManagedHash
}

// FleetSyncOnce fetches and applies the node's bundle.
func (m *Manager) FleetSyncOnce(ctx context.Context, force bool) error {
	cfg := m.Config()
	if cfg.Role != RoleNode {
		return errors.New("this node is not part of a fleet")
	}
	if !m.syncMu.TryLock() {
		return errors.New("a sync is already running")
	}
	defer m.syncMu.Unlock()
	m.mu.Lock()
	m.status.LastAttemptAt = m.opt.Now().Unix()
	have := m.status.AppliedHash
	m.mu.Unlock()

	result, err := m.fleetSync(ctx, cfg, have, force)
	m.mu.Lock()
	if err != nil {
		m.status.LastError = trunc(err.Error(), 300)
		m.status.LastResult = "error"
	} else {
		m.status.LastError = ""
		m.status.LastResult = result
		m.status.LastSuccessAt = m.opt.Now().Unix()
	}
	m.saveStatusLocked()
	m.mu.Unlock()
	return err
}

func (m *Manager) fleetSync(ctx context.Context, cfg Config, have string, force bool) (string, error) {
	c, ok := m.loadCreds()
	if !ok {
		return "", errors.New("this node has no hub credentials; join the fleet again")
	}
	req, err := m.fleetRequest(ctx, cfg, http.MethodGet, FleetConfigPath, nil)
	if err != nil {
		return "", err
	}
	if have != "" && !force {
		req.URL.RawQuery = "have=" + have
	}
	resp, err := m.httpClient(cfg).Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach hub: %w", sanitizeErr(err))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return "unchanged", nil
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusNotFound:
		return "", errors.New("hub rejected this node (revoked, removed, wrong hub URL or clock out of sync)")
	case http.StatusTooManyRequests:
		return "", errors.New("hub rate limited this node")
	default:
		return "", fmt.Errorf("hub answered HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxSnapshotBytes*2+1))
	if err != nil {
		return "", err
	}
	env, payload, err := Open(c.NodeKey, raw)
	if err != nil {
		return "", err
	}
	meta := payload.Fleet
	if meta == nil {
		return "", errors.New("hub answered with a non-fleet snapshot")
	}
	if c.HubID != "" && meta.HubID != c.HubID {
		return "", errors.New("the bundle comes from a different hub than the one this node joined")
	}
	if meta.Rotate != "" { //store the rotated key before anything can restart the process
		if len(meta.Rotate) < 64 || !isHex(meta.Rotate) {
			return "", errors.New("hub sent an invalid rotated key")
		}
		c.NodeKey = meta.Rotate
		if err := m.saveCreds(c); err != nil {
			return "", fmt.Errorf("cannot store the rotated node key: %w", err)
		}
		m.opt.Logf("[fleet] node key rotated")
	}
	m.mu.Lock()
	m.status.AttemptHash = meta.Hash
	m.status.FleetGroup = meta.Group
	m.mu.Unlock()
	return m.applyFleet(env, payload, force)
}

// applyFleet installs the managed scopes of a bundle, leaving everything the
// hub does not manage untouched.
func (m *Manager) applyFleet(env *Envelope, payload *Payload, force bool) (string, error) {
	meta := payload.Fleet
	m.mu.RLock()
	prev := m.status
	m.mu.RUnlock()

	if meta.NoConfig {
		return "unchanged", nil //nothing has been published to this group yet
	}
	if meta.Hash == prev.AppliedHash && !force {
		return "unchanged", nil
	}
	if meta.Hash == prev.RejectedHash && !force {
		return "", errors.New("this bundle previously prevented a clean start and was rolled back; waiting for the hub to publish a change")
	}

	vars := map[string]string{}
	for k, v := range meta.Vars {
		vars[k] = v
	}
	if err := ValidateVars(vars); err != nil {
		return "", fmt.Errorf("bundle rejected: %w", err)
	}
	vars["id"], vars["name"], vars["group"] = sanitizeVar(m.opt.NodeID), sanitizeVar(meta.NodeName), sanitizeVar(meta.Group)
	all := append(append([]FileEntry{}, payload.Files...), meta.Extra...)
	resolved, err := ResolveFiles(all, vars)
	if err != nil {
		return "", fmt.Errorf("bundle rejected: %w", err)
	}
	byScope := groupItems(resolved, nil)
	for _, it := range resolved {
		if _, ok := scopeForPath(it.Path); !ok {
			return "", fmt.Errorf("bundle contains %q, which no scope on this node handles (node is older than the hub?)", it.Path)
		}
	}

	senv := &ScopeEnv{ConfDir: m.opt.ConfDir}
	scopes := append([]string{}, meta.Scopes...)
	sort.Strings(scopes)
	var (
		files     []FileEntry
		roots     []string
		conflicts []Conflict
		managed   = map[string][]string{}
		commits   []*ScopePlan
		rootSeen  = map[string]bool{}
	)
	for _, name := range scopes {
		s, ok := GetScope(name)
		if !ok {
			return "", fmt.Errorf("the hub manages scope %q, which this node does not support", name)
		}
		items := byScope[name]
		if err := s.Validate(items); err != nil {
			return "", fmt.Errorf("bundle rejected by scope %s: %w", name, err)
		}
		plan, err := s.Apply(senv, items, prev.Managed[name])
		if err != nil {
			return "", fmt.Errorf("scope %s: %w", name, err)
		}
		for _, r := range plan.Roots {
			if rootSeen[r] {
				return "", fmt.Errorf("scope %s: root %q is claimed by two scopes", name, r)
			}
			rootSeen[r] = true
			roots = append(roots, r)
		}
		files = append(files, plan.Files...)
		conflicts = append(conflicts, plan.Conflicts...)
		managed[name] = plan.ManagedKeys
		commits = append(commits, plan)
	}
	sort.Strings(roots)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	merged := &Payload{Roots: roots, IncludesCerts: rootSeen[certRoot], Files: files}
	merged.ContentHash = HashFiles(merged.Files)
	if err := ValidatePayload(merged); err != nil {
		return "", fmt.Errorf("bundle rejected: %w", err)
	}
	if m.opt.Validate != nil {
		if err := m.opt.Validate(merged); err != nil {
			return "", fmt.Errorf("bundle rejected by validation, previous configuration kept: %w", err)
		}
	}

	managedHash := managedFilesHash(managed, files)
	setStatus := func(st *followerStatus) {
		st.AppliedVersion = meta.Version
		st.AppliedHash = meta.Hash
		st.AppliedAt = m.opt.Now().Unix()
		st.CertsSynced = merged.IncludesCerts
		st.Managed, st.ManagedHash, st.FleetScopes = managed, managedHash, scopes
		st.Conflicts, st.FleetGroup = conflicts, meta.Group
	}

	hooks := false
	for _, p := range commits {
		if p.Commit != nil {
			hooks = true
		}
	}
	if local, err := CollectFiles(m.opt.ConfDir, true); err == nil && !hooks {
		var cur []FileEntry
		for _, f := range local.Files {
			if rootSeen[strings.SplitN(f.Path, "/", 2)[0]] {
				cur = append(cur, f)
			}
		}
		if HashFiles(cur) == merged.ContentHash { //already identical on disk
			m.mu.Lock()
			setStatus(&m.status)
			m.saveStatusLocked()
			m.mu.Unlock()
			return "unchanged", nil
		}
	}

	ap := &Applier{ConfDir: m.opt.ConfDir}
	applied, err := ap.ApplyPayload(merged, BackupTag(m.opt.Now()))
	if err != nil {
		return "", fmt.Errorf("apply failed, previous configuration kept: %w", err)
	}
	var done []*ScopePlan
	undo := func() {
		for i := len(done) - 1; i >= 0; i-- {
			if done[i].Undo != nil {
				done[i].Undo()
			}
		}
	}
	for _, p := range commits {
		if p.Commit == nil {
			continue
		}
		if err := p.Commit(); err != nil {
			undo()
			applied.Rollback()
			return "", fmt.Errorf("apply failed, previous configuration kept: %w", err)
		}
		done = append(done, p)
	}
	return m.finishApply(applied, roots, meta.Hash, meta.Version, setStatus, undo,
		fmt.Sprintf("applied fleet bundle v%d (%d files, scopes %s)", meta.Version, len(files), strings.Join(scopes, ",")))
}

func sanitizeVar(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '-'
	}, s)
}

// managedFilesHash hashes the managed files as they will be on disk.
func managedFilesHash(managed map[string][]string, files []FileEntry) string {
	want := map[string]bool{}
	for _, keys := range managed {
		for _, k := range keys {
			want[k] = true
		}
	}
	var out []FileEntry
	for _, f := range files {
		if want[f.Path] {
			out = append(out, FileEntry{Path: f.Path, Data: f.Data})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return HashFiles(out)
}

// ---------------------------------------------------------------------
// read-only information for the node UI and the edit guard

// FleetNodeInfo is shown on the node ("managed by hub" badge).
type FleetNodeInfo struct {
	Managed    bool       `json:"managed"`
	HubURL     string     `json:"hubUrl,omitempty"`
	HubHost    string     `json:"hubHost,omitempty"`
	Pinned     bool       `json:"pinned"`
	Group      string     `json:"group,omitempty"`
	Scopes     []string   `json:"scopes,omitempty"`
	ProxyKeys  []string   `json:"managedProxyRules,omitempty"`
	Conflicts  []Conflict `json:"conflicts,omitempty"`
	Applied    int64      `json:"appliedVersion"`
	LastResult string     `json:"lastResult,omitempty"`
	LastError  string     `json:"lastError,omitempty"`
	LastOK     int64      `json:"lastSuccessAt"`
	Insecure   bool       `json:"insecureTransport"`
}

// FleetInfo describes the fleet state of this node.
func (m *Manager) FleetInfo() FleetNodeInfo {
	cfg := m.Config()
	if cfg.Role != RoleNode {
		return FleetNodeInfo{}
	}
	m.mu.RLock()
	st := m.status
	m.mu.RUnlock()
	info := FleetNodeInfo{Managed: true, HubURL: cfg.PrimaryURL, Pinned: cfg.PrimaryFingerprint != "", Group: st.FleetGroup, Scopes: st.FleetScopes,
		Conflicts: st.Conflicts, Applied: st.AppliedVersion, LastResult: st.LastResult, LastError: st.LastError, LastOK: st.LastSuccessAt}
	if u, err := url.Parse(cfg.PrimaryURL); err == nil {
		info.HubHost = u.Host
		info.Insecure = u.Scheme == "http"
	}
	for _, k := range st.Managed["proxy"] {
		info.ProxyKeys = append(info.ProxyKeys, strings.TrimSuffix(strings.TrimPrefix(k, "proxy/"), ".config"))
	}
	return info
}

// Admin API prefix of a managed scope, used by the edit guard.
var scopeAPIPrefixes = map[string][]string{
	"redirect":    {"/api/redirect/"},
	"access":      {"/api/access/", "/api/blacklist/", "/api/whitelist/", "/api/quickban/", "/api/trustedproxy/"},
	"pathrules":   {"/api/pathrule/"},
	"streamproxy": {"/api/streamprox/"},
	"acme":        {"/api/acme/autoRenew/"},
	"certs":       {"/api/cert/"},
}

// fleetBlocks reports the managed object a write request would modify, or "".
func (m *Manager) fleetBlocks(r *http.Request) string {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return ""
	}
	m.mu.RLock()
	st := m.status
	m.mu.RUnlock()
	p := r.URL.Path
	if p == "/api/conf/import" && len(st.FleetScopes) > 0 {
		return "configuration import"
	}
	for _, sc := range st.FleetScopes {
		for _, pre := range scopeAPIPrefixes[sc] {
			if strings.HasPrefix(p, pre) {
				return sc
			}
		}
	}
	if strings.HasPrefix(p, "/api/proxy/") && !nodeLocalProxyPaths[p] && len(st.Managed["proxy"]) > 0 {
		r.ParseForm()
		for _, f := range []string{"ep", "rootname", "domain"} {
			v := strings.TrimSpace(r.Form.Get(f))
			if v == "" {
				continue
			}
			for _, k := range st.Managed["proxy"] {
				if proxyFileKey(k) == v || proxyFileKey(k) == strings.ReplaceAll(v, "*", "_") {
					return "proxy rule " + v
				}
			}
		}
	}
	return ""
}

func proxyFileKey(p string) string {
	return strings.TrimSuffix(strings.TrimPrefix(p, "proxy/"), ".config")
}
