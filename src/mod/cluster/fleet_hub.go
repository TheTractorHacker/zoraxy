package cluster

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hub is the central management side. It is inert unless the node role is
// "hub"; the state file is only read, never created, otherwise.
type Hub struct {
	m *Manager

	mu    sync.Mutex
	st    hubState
	rt    map[string]*nodeRuntime
	audit []AuditEntry

	verifier    *TokenVerifier
	joinLimiter *RateLimiter
	syncLimiter *RateLimiter

	keyMu  sync.Mutex
	hubKey string

	cacheMu    sync.Mutex
	cache      map[int64]map[string][]FileEntry
	cacheOrder []int64
	hashMemo   map[string]string
}

func newHub(m *Manager) *Hub {
	h := &Hub{
		m:           m,
		rt:          map[string]*nodeRuntime{},
		verifier:    NewTokenVerifier(),
		joinLimiter: NewRateLimiter(joinRateLimit, time.Minute),
		syncLimiter: NewRateLimiter(fleetRateLimit, time.Minute),
		cache:       map[int64]map[string][]FileEntry{},
		hashMemo:    map[string]string{},
	}
	h.st = hubState{Nodes: map[string]*FleetNode{}, Groups: map[string]*FleetGroup{}, NextVer: 1}
	h.st.Settings = defaultHubSettings()
	if b, err := os.ReadFile(h.stateFile()); err == nil {
		var st hubState
		if json.Unmarshal(b, &st) == nil {
			h.st = st
			if h.st.Nodes == nil {
				h.st.Nodes = map[string]*FleetNode{}
			}
			if h.st.Groups == nil {
				h.st.Groups = map[string]*FleetGroup{}
			}
			if h.st.NextVer < 1 {
				h.st.NextVer = 1
			}
			if h.st.Settings.KeepVersions == 0 {
				h.st.Settings = defaultHubSettings()
			}
		}
	}
	h.loadAudit()
	return h
}

func defaultHubSettings() HubSettings {
	return HubSettings{KeepVersions: DefaultKeepVersions, HeartbeatSecs: int(DefaultHeartbeat / time.Second), HealthGraceSec: 30}
}

func (h *Hub) dir() string       { return filepath.Join(h.m.opt.ConfDir, StateDirName) }
func (h *Hub) stateFile() string { return filepath.Join(h.dir(), "fleet-hub.json") }
func (h *Hub) keyFile() string   { return filepath.Join(h.dir(), "fleet-hub.key") }
func (h *Hub) versionDir() string {
	return filepath.Join(h.dir(), "fleet", "versions")
}
func (h *Hub) now() time.Time { return h.m.opt.Now() }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("cluster: random source failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func writeFileAtomic(path string, b []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// saveLocked persists the structural state. Caller holds h.mu.
func (h *Hub) saveLocked() error {
	if h.st.HubID == "" {
		h.st.HubID = randHex(8)
	}
	b, err := json.MarshalIndent(&h.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(h.stateFile(), b, 0o600)
}

// HubID is the stable identifier of this hub.
func (h *Hub) HubID() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.st.HubID == "" {
		h.saveLocked()
	}
	return h.st.HubID
}

func (h *Hub) active() bool { return h.m.Role() == RoleHub }

func (h *Hub) key() (string, error) {
	h.keyMu.Lock()
	defer h.keyMu.Unlock()
	if h.hubKey != "" {
		return h.hubKey, nil
	}
	if b, err := os.ReadFile(h.keyFile()); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		h.hubKey = strings.TrimSpace(string(b))
		return h.hubKey, nil
	}
	k := randHex(32)
	if err := writeFileAtomic(h.keyFile(), []byte(k), 0o600); err != nil {
		return "", err
	}
	h.hubKey = k
	return k, nil
}

// ---------------------------------------------------------------------
// audit log

const (
	auditMemory  = 500
	auditMaxFile = 1 << 20
)

func (h *Hub) auditFile() string { return filepath.Join(h.dir(), "fleet-audit.jsonl") }

func (h *Hub) loadAudit() {
	b, err := os.ReadFile(h.auditFile())
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		var e AuditEntry
		if line != "" && json.Unmarshal([]byte(line), &e) == nil {
			h.audit = append(h.audit, e)
		}
	}
	if len(h.audit) > auditMemory {
		h.audit = h.audit[len(h.audit)-auditMemory:]
	}
}

// Audit records a hub action (who, when, what). It never stores secrets.
func (h *Hub) Audit(actor, action, target, detail string) {
	e := AuditEntry{At: h.now().Unix(), Actor: trimTo(actor, 64), Action: trimTo(action, 48), Target: trimTo(target, 96), Detail: trimTo(detail, 300)}
	h.mu.Lock()
	h.auditLocked(e)
	h.mu.Unlock()
}

func (h *Hub) auditLocked(e AuditEntry) {
	h.audit = append(h.audit, e)
	if len(h.audit) > auditMemory {
		h.audit = h.audit[len(h.audit)-auditMemory:]
	}
	line, _ := json.Marshal(e)
	os.MkdirAll(h.dir(), 0o700)
	if fi, err := os.Stat(h.auditFile()); err == nil && fi.Size() > auditMaxFile {
		var buf []byte
		for _, x := range h.audit {
			l, _ := json.Marshal(x)
			buf = append(append(buf, l...), '\n')
		}
		os.WriteFile(h.auditFile(), buf, 0o600)
		return
	}
	f, err := os.OpenFile(h.auditFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
}

// AuditLog returns the newest entries first.
func (h *Hub) AuditLog(limit int) []AuditEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	if limit <= 0 || limit > len(h.audit) {
		limit = len(h.audit)
	}
	out := make([]AuditEntry, 0, limit)
	for i := len(h.audit) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, h.audit[i])
	}
	return out
}

// ---------------------------------------------------------------------
// join tokens and enrollment

var (
	ErrJoinInvalid = errors.New("invalid or expired join token")
	dummyTokenHash = hex.EncodeToString(make([]byte, 32))
)

func tokenSecretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CreateJoinToken makes a one time enrollment token. The returned string is
// shown once; only its hash is kept.
func (h *Hub) CreateJoinToken(by string, ttl time.Duration, nodeName, group string) (string, JoinToken, error) {
	if !h.active() {
		return "", JoinToken{}, errors.New("this node is not a fleet hub")
	}
	if ttl <= 0 {
		ttl = DefaultJoinTokenTTL
	}
	if ttl > MaxJoinTokenTTL {
		return "", JoinToken{}, errors.New("join tokens may live at most 24 hours")
	}
	if !nodeNamePattern.MatchString(nodeName) {
		return "", JoinToken{}, errors.New("node name may contain letters, digits, space . _ - (max 64)")
	}
	if group != "" && !groupNamePattern.MatchString(group) {
		return "", JoinToken{}, errors.New("group name must match [A-Za-z0-9_-]{1,32}")
	}
	id, secret := randHex(4), randHex(16)
	now := h.now()
	t := JoinToken{ID: id, Hash: tokenSecretHash(secret), CreatedAt: now.Unix(), CreatedBy: trimTo(by, 64),
		ExpiresAt: now.Add(ttl).Unix(), NodeName: strings.TrimSpace(nodeName), Group: group}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneTokensLocked(now)
	open := 0
	for _, x := range h.st.Tokens {
		if x.UsedAt == 0 && !x.Revoked {
			open++
		}
	}
	if open >= maxJoinTokens {
		return "", JoinToken{}, errors.New("too many open join tokens; revoke some first")
	}
	h.st.Tokens = append(h.st.Tokens, t)
	if err := h.saveLocked(); err != nil {
		h.st.Tokens = h.st.Tokens[:len(h.st.Tokens)-1]
		return "", JoinToken{}, err
	}
	h.auditLocked(AuditEntry{At: now.Unix(), Actor: by, Action: "join-token.create", Target: id,
		Detail: fmt.Sprintf("expires %s group=%q name=%q", time.Unix(t.ExpiresAt, 0).UTC().Format(time.RFC3339), group, t.NodeName)})
	return "zj1." + id + "." + secret, t, nil
}

func (h *Hub) pruneTokensLocked(now time.Time) {
	keep := h.st.Tokens[:0]
	for _, t := range h.st.Tokens {
		dead := (t.UsedAt != 0 && now.Unix()-t.UsedAt > 86400) || (t.UsedAt == 0 && now.Unix()-t.ExpiresAt > 86400)
		if !dead {
			keep = append(keep, t)
		}
	}
	h.st.Tokens = keep
}

// RevokeJoinToken invalidates an unused token.
func (h *Hub) RevokeJoinToken(by, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.st.Tokens {
		if h.st.Tokens[i].ID == id {
			h.st.Tokens[i].Revoked = true
			h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "join-token.revoke", Target: id})
			return h.saveLocked()
		}
	}
	return errors.New("no such join token")
}

// JoinResult is returned to a node that enrolled.
type JoinResult struct {
	NodeID        string `json:"nodeId"`
	NodeKey       string `json:"nodeKey"`
	Group         string `json:"group"`
	HubID         string `json:"hubId"`
	HeartbeatSecs int    `json:"heartbeatSecs"`
}

// Join redeems a join token. A token works exactly once; the check, the
// consumption and the persistence happen under one lock.
func (h *Hub) Join(token, nodeID, name, version, addr string) (*JoinResult, error) {
	if !h.active() {
		return nil, ErrJoinInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "zj1" || !nonceHex8.MatchString(parts[1]) || len(parts[2]) != 32 {
		return nil, ErrJoinInvalid
	}
	if !nodeIDPattern.MatchString(nodeID) {
		return nil, errors.New("invalid node id")
	}
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	var tok *JoinToken
	for i := range h.st.Tokens {
		if h.st.Tokens[i].ID == parts[1] {
			tok = &h.st.Tokens[i]
		}
	}
	want := dummyTokenHash
	if tok != nil {
		want = tok.Hash
	}
	match := subtle.ConstantTimeCompare([]byte(tokenSecretHash(parts[2])), []byte(want)) == 1
	if tok == nil || !match || tok.UsedAt != 0 || tok.Revoked || now.Unix() > tok.ExpiresAt {
		h.auditLocked(AuditEntry{At: now.Unix(), Actor: "node:" + trimTo(addr, 45), Action: "join.denied", Target: trimTo(nodeID, 64)})
		return nil, ErrJoinInvalid
	}
	group := tok.Group
	if group == "" {
		group = defaultGroup
	}
	if _, ok := h.st.Groups[group]; !ok {
		if len(h.st.Groups) >= maxFleetGroups {
			return nil, errors.New("group limit reached")
		}
		h.st.Groups[group] = &FleetGroup{Name: group}
	}
	n, existed := h.st.Nodes[nodeID]
	if !existed && len(h.st.Nodes) >= maxFleetNodes {
		return nil, errors.New("node limit reached")
	}
	if !nodeNamePattern.MatchString(name) {
		name = ""
	}
	if tok.NodeName != "" {
		name = tok.NodeName
	}
	if name == "" {
		name = nodeID
	}
	prev := *tok
	prevNode := n
	if !existed {
		n = &FleetNode{ID: nodeID}
		h.st.Nodes[nodeID] = n
	}
	n.Name, n.Group, n.Key, n.NextKey = name, group, randHex(32), ""
	n.Revoked, n.RevokedAt, n.JoinedAt = false, 0, now.Unix()
	tok.UsedAt, tok.UsedBy = now.Unix(), nodeID
	if err := h.saveLocked(); err != nil {
		*tok = prev
		if existed {
			h.st.Nodes[nodeID] = prevNode
		} else {
			delete(h.st.Nodes, nodeID)
		}
		return nil, errors.New("hub could not persist the enrollment")
	}
	h.rtFor(nodeID).Version = trimTo(version, 32)
	h.auditLocked(AuditEntry{At: now.Unix(), Actor: "node:" + trimTo(addr, 45), Action: "join", Target: nodeID, Detail: "group=" + group + " token=" + tok.ID})
	return &JoinResult{NodeID: nodeID, NodeKey: n.Key, Group: group, HubID: h.st.HubID, HeartbeatSecs: h.st.Settings.HeartbeatSecs}, nil
}

var nonceHex8 = nonceHexN(8)

func (h *Hub) rtFor(id string) *nodeRuntime {
	r := h.rt[id]
	if r == nil {
		r = &nodeRuntime{}
		h.rt[id] = r
	}
	return r
}

// ---------------------------------------------------------------------
// per node authentication

var errNodeAuth = errors.New("unauthorized")

// authNode verifies a bearer token against the node's key. Revoked and
// unknown nodes fail with the same error (and comparable work). When a node
// authenticates with a staged rotation key the rotation is completed.
func (h *Hub) authNode(token, method, urlPath string, now time.Time) (*FleetNode, string, error) {
	nodeID, ok := TokenNode(token)
	if !ok {
		return nil, "", errNodeAuth
	}
	h.mu.Lock()
	n := h.st.Nodes[nodeID]
	var cp FleetNode
	if n != nil {
		cp = *n
	}
	h.mu.Unlock()
	if n == nil || cp.Revoked {
		h.verifier.Verify(dummyTokenHash, method, urlPath, token, now) //equalise timing
		return nil, "", errNodeAuth
	}
	keys := []string{cp.Key}
	if cp.NextKey != "" {
		keys = append(keys, cp.NextKey)
	}
	for i, k := range keys {
		if _, err := h.verifier.Verify(k, method, urlPath, token, now); err == nil {
			if i == 1 { //the node picked up the rotated key: the old one dies now
				h.mu.Lock()
				if cur := h.st.Nodes[nodeID]; cur != nil && cur.NextKey == k {
					cur.Key, cur.NextKey = k, ""
					h.saveLocked()
					h.auditLocked(AuditEntry{At: now.Unix(), Actor: "node:" + nodeID, Action: "key.rotated", Target: nodeID})
				}
				h.mu.Unlock()
			}
			return &cp, k, nil
		} else if errors.Is(err, ErrTokenReplayed) || errors.Is(err, ErrTokenExpired) {
			return nil, "", errNodeAuth
		}
	}
	return nil, "", errNodeAuth
}

// ---------------------------------------------------------------------
// node management actions

func (h *Hub) node(id string) (*FleetNode, error) {
	n := h.st.Nodes[id]
	if n == nil {
		return nil, errors.New("no such node")
	}
	return n, nil
}

// RevokeNode makes the node's credentials useless immediately.
func (h *Hub) RevokeNode(by, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.node(id)
	if err != nil {
		return err
	}
	n.Revoked, n.RevokedAt, n.NextKey = true, h.now().Unix(), ""
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "node.revoke", Target: id})
	return h.saveLocked()
}

// RotateNode stages a new node key. It is delivered inside the next sealed
// config response and takes over when the node authenticates with it.
func (h *Hub) RotateNode(by, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.node(id)
	if err != nil {
		return err
	}
	if n.Revoked {
		return errors.New("node is revoked; enroll it again with a new join token")
	}
	n.NextKey = randHex(32)
	h.rtFor(id).SyncRequest = true
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "node.rotate-key", Target: id})
	return h.saveLocked()
}

// RemoveNode deletes the node record (its credentials stop working).
func (h *Hub) RemoveNode(by, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.node(id); err != nil {
		return err
	}
	delete(h.st.Nodes, id)
	delete(h.rt, id)
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "node.remove", Target: id})
	return h.saveLocked()
}

// SyncNow asks a node to fetch its configuration at its next heartbeat.
func (h *Hub) SyncNow(by, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.node(id); err != nil {
		return err
	}
	h.rtFor(id).SyncRequest = true
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "node.sync-now", Target: id})
	return nil
}

// SetNodeGroup moves a node to another group (created if new).
func (h *Hub) SetNodeGroup(by, id, group string) error {
	if !groupNamePattern.MatchString(group) {
		return errors.New("group name must match [A-Za-z0-9_-]{1,32}")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.node(id)
	if err != nil {
		return err
	}
	if _, ok := h.st.Groups[group]; !ok {
		if len(h.st.Groups) >= maxFleetGroups {
			return errors.New("group limit reached")
		}
		h.st.Groups[group] = &FleetGroup{Name: group}
	}
	old := n.Group
	n.Group = group
	h.rtFor(id).SyncRequest = true
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "node.set-group", Target: id, Detail: old + " -> " + group})
	return h.saveLocked()
}

// SetNodeVars replaces the node's variables.
func (h *Hub) SetNodeVars(by, id string, vars map[string]string) error {
	if err := ValidateVars(vars); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.node(id)
	if err != nil {
		return err
	}
	n.Vars = vars
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "node.set-vars", Target: id, Detail: varNames(vars)})
	return h.saveLocked()
}

// SetNodeScopes sets or (nil) clears the node's own scope selection.
func (h *Hub) SetNodeScopes(by, id string, sel *ScopeSel) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.node(id)
	if err != nil {
		return err
	}
	if sel != nil {
		s, err := normalizeSel(*sel)
		if err != nil {
			return err
		}
		sel = &s
	}
	n.Override = sel
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "node.set-scopes", Target: id, Detail: selSummary(sel)})
	return h.saveLocked()
}

// SetGroup creates or updates a group's scopes and variables.
func (h *Hub) SetGroup(by, name string, sel ScopeSel, vars map[string]string) error {
	if !groupNamePattern.MatchString(name) {
		return errors.New("group name must match [A-Za-z0-9_-]{1,32}")
	}
	if err := ValidateVars(vars); err != nil {
		return err
	}
	s, err := normalizeSel(sel)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	g := h.st.Groups[name]
	if g == nil {
		if len(h.st.Groups) >= maxFleetGroups {
			return errors.New("group limit reached")
		}
		g = &FleetGroup{Name: name}
		h.st.Groups[name] = g
	}
	g.Sel, g.Vars = s, vars
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "group.set", Target: name, Detail: selSummary(&s) + " " + varNames(vars)})
	return h.saveLocked()
}

// DeleteGroup removes an empty group.
func (h *Hub) DeleteGroup(by, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range h.st.Nodes {
		if n.Group == name {
			return errors.New("group still has nodes")
		}
	}
	if h.st.Groups[name] == nil {
		return errors.New("no such group")
	}
	delete(h.st.Groups, name)
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "group.delete", Target: name})
	return h.saveLocked()
}

// SetSettings changes the hub options.
func (h *Hub) SetSettings(by string, s HubSettings) error {
	if s.KeepVersions < 2 || s.KeepVersions > 100 {
		return errors.New("keepVersions must be between 2 and 100")
	}
	if s.HeartbeatSecs < 5 || s.HeartbeatSecs > 300 {
		return errors.New("heartbeatSecs must be between 5 and 300")
	}
	if s.HealthGraceSec < 5 || s.HealthGraceSec > 600 {
		return errors.New("healthGraceSec must be between 5 and 600")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.Settings = s
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "settings.set", Detail: fmt.Sprintf("keep=%d certs=%v", s.KeepVersions, s.CaptureCerts)})
	return h.saveLocked()
}

func normalizeSel(s ScopeSel) (ScopeSel, error) {
	names, err := validScopeNames(s.Scopes)
	if err != nil {
		return s, err
	}
	var tags []string
	for _, t := range s.ProxyTags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) > 64 || strings.ContainsAny(t, "\"\\\x00\n") {
			return s, errors.New("invalid tag")
		}
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return ScopeSel{Scopes: names, ProxyTags: tags}, nil
}

func selSummary(s *ScopeSel) string {
	if s == nil {
		return "inherit"
	}
	r := strings.Join(s.Scopes, ",")
	if len(s.ProxyTags) > 0 {
		r += " tags=" + strings.Join(s.ProxyTags, ",")
	}
	return r
}

func varNames(v map[string]string) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k) //names only, never values
	}
	sort.Strings(keys)
	return "vars=" + strings.Join(keys, ",")
}

// ---------------------------------------------------------------------
// effective configuration of a node

func (h *Hub) effectiveLocked(n *FleetNode) (ScopeSel, map[string]string) {
	g := h.st.Groups[n.Group]
	var sel ScopeSel
	vars := map[string]string{}
	if g != nil {
		sel = g.Sel
		for k, v := range g.Vars {
			vars[k] = v
		}
	}
	if n.Override != nil {
		sel = *n.Override
	}
	for k, v := range n.Vars {
		vars[k] = v
	}
	return sel, vars
}

// desiredVersionLocked is the version the node should run now.
func (h *Hub) desiredVersionLocked(n *FleetNode) int64 {
	g := h.st.Groups[n.Group]
	if g == nil {
		return 0
	}
	if r := g.Rollout; r != nil && n.ID == r.CanaryNode && (r.State == RolloutCanary || r.State == RolloutAwaitPromotion) {
		return r.Version
	}
	return g.Desired
}

func builtinVars(n *FleetNode) map[string]string {
	safe := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
				return r
			}
			return '-'
		}, s)
	}
	return map[string]string{"id": safe(n.ID), "name": safe(n.Name), "group": safe(n.Group)}
}

// bundle is a node's resolved view of a version, before sealing.
type bundle struct {
	meta  FleetMeta
	files []FileEntry
}

func (h *Hub) buildBundle(n FleetNode, sel ScopeSel, vars map[string]string, ver int64) (*bundle, error) {
	b := &bundle{meta: FleetMeta{HubID: h.HubID(), Version: ver, Group: n.Group, NodeName: n.Name, Scopes: sel.Scopes, Vars: vars}}
	if ver == 0 || len(sel.Scopes) == 0 {
		b.meta.NoConfig = ver == 0
		b.meta.Hash = hashStrings("none", strconv.FormatInt(ver, 10), strings.Join(sel.Scopes, ","), n.Group, n.Name, sortedVars(vars))
		return b, nil
	}
	items, err := h.loadVersion(ver)
	if err != nil {
		return nil, err
	}
	var files, extra []FileEntry
	for _, sc := range sel.Scopes {
		its, ok := items[sc]
		if !ok {
			continue
		}
		if s, ok := GetScope(sc); ok {
			if f, ok := s.(interface {
				Filter([]FileEntry, Selection) []FileEntry
			}); ok {
				its = f.Filter(its, Selection{ProxyTags: sel.ProxyTags})
			}
		}
		for _, it := range its {
			if validEntryPath(it.Path, ManagedRoots(true)) {
				files = append(files, it)
			} else {
				extra = append(extra, it)
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(extra, func(i, j int) bool { return extra[i].Path < extra[j].Path })
	b.files, b.meta.Extra = files, extra
	b.meta.Hash = hashStrings("v1", strconv.FormatInt(ver, 10), strings.Join(sel.Scopes, ","), strings.Join(sel.ProxyTags, ","),
		HashFiles(files), HashFiles(extra), sortedVars(vars), n.Group, n.Name)
	return b, nil
}

// bundleFor builds the bundle a node should have right now.
func (h *Hub) bundleFor(id string) (*bundle, *FleetNode, error) {
	h.mu.Lock()
	n := h.st.Nodes[id]
	if n == nil {
		h.mu.Unlock()
		return nil, nil, errors.New("no such node")
	}
	cp := *n
	sel, vars := h.effectiveLocked(n)
	ver := h.desiredVersionLocked(n)
	h.mu.Unlock()
	b, err := h.buildBundle(cp, sel, vars, ver)
	return b, &cp, err
}

// DesiredHash returns the hash of the bundle the node should be running.
// Results are memoised per input set so the dashboard stays cheap.
func (h *Hub) DesiredHash(id string) (int64, string) {
	h.mu.Lock()
	n := h.st.Nodes[id]
	if n == nil {
		h.mu.Unlock()
		return 0, ""
	}
	cp := *n
	sel, vars := h.effectiveLocked(n)
	ver := h.desiredVersionLocked(n)
	h.mu.Unlock()
	memo := hashStrings(strconv.FormatInt(ver, 10), strings.Join(sel.Scopes, ","), strings.Join(sel.ProxyTags, ","), sortedVars(vars), cp.Group, cp.Name)
	h.cacheMu.Lock()
	if v, ok := h.hashMemo[memo]; ok {
		h.cacheMu.Unlock()
		return ver, v
	}
	h.cacheMu.Unlock()
	b, err := h.buildBundle(cp, sel, vars, ver)
	if err != nil {
		return ver, ""
	}
	h.cacheMu.Lock()
	if len(h.hashMemo) > 4096 {
		h.hashMemo = map[string]string{}
	}
	h.hashMemo[memo] = b.meta.Hash
	h.cacheMu.Unlock()
	return ver, b.meta.Hash
}

// Filterer is implemented by the file scopes.
func (s *fileScope) Filter(items []FileEntry, sel Selection) []FileEntry {
	if s.kind != "proxy" || len(sel.ProxyTags) == 0 {
		return items
	}
	var out []FileEntry
	for _, f := range items {
		if hasAnyTag(f.Data, sel.ProxyTags) {
			out = append(out, f)
		}
	}
	return out
}

// run advances canary rollouts until ctx ends.
func (h *Hub) run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Tick(h.now())
		}
	}
}
