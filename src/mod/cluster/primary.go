package cluster

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Paths served by a primary on the admin port, outside the admin session and
// CSRF layers (they authenticate with the HMAC bearer token instead).
const (
	SnapshotPath  = "/api/cluster/snapshot"
	HeartbeatPath = "/api/cluster/heartbeat"
)

const (
	maxNodes         = 256
	maxHeartbeatBody = 8 << 10
	syncRateLimit    = 30 //requests per client IP per minute (valid or not)
)

// NodeInfo is what the primary knows about a follower.
type NodeInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	AppliedVersion int64  `json:"appliedVersion"`
	LastSyncAt     int64  `json:"lastSyncAt"`
	LastError      string `json:"lastError"`
	LastSeen       int64  `json:"lastSeen"`
	Addr           string `json:"addr"`
}

type primaryFile struct {
	Version int64  `json:"version"`
	Hash    string `json:"hash"`
}

type primaryState struct {
	m        *Manager
	verifier *TokenVerifier
	limiter  *RateLimiter

	mu    sync.Mutex
	nodes map[string]*NodeInfo
}

func newPrimaryState(m *Manager) *primaryState {
	return &primaryState{
		m:        m,
		verifier: NewTokenVerifier(),
		limiter:  NewRateLimiter(syncRateLimit, time.Minute),
		nodes:    map[string]*NodeInfo{},
	}
}

func (p *primaryState) stateFile() string {
	return filepath.Join(p.m.opt.ConfDir, StateDirName, "primary.json")
}

// current builds the current snapshot and assigns its version. The version
// only moves forward: a changed content hash gets max(previous+1, now in
// milliseconds), so it stays monotonic even if state is lost and the node is
// rebuilt later.
func (p *primaryState) current(includeCerts bool) ([]byte, int64, *Payload, error) {
	payload, err := CollectFiles(p.m.opt.ConfDir, includeCerts)
	if err != nil {
		return nil, 0, nil, err
	}
	p.mu.Lock()
	var st primaryFile
	if b, err := os.ReadFile(p.stateFile()); err == nil {
		json.Unmarshal(b, &st)
	}
	hash := payload.ContentHash
	if includeCerts {
		hash += "+certs"
	}
	if st.Hash != hash || st.Version == 0 {
		nv := p.m.opt.Now().UnixMilli()
		if nv <= st.Version {
			nv = st.Version + 1
		}
		st = primaryFile{Version: nv, Hash: hash}
		os.MkdirAll(filepath.Dir(p.stateFile()), 0o700)
		if b, err := json.Marshal(st); err == nil {
			os.WriteFile(p.stateFile(), b, 0o600)
		}
	}
	p.mu.Unlock()
	raw, err := Seal(p.m.secret(), st.Version, p.m.opt.Now().Unix(), p.m.opt.NodeID, payload)
	return raw, st.Version, payload, err
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authenticate gates every sync request. It answers 404 unless this node is
// a primary (a standalone node exposes nothing), 429 when rate limited and
// 401 for any token problem (no detail about why).
func (p *primaryState) authenticate(w http.ResponseWriter, r *http.Request, method string) (string, bool) {
	if p.m.Role() != RolePrimary {
		http.NotFound(w, r)
		return "", false
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	now := p.m.opt.Now()
	if !p.limiter.Allow(clientIP(r), now) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return "", false
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	node, err := p.verifier.Verify(p.m.secret(), r.Method, r.URL.Path, tok, now)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	return node, true
}

func (p *primaryState) touch(node string, r *http.Request) *NodeInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, ok := p.nodes[node]
	if !ok {
		if len(p.nodes) >= maxNodes {
			return nil
		}
		n = &NodeInfo{ID: node}
		p.nodes[node] = n
	}
	n.LastSeen = p.m.opt.Now().Unix()
	n.Addr = clientIP(r)
	return n
}

// handleSnapshot serves GET /api/cluster/snapshot[?have=<version>].
func (p *primaryState) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	node, ok := p.authenticate(w, r, http.MethodGet)
	if !ok {
		return
	}
	p.touch(node, r)
	cfg := p.m.Config()
	raw, version, _, err := p.current(cfg.SyncCerts)
	if err != nil {
		p.m.opt.Logf("[cluster] snapshot build failed: %v", err)
		http.Error(w, "snapshot unavailable", http.StatusInternalServerError)
		return
	}
	if have, err := strconv.ParseInt(r.URL.Query().Get("have"), 10, 64); err == nil && have == version {
		w.Header().Set("X-Zoraxy-Snapshot-Version", strconv.FormatInt(version, 10))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Zoraxy-Snapshot-Version", strconv.FormatInt(version, 10))
	w.Write(raw)
}

type heartbeatBody struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	AppliedVersion int64  `json:"appliedVersion"`
	LastSyncAt     int64  `json:"lastSyncAt"`
	LastError      string `json:"lastError"`
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// handleHeartbeat serves POST /api/cluster/heartbeat.
func (p *primaryState) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	node, ok := p.authenticate(w, r, http.MethodPost)
	if !ok {
		return
	}
	var hb heartbeatBody
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHeartbeatBody))
	if err != nil || json.Unmarshal(body, &hb) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	n := p.touch(node, r)
	if n == nil {
		http.Error(w, "node limit reached", http.StatusServiceUnavailable)
		return
	}
	p.mu.Lock()
	n.Name = trunc(hb.Name, 64)
	n.Version = trunc(hb.Version, 32)
	n.AppliedVersion = hb.AppliedVersion
	n.LastSyncAt = hb.LastSyncAt
	n.LastError = trunc(hb.LastError, 200)
	p.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// Nodes returns the followers seen so far, sorted by id.
func (p *primaryState) Nodes() []NodeInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]NodeInfo, 0, len(p.nodes))
	for _, n := range p.nodes {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SyncHandler returns the handler for the token authenticated sync
// endpoints. Mount it on /api/cluster/snapshot and /api/cluster/heartbeat
// outside any session or CSRF middleware.
func (m *Manager) SyncHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(SnapshotPath, m.primary.handleSnapshot)
	mux.HandleFunc(HeartbeatPath, m.primary.handleHeartbeat)
	return mux
}

// Nodes lists the followers known to this primary.
func (m *Manager) Nodes() []NodeInfo { return m.primary.Nodes() }

// CurrentSnapshotVersion returns the version a follower would receive now.
func (m *Manager) CurrentSnapshotVersion() (int64, error) {
	_, v, _, err := m.primary.current(m.Config().SyncCerts)
	return v, err
}
