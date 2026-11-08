package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// followerStatus is persisted to <conf>/.cluster/follower.json so the last
// applied version survives the restart that follows an apply.
type followerStatus struct {
	AppliedVersion int64  `json:"appliedVersion"`
	AppliedHash    string `json:"appliedHash"`
	AppliedAt      int64  `json:"appliedAt"`
	LastAttemptAt  int64  `json:"lastAttemptAt"`
	LastSuccessAt  int64  `json:"lastSuccessAt"`
	LastError      string `json:"lastError"`
	LastResult     string `json:"lastResult"` //applied, unchanged, error
	CertsSynced    bool   `json:"certsSynced"`
	RejectedHash   string `json:"rejectedHash,omitempty"` //snapshot that prevented a clean start

	// Fleet (central management) node state
	AttemptHash string              `json:"attemptHash,omitempty"` //bundle of the latest apply attempt
	ManagedHash string              `json:"managedHash,omitempty"` //hash of the managed files as applied (local drift check)
	Managed     map[string][]string `json:"managed,omitempty"`     //scope -> keys owned by the hub
	FleetScopes []string            `json:"fleetScopes,omitempty"`
	Conflicts   []Conflict          `json:"conflicts,omitempty"`
	FleetGroup  string              `json:"fleetGroup,omitempty"`
}

func (m *Manager) followerStateFile() string {
	return filepath.Join(m.opt.ConfDir, StateDirName, "follower.json")
}

func (m *Manager) loadStatus() {
	if b, err := os.ReadFile(m.followerStateFile()); err == nil {
		json.Unmarshal(b, &m.status)
	}
}

func (m *Manager) saveStatusLocked() {
	b, err := json.Marshal(m.status)
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(m.followerStateFile()), 0o700)
	os.WriteFile(m.followerStateFile(), b, 0o600)
}

// FollowerStatus is the view exposed to the UI.
type FollowerStatus struct {
	AppliedVersion int64  `json:"appliedVersion"`
	AppliedAt      int64  `json:"appliedAt"`
	LastAttemptAt  int64  `json:"lastAttemptAt"`
	LastSuccessAt  int64  `json:"lastSuccessAt"`
	LastError      string `json:"lastError"`
	LastResult     string `json:"lastResult"`
}

// Status returns the follower sync state.
func (m *Manager) Status() FollowerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.status
	return FollowerStatus{s.AppliedVersion, s.AppliedAt, s.LastAttemptAt, s.LastSuccessAt, s.LastError, s.LastResult}
}

type followerRunner struct {
	role   string
	cancel context.CancelFunc
	done   chan struct{}
}

func (r *followerRunner) stop() {
	r.cancel()
	<-r.done
}

// reconcileFollower starts, stops or switches the background loop to match
// the role: the poll loop (follower), the fleet node loop (node) or the hub
// rollout ticker (hub).
func (m *Manager) reconcileFollower() {
	m.mu.Lock()
	defer m.mu.Unlock()
	role := m.cfg.Role
	want := role == RoleFollower || role == RoleNode || role == RoleHub
	if m.followerRun != nil && (!want || m.followerRun.role != role) {
		old := m.followerRun
		m.followerRun = nil
		go old.stop()
	}
	if want && m.followerRun == nil {
		ctx, cancel := context.WithCancel(context.Background())
		r := &followerRunner{role: role, cancel: cancel, done: make(chan struct{})}
		m.followerRun = r
		go func() {
			defer close(r.done)
			switch role {
			case RoleNode:
				m.fleetLoop(ctx)
			case RoleHub:
				m.hub.run(ctx)
			default:
				m.pollLoop(ctx)
			}
		}()
	}
}

func (m *Manager) pollLoop(ctx context.Context) {
	// small initial delay so startup finishes first
	wait := 5*time.Second + time.Duration(rand.Intn(5000))*time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := m.SyncOnce(ctx, false); err != nil {
			m.opt.Logf("[cluster] sync failed: %v", err)
		}
		iv := time.Duration(m.Config().SyncIntervalSeconds) * time.Second
		jitter := time.Duration(rand.Int63n(int64(iv) / 5)) //+0..20%
		wait = iv + jitter
	}
}

func (m *Manager) httpClient(cfg Config) *http.Client {
	if m.opt.HTTPClient != nil {
		return m.opt.HTTPClient
	}
	return newPinnedClient(cfg.PrimaryFingerprint)
}

// newPinnedClient builds the HTTP client for talking to a primary or hub.
// With a fingerprint the server's leaf certificate must match it (this is
// how self-signed admin certificates from -webui_tls are trusted); without
// one the normal certificate verification applies.
func newPinnedClient(pin string) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate presented")
			}
			sum := sha256.Sum256(raw[0])
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
				return errors.New("primary certificate does not match the pinned fingerprint")
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:       60 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: tc, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (m *Manager) primaryRequest(ctx context.Context, cfg Config, method, p string, body []byte) (*http.Request, error) {
	u := strings.TrimRight(cfg.PrimaryURL, "/") + p
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// the token is bound to the path only (no query string)
	req.Header.Set("Authorization", "Bearer "+MakeToken(m.secret(), method, p, m.opt.NodeID, m.opt.Now()))
	req.Header.Set("User-Agent", "zoraxy-cluster/"+m.opt.Version)
	return req, nil
}

// SyncOnce performs one follower sync. force accepts an older snapshot
// version than the one applied (used after the primary was rebuilt).
func (m *Manager) SyncOnce(ctx context.Context, force bool) error {
	cfg := m.Config()
	if cfg.Role != RoleFollower {
		return errors.New("this node is not a follower")
	}
	if !m.syncMu.TryLock() {
		return errors.New("a sync is already running")
	}
	defer m.syncMu.Unlock()

	m.mu.Lock()
	m.status.LastAttemptAt = m.opt.Now().Unix()
	have := m.status.AppliedVersion
	m.mu.Unlock()

	result, err := m.syncLocked(ctx, cfg, have, force)
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
	st := m.status
	m.mu.Unlock()

	m.sendHeartbeat(ctx, cfg, st)
	return err
}

func (m *Manager) syncLocked(ctx context.Context, cfg Config, have int64, force bool) (string, error) {
	client := m.httpClient(cfg)
	q := ""
	if have > 0 && !force {
		q = "?have=" + strconv.FormatInt(have, 10)
	}
	// token covers the path, the query string is not authenticated and only
	// an optimisation
	req, err := m.primaryRequest(ctx, cfg, http.MethodGet, SnapshotPath, nil)
	if err != nil {
		return "", err
	}
	req.URL.RawQuery = strings.TrimPrefix(q, "?")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach primary: %w", sanitizeErr(err))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return "unchanged", nil
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusNotFound:
		return "", errors.New("primary rejected the request (check the cluster secret, that the primary has role=primary, and clock sync)")
	case http.StatusTooManyRequests:
		return "", errors.New("primary rate limited this node")
	default:
		return "", fmt.Errorf("primary answered HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxSnapshotBytes*2+1))
	if err != nil {
		return "", err
	}
	env, payload, err := Open(m.secret(), raw)
	if err != nil {
		return "", err
	}
	return m.applySnapshot(env, payload, force)
}

func (m *Manager) applySnapshot(env *Envelope, payload *Payload, force bool) (string, error) {
	m.mu.RLock()
	prev := m.status
	m.mu.RUnlock()

	if env.Version < prev.AppliedVersion && !force {
		return "", fmt.Errorf("refusing stale snapshot version %d (applied %d)", env.Version, prev.AppliedVersion)
	}
	if payload.ContentHash == prev.RejectedHash && !force {
		return "", errors.New("this snapshot previously prevented a clean start and was rolled back; waiting for the primary to change it")
	}
	if payload.ContentHash == prev.AppliedHash {
		// same content as last time; drift from local edits is left alone
		m.mu.Lock()
		m.status.AppliedVersion = env.Version
		m.status.CertsSynced = payload.IncludesCerts
		m.saveStatusLocked()
		m.mu.Unlock()
		return "unchanged", nil
	}

	toApply := neutralizeACME(payload)
	if m.opt.Validate != nil {
		if err := m.opt.Validate(toApply); err != nil {
			return "", fmt.Errorf("snapshot rejected by validation, previous configuration kept: %w", err)
		}
	}

	// Nothing to do if the files already match (first sync of an identical node).
	local, err := CollectFiles(m.opt.ConfDir, toApply.IncludesCerts)
	if err == nil && local.ContentHash == toApply.ContentHash {
		m.mu.Lock()
		m.status.AppliedVersion = env.Version
		m.status.AppliedHash = payload.ContentHash
		m.status.AppliedAt = m.opt.Now().Unix()
		m.status.CertsSynced = payload.IncludesCerts
		m.saveStatusLocked()
		m.mu.Unlock()
		return "unchanged", nil
	}

	ap := &Applier{ConfDir: m.opt.ConfDir}
	applied, err := ap.ApplyPayload(toApply, BackupTag(m.opt.Now()))
	if err != nil {
		return "", fmt.Errorf("apply failed, previous configuration kept: %w", err)
	}

	return m.finishApply(applied, toApply.Roots, payload.ContentHash, env.Version, func(st *followerStatus) {
		st.AppliedVersion = env.Version
		st.AppliedHash = payload.ContentHash
		st.AppliedAt = m.opt.Now().Unix()
		st.CertsSynced = payload.IncludesCerts
	}, nil, fmt.Sprintf("applied snapshot version %d (%d files)", env.Version, len(payload.Files)))
}

// finishApply persists the new state, then reloads the process. It is shared
// by the legacy follower and the Fleet node. Any failure rolls the files (and
// via undo, non file state) back to what they were before the apply.
func (m *Manager) finishApply(applied *Applied, roots []string, hash string, version int64, mutate func(*followerStatus), undo func(), logMsg string) (string, error) {
	// Persist the new state first so the restart that Reload triggers sees it.
	m.mu.Lock()
	old := m.status
	mutate(&m.status)
	m.saveStatusLocked()
	m.mu.Unlock()

	if m.opt.Reload != nil {
		m.writePending(pendingApply{BackupDir: applied.BackupDir, Roots: roots, Hash: hash, Version: version, PrevStatus: old})
		if err := m.opt.Reload(); err != nil {
			m.MarkHealthy()
			rbErr := applied.Rollback()
			if undo != nil {
				undo()
			}
			m.mu.Lock()
			m.status = old
			m.saveStatusLocked()
			m.mu.Unlock()
			if rbErr != nil {
				return "", fmt.Errorf("reload failed (%v) and rollback failed: %v", err, rbErr)
			}
			return "", fmt.Errorf("reload failed, rolled back to previous configuration: %w", err)
		}
	}
	m.opt.Logf("[cluster] %s", logMsg)
	return "applied", nil
}

// neutralizeACME returns the payload as a follower should store it. When
// certificates are synced the primary is the single ACME issuer, so the
// follower's copy of acme_conf.json gets automatic renewal switched off;
// otherwise every follower would try to renew the same certificates.
func neutralizeACME(p *Payload) *Payload {
	if !p.IncludesCerts {
		return p
	}
	out := *p
	out.Files = make([]FileEntry, len(p.Files))
	copy(out.Files, p.Files)
	for i, f := range out.Files {
		if f.Path != "acme_conf.json" {
			continue
		}
		var obj map[string]any
		if json.Unmarshal(f.Data, &obj) != nil {
			continue
		}
		if _, ok := obj["Enabled"]; ok {
			obj["Enabled"] = false
			if b, err := json.Marshal(obj); err == nil {
				out.Files[i].Data = b
			}
		}
	}
	out.ContentHash = HashFiles(out.Files)
	return &out
}

// sanitizeErr keeps URLs with query strings / tokens out of error text.
func sanitizeErr(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) && ue.Unwrap() != nil {
		return ue.Unwrap()
	}
	return err
}

func (m *Manager) sendHeartbeat(ctx context.Context, cfg Config, st followerStatus) {
	hb, _ := json.Marshal(heartbeatBody{
		Name:           m.opt.NodeName,
		Version:        m.opt.Version,
		AppliedVersion: st.AppliedVersion,
		LastSyncAt:     st.LastSuccessAt,
		LastError:      st.LastError,
	})
	req, err := m.primaryRequest(ctx, cfg, http.MethodPost, HeartbeatPath, hb)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.httpClient(cfg).Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
}
