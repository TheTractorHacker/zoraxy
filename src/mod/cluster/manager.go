package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Roles of a node.
const (
	RoleStandalone = "standalone"
	RolePrimary    = "primary"
	RoleFollower   = "follower"
)

const (
	DefaultSyncInterval = 60
	MinSyncInterval     = 10
	MaxSyncInterval     = 3600
	configFileName      = "cluster.json"
)

// Config is persisted in <conf>/cluster.json (mode 0600; it holds the secret).
// The file is node local and is never synced.
type Config struct {
	Role                string   `json:"role"`
	Secret              string   `json:"secret,omitempty"`
	PrimaryURL          string   `json:"primaryUrl,omitempty"`
	PrimaryFingerprint  string   `json:"primaryFingerprint,omitempty"` //optional SHA-256 pin of the primary admin TLS leaf certificate
	SyncIntervalSeconds int      `json:"syncIntervalSeconds,omitempty"`
	SyncCerts           bool     `json:"syncCerts,omitempty"`
	HealthDisabled      bool     `json:"healthDisabled,omitempty"`
	HealthAllow         []string `json:"healthAllow,omitempty"`
}

// Options configures a Manager.
type Options struct {
	ConfDir         string
	NodeID          string //stable id of this node (the node UUID)
	NodeName        string
	Version         string //Zoraxy version
	FlagSecret      string //value of -cluster_secret, wins over the file
	AllowLocalEdits bool   //-cluster_allow_local_edits
	// Reload is called after a follower applied new files. It should make the
	// process pick them up (Zoraxy restarts itself). Returning an error rolls
	// the files back.
	Reload func() error
	// Validate optionally checks a snapshot against the real config schemas
	// before anything is written (JSON validity is always checked).
	Validate func(p *Payload) error
	Logf     func(format string, a ...any)
	Now      func() time.Time
	// HTTPClient is used by followers and fleet nodes; nil builds one from the config.
	HTTPClient *http.Client
	// Actor names the admin who issued a hub action (audit log). Optional.
	Actor func(r *http.Request) string
	// Stats returns the bounded telemetry a fleet node reports in its
	// heartbeat. Optional.
	Stats func() NodeStats
}

// Manager owns the cluster configuration and both roles of the sync.
type Manager struct {
	opt    Options
	health *HealthEndpoint

	mu          sync.RWMutex
	cfg         Config
	bootSecret  string //secret in effect when the process started (session keys)
	secretFlag  bool
	followerRun *followerRunner

	primary *primaryState
	status  followerStatus
	syncMu  sync.Mutex

	hub   *Hub      //central management (role hub)
	creds nodeCreds //node key of a fleet node (cached, lives in .cluster/fleet-node.json)
}

// NewManager loads conf/cluster.json (missing = standalone).
func NewManager(opt Options) (*Manager, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	m := &Manager{opt: opt, health: NewHealthEndpoint(opt.Version)}
	m.cfg = Config{Role: RoleStandalone}
	if b, err := os.ReadFile(m.configPath()); err == nil {
		if err := json.Unmarshal(b, &m.cfg); err != nil {
			return nil, fmt.Errorf("cluster.json is not valid: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if opt.FlagSecret != "" {
		m.cfg.Secret = opt.FlagSecret
		m.secretFlag = true
	}
	m.normalizeLocked()
	if m.cfg.Secret != "" {
		if err := ValidateSecret(m.cfg.Secret); err != nil {
			return nil, err
		}
	}
	if (m.cfg.Role == RolePrimary || m.cfg.Role == RoleFollower) && m.cfg.Secret == "" {
		opt.Logf("[cluster] role %s needs a cluster secret; running as standalone", m.cfg.Role)
		m.cfg.Role = RoleStandalone
	}
	m.bootSecret = m.cfg.Secret
	if err := m.health.Configure(m.cfg.HealthAllow, m.cfg.HealthDisabled); err != nil {
		return nil, fmt.Errorf("cluster.json health allow list: %w", err)
	}
	m.primary = newPrimaryState(m)
	m.hub = newHub(m)
	if m.cfg.Role == RoleNode {
		if _, ok := m.loadCreds(); !ok {
			opt.Logf("[fleet] role node needs hub credentials (.cluster/fleet-node.json); running as standalone")
			m.cfg.Role = RoleStandalone
		}
	}
	m.loadStatus()
	m.bootGuard()
	return m, nil
}

func (m *Manager) configPath() string { return filepath.Join(m.opt.ConfDir, configFileName) }

func (m *Manager) normalizeLocked() {
	switch m.cfg.Role {
	case RolePrimary, RoleFollower, RoleHub, RoleNode:
	default:
		m.cfg.Role = RoleStandalone
	}
	if m.cfg.SyncIntervalSeconds == 0 {
		m.cfg.SyncIntervalSeconds = DefaultSyncInterval
	}
	if m.cfg.SyncIntervalSeconds < MinSyncInterval {
		m.cfg.SyncIntervalSeconds = MinSyncInterval
	}
	if m.cfg.SyncIntervalSeconds > MaxSyncInterval {
		m.cfg.SyncIntervalSeconds = MaxSyncInterval
	}
}

// Health returns the health endpoint shared by all proxy listeners.
func (m *Manager) Health() *HealthEndpoint { return m.health }

// Role returns the current role.
func (m *Manager) Role() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Role
}

// Secret returns the configured cluster secret ("" if unset). Internal use.
func (m *Manager) secret() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Secret
}

// KeyMaterial returns the key input for user facing session keys: the node
// UUID unchanged without a cluster secret, a derived key with one. It uses
// the secret in effect at process start, as session stores are built once.
func (m *Manager) KeyMaterial(nodeUUID, purpose string) string {
	if m == nil {
		return nodeUUID
	}
	return KeyMaterial(m.bootSecret, nodeUUID, purpose)
}

// AllowLocalEdits reports -cluster_allow_local_edits.
func (m *Manager) AllowLocalEdits() bool { return m.opt.AllowLocalEdits }

func (m *Manager) saveLocked() error {
	cfg := m.cfg
	if m.secretFlag {
		cfg.Secret = "" //never persist a secret that only came from the command line
		if b, err := os.ReadFile(m.configPath()); err == nil {
			var old Config
			if json.Unmarshal(b, &old) == nil {
				cfg.Secret = old.Secret
			}
		}
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.opt.ConfDir, 0o755); err != nil {
		return err
	}
	tmp := m.configPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.configPath())
}

// ConfigUpdate carries changes from the UI. Nil/empty means unchanged except
// where noted.
type ConfigUpdate struct {
	Role                *string
	Secret              *string
	PrimaryURL          *string
	PrimaryFingerprint  *string
	SyncIntervalSeconds *int
	SyncCerts           *bool
	HealthDisabled      *bool
	HealthAllow         *[]string
}

// Update validates and applies a configuration change and (re)starts or
// stops the follower loop as needed.
func (m *Manager) Update(u ConfigUpdate) error {
	m.mu.Lock()
	next := m.cfg
	if u.Role != nil {
		next.Role = *u.Role
		switch next.Role {
		case RoleStandalone, RolePrimary, RoleFollower, RoleHub:
		case RoleNode:
			if m.creds.NodeKey == "" {
				m.mu.Unlock()
				return errors.New("a node joins a fleet with a join token (Fleet page); it cannot be switched on directly")
			}
		default:
			m.mu.Unlock()
			return errors.New("role must be standalone, primary, follower, hub or node")
		}
	}
	if u.Secret != nil {
		if m.secretFlag {
			m.mu.Unlock()
			return errors.New("the cluster secret is set by -cluster_secret and cannot be changed here")
		}
		if err := ValidateSecret(*u.Secret); err != nil {
			m.mu.Unlock()
			return err
		}
		next.Secret = *u.Secret
	}
	if u.PrimaryURL != nil {
		next.PrimaryURL = strings.TrimSpace(*u.PrimaryURL)
	}
	if u.PrimaryFingerprint != nil {
		fp := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(*u.PrimaryFingerprint), ":", ""))
		if fp != "" && (len(fp) != 64 || !isHex(fp)) {
			m.mu.Unlock()
			return errors.New("primary fingerprint must be a SHA-256 hex string (64 characters)")
		}
		next.PrimaryFingerprint = fp
	}
	if u.SyncIntervalSeconds != nil {
		next.SyncIntervalSeconds = *u.SyncIntervalSeconds
	}
	if u.SyncCerts != nil {
		next.SyncCerts = *u.SyncCerts
	}
	if u.HealthDisabled != nil {
		next.HealthDisabled = *u.HealthDisabled
	}
	if u.HealthAllow != nil {
		next.HealthAllow = *u.HealthAllow
	}
	if (next.Role == RolePrimary || next.Role == RoleFollower) && next.Secret == "" {
		m.mu.Unlock()
		return errors.New("a cluster secret is required for the primary and follower roles")
	}
	if next.Role == RoleFollower || next.Role == RoleNode {
		if err := validatePrimaryURL(next.PrimaryURL); err != nil {
			m.mu.Unlock()
			return err
		}
	}
	if _, err := ParseAllowList(next.HealthAllow); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("health allow list: %w", err)
	}
	prev := m.cfg
	m.cfg = next
	m.normalizeLocked()
	if err := m.saveLocked(); err != nil {
		m.cfg = prev
		m.mu.Unlock()
		return err
	}
	cfg := m.cfg
	m.mu.Unlock()

	m.health.Configure(cfg.HealthAllow, cfg.HealthDisabled)
	m.reconcileFollower()
	return nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validatePrimaryURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("primary URL must look like https://host:8000 (no credentials)")
	}
	return nil
}

// Config returns a copy of the configuration with the secret removed.
func (m *Manager) Config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.cfg
	c.Secret = ""
	return c
}

// SecretFingerprint is a short identifier safe to display.
func (m *Manager) SecretFingerprint() string { return Fingerprint(m.secret()) }

// RestartRequired is true when the secret changed since start, so session
// keys (CAPTCHA, sticky) still use the old input.
func (m *Manager) RestartRequired() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Secret != m.bootSecret
}

// Start launches the follower loop if the role requires it.
func (m *Manager) Start() { m.reconcileFollower() }

// Stop halts background work.
func (m *Manager) Stop() {
	m.mu.Lock()
	r := m.followerRun
	m.followerRun = nil
	m.mu.Unlock()
	if r != nil {
		r.stop()
	}
}
