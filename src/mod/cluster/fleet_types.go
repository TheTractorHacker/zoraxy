package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

/*
	Fleet (central management) data model.

	Hub side state is persisted in <conf>/.cluster/fleet-hub.json (0600, holds
	the per node keys). Immutable config versions are sealed (AES-256-GCM +
	HMAC, the snapshot format) with a random hub key kept in
	<conf>/.cluster/fleet-hub.key (0600) under <conf>/.cluster/fleet/versions.

	The hub can only publish configuration versions and ask a node to sync
	now. There is no remote command execution of any kind.
*/

// Fleet endpoints on the admin port. Like the legacy sync endpoints they sit
// outside the admin session and CSRF layers and authenticate on their own.
const (
	FleetJoinPath      = "/api/fleet/join"
	FleetConfigPath    = "/api/fleet/config"
	FleetHeartbeatPath = "/api/fleet/heartbeat"
)

// Roles added by Fleet. The legacy primary/follower roles are unchanged.
const (
	RoleHub  = "hub"
	RoleNode = "node"
)

// Rollout strategies and states.
const (
	StrategyImmediate = "immediate"
	StrategyCanary    = "canary"
	StrategyManual    = "manual"

	RolloutPendingApproval = "pending_approval"
	RolloutCanary          = "canary"
	RolloutAwaitPromotion  = "awaiting_promotion"
	RolloutComplete        = "complete"
	RolloutHalted          = "halted"
	RolloutAborted         = "aborted"
)

// Node status values shown on the dashboard.
const (
	StatusOnline   = "online"
	StatusDegraded = "degraded"
	StatusOffline  = "offline"
	StatusRevoked  = "revoked"
	StatusNever    = "never-seen"
)

const (
	defaultGroup        = "default"
	maxFleetNodes       = 256
	maxFleetGroups      = 64
	maxJoinTokens       = 64
	MaxJoinTokenTTL     = 24 * time.Hour
	DefaultJoinTokenTTL = 15 * time.Minute
	DefaultKeepVersions = 10
	onlineWithin        = 90 * time.Second
	offlineAfter        = 5 * time.Minute
	DefaultHeartbeat    = 20 * time.Second
	fleetRateLimit      = 240 //authenticated sync requests per client IP per minute
	joinRateLimit       = 10  //join attempts per client IP per minute
	maxFleetHBBody      = 16 << 10
)

var (
	groupNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	nodeNamePattern  = regexp.MustCompile(`^[A-Za-z0-9 ._-]{0,64}$`)
)

// JoinToken is a one time enrollment credential created on the hub. Only a
// hash of the secret part is stored.
type JoinToken struct {
	ID        string `json:"id"`
	Hash      string `json:"hash"`
	CreatedAt int64  `json:"createdAt"`
	CreatedBy string `json:"createdBy"`
	ExpiresAt int64  `json:"expiresAt"`
	NodeName  string `json:"nodeName,omitempty"`
	Group     string `json:"group,omitempty"`
	UsedAt    int64  `json:"usedAt,omitempty"`
	UsedBy    string `json:"usedBy,omitempty"`
	Revoked   bool   `json:"revoked,omitempty"`
}

// ScopeSel is the scope choice of a group or node.
type ScopeSel struct {
	Scopes    []string `json:"scopes"`
	ProxyTags []string `json:"proxyTags,omitempty"`
}

// FleetNode is a node enrolled at the hub.
type FleetNode struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Group     string            `json:"group"`
	Key       string            `json:"key"`               //current node key (hex)
	NextKey   string            `json:"nextKey,omitempty"` //staged by a rotation until the node used it
	JoinedAt  int64             `json:"joinedAt"`
	Revoked   bool              `json:"revoked,omitempty"`
	RevokedAt int64             `json:"revokedAt,omitempty"`
	Vars      map[string]string `json:"vars,omitempty"`
	Override  *ScopeSel         `json:"override,omitempty"` //nil = inherit the group
	Pinned    string            `json:"-"`
}

// FleetGroup is a set of nodes sharing scopes, variables and rollouts.
type FleetGroup struct {
	Name    string            `json:"name"`
	Sel     ScopeSel          `json:"sel"`
	Vars    map[string]string `json:"vars,omitempty"`
	Desired int64             `json:"desired"` //stable version for every node (0 = nothing published)
	Rollout *Rollout          `json:"rollout,omitempty"`
}

// Rollout tracks the latest publish of a group.
type Rollout struct {
	ID              string `json:"id"`
	Group           string `json:"group"`
	Version         int64  `json:"version"`
	PrevVersion     int64  `json:"prevVersion"`
	Strategy        string `json:"strategy"`
	State           string `json:"state"`
	CanaryNode      string `json:"canaryNode,omitempty"`
	HealthySeconds  int    `json:"healthySeconds"`
	HoldForApproval bool   `json:"holdForApproval,omitempty"`
	TimeoutSeconds  int    `json:"timeoutSeconds"`
	StartedAt       int64  `json:"startedAt"`
	StateAt         int64  `json:"stateAt"`
	Reason          string `json:"reason,omitempty"`
	By              string `json:"by"`
	HealthySince    int64  `json:"-"`
	UnhealthySince  int64  `json:"-"`
}

// VersionMeta describes a stored configuration version.
type VersionMeta struct {
	ID        int64             `json:"id"`
	CreatedAt int64             `json:"createdAt"`
	CreatedBy string            `json:"createdBy"`
	Note      string            `json:"note"`
	Scopes    []string          `json:"scopes"`
	Hash      string            `json:"hash"`
	Files     map[string]string `json:"files"` //path -> sha256 (index for diffs, no content)
}

// HubSettings are the hub wide options.
type HubSettings struct {
	KeepVersions   int  `json:"keepVersions"`
	CaptureCerts   bool `json:"captureCerts"`   //include certificates (and keys) in captured versions
	HeartbeatSecs  int  `json:"heartbeatSecs"`  //interval nodes are told to use
	HealthGraceSec int  `json:"healthGraceSec"` //how long a canary may be unhealthy before the rollout halts
}

type hubState struct {
	HubID    string                `json:"hubId"`
	Settings HubSettings           `json:"settings"`
	Nodes    map[string]*FleetNode `json:"nodes"`
	Groups   map[string]*FleetGroup `json:"groups"`
	Tokens   []JoinToken           `json:"tokens"`
	Versions []VersionMeta         `json:"versions"`
	NextVer  int64                 `json:"nextVersion"`
}

// NodeStats is the bounded telemetry a node reports. Counters are cumulative
// since the node process started; the hub derives per minute rates.
type NodeStats struct {
	UptimeSeconds int64  `json:"uptime"`
	Health        string `json:"health"` //ok | unavailable
	Endpoints     int    `json:"endpoints"`
	CertExpiry    int64  `json:"certExpiry,omitempty"` //soonest leaf expiry, unix
	WAFMode       string `json:"wafMode,omitempty"`
	Requests      uint64 `json:"requests"`
	Errors        uint64 `json:"errors"` //5xx responses
	WAFEvents     uint64 `json:"wafEvents"`
}

type fleetHeartbeat struct {
	Name         string     `json:"name"`
	Version      string     `json:"version"`
	AppliedVer   int64      `json:"appliedVersion"`
	AppliedHash  string     `json:"appliedHash"`
	AttemptHash  string     `json:"attemptHash"`
	LastResult   string     `json:"lastResult"`
	LastError    string     `json:"lastError"`
	LocalDrift   bool       `json:"localDrift"`
	Conflicts    []Conflict `json:"conflicts,omitempty"`
	Stats        NodeStats  `json:"stats"`
	ManagedCount int        `json:"managedCount"`
}

type fleetHeartbeatReply struct {
	SyncNow     bool   `json:"syncNow"`
	DesiredHash string `json:"desiredHash"`
	HeartbeatS  int    `json:"heartbeatSecs"`
}

// FleetMeta rides inside the sealed payload of a bundle.
type FleetMeta struct {
	HubID    string            `json:"hubId"`
	Version  int64             `json:"version"`
	Hash     string            `json:"hash"`
	Group    string            `json:"group"`
	NodeName string            `json:"nodeName"`
	Scopes   []string          `json:"scopes"`
	Vars     map[string]string `json:"vars,omitempty"`
	Extra    []FileEntry       `json:"extra,omitempty"` //items of non file scopes
	Rotate   string            `json:"rotate,omitempty"`
	NoConfig bool              `json:"noConfig,omitempty"` //nothing published yet
}

// HistoryEntry is one apply attempt reported by or about a node.
type HistoryEntry struct {
	At      int64  `json:"at"`
	Version int64  `json:"version"`
	Result  string `json:"result"`
	Error   string `json:"error,omitempty"`
}

// nodeRuntime is non persistent per node state.
type nodeRuntime struct {
	LastSeen     int64
	Addr         string
	Version      string
	HB           fleetHeartbeat
	PrevStats    NodeStats
	PrevAt       int64
	ReqPerMin    float64
	ErrPerMin    float64
	WAFPerMin    float64
	SyncRequest  bool
	Errors       []HistoryEntry
	History      []HistoryEntry
	lastHistHash string
}

// AuditEntry is one hub action.
type AuditEntry struct {
	At     int64  `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func hashStrings(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(strconv.Itoa(len(p))))
		h.Write([]byte{0})
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedVars(v map[string]string) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + v[k] + "\n")
	}
	return b.String()
}

func trimTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
