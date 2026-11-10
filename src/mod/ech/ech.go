// Package ech implements server-side Encrypted Client Hello (RFC 9849) key management.
//
// Keys are HPKE key pairs (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM and ChaCha20-Poly1305).
// The newest "active" key is the one advertised in the ECHConfigList that is published in DNS HTTPS
// records; "retired" keys are only used to decrypt, until they are purged after the retain window, so clients
// holding a cached older DNS answer keep working across a rotation.
//
// The Manager plugs into crypto/tls through GetEncryptedClientHelloKeys, which is read per handshake, so
// enabling, rotating and retiring keys never needs a listener restart. Everything is off by default.
package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ECHConfig extension version (RFC 9849)
	echVersion = 0xfe0d
	kemX25519  = 0x0020
	kdfSHA256  = 0x0001
	aeadAES128 = 0x0001
	aeadChaCha = 0x0003

	DefaultMaxNameLength = 64
	DefaultRetainHours   = 24 * 7
	MaxKeys              = 16
)

const (
	StateActive  = "active"
	StateRetired = "retired"
)

// Settings is the global ECH configuration
type Settings struct {
	Enabled          bool   // Master switch, default off
	PublicName       string // Outer SNI (public_name) of generated configs. Must be a name Zoraxy serves a valid certificate for
	MaxNameLength    int    // maximum_name_length of generated configs (clients pad the inner SNI to this), default 64
	RotateEveryHours int    // Automatic rotation interval, 0 = manual only
	RetainHours      int    // How long retired keys keep decrypting, default 168 (7 days). Keep it above the DNS TTL
}

// Key is one stored ECH key pair
type Key struct {
	ID            string    // Random identifier used by the API
	ConfigID      uint8     // config_id of the ECHConfig
	PublicName    string    // public_name baked into the config
	MaxNameLength int       // maximum_name_length baked into the config
	State         string    // active or retired
	Created       time.Time //
	RetiredAt     time.Time `json:",omitzero"`
	PrivateKey    string    // base64 raw X25519 private key. Secret: never logged, never returned by the API
	Config        string    // base64 serialised ECHConfig (a single config, not a list)
}

type fileData struct {
	Settings Settings
	Keys     []*Key
}

// Manager owns the settings and keys
type Manager struct {
	dir string

	mu       sync.RWMutex
	settings Settings
	keys     []*Key
	cached   []tls.EncryptedClientHelloKey // built from keys, replaced on every change
	now      func() time.Time

	accepted atomic.Uint64 // TLS requests whose ClientHello was decrypted
	plain    atomic.Uint64 // TLS requests without (or with a rejected) ECH while ECH is enabled

	outer    atomic.Uint64 // TLS handshakes whose (outer) SNI was the public name: ECH rejected, or a direct visit to the public name
	outerBad atomic.Uint64 // ... of which the certificate served was not valid for the public name
	warnMu   sync.Mutex
	lastWarn time.Time
}

// NoteOuterHandshake is called for every handshake whose SNI equals the public name. certOK says whether the
// certificate that was served is valid for it. It returns true when the caller should log a warning (rate limited).
// A handshake for the public name is what a client sends after Zoraxy rejected its ECH (stale or foreign config),
// but it is also what a direct visit to the public name looks like: the server cannot tell the two apart.
func (m *Manager) NoteOuterHandshake(certOK bool) (warn bool) {
	m.outer.Add(1)
	if certOK {
		return false
	}
	m.outerBad.Add(1)
	m.warnMu.Lock()
	defer m.warnMu.Unlock()
	if m.now().Sub(m.lastWarn) < 10*time.Minute {
		return false
	}
	m.lastWarn = m.now()
	return true
}

// OuterStats returns the number of handshakes addressed to the public name and how many were served an invalid certificate
func (m *Manager) OuterStats() (total, badCert uint64) {
	return m.outer.Load(), m.outerBad.Load()
}

var hostnameRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidatePublicName checks that the name is usable as an ECH public_name: a DNS host name, not an IP, lowercase, at most 255 bytes
func ValidatePublicName(name string) error {
	if name == "" {
		return errors.New("public name is required")
	}
	if len(name) > 253 {
		return errors.New("public name too long")
	}
	for _, r := range name {
		if r > 127 {
			return errors.New("public name must use ASCII letters only: convert an international name to punycode (xn--...) first")
		}
	}
	if name != strings.ToLower(name) {
		return errors.New("public name must be lowercase")
	}
	if !hostnameRe.MatchString(name) {
		return errors.New("public name must be a valid DNS host name (not an IP address, no wildcard)")
	}
	return nil
}

// Open loads (or initialises) the manager state under dir (conf/ech)
func Open(dir string) (*Manager, error) {
	m := &Manager{dir: dir, now: time.Now}
	m.settings = Settings{MaxNameLength: DefaultMaxNameLength, RetainHours: DefaultRetainHours}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	raw, err := os.ReadFile(filepath.Join(dir, "ech.json"))
	if err == nil {
		var fd fileData
		if err := json.Unmarshal(raw, &fd); err != nil {
			return nil, fmt.Errorf("ech.json is corrupt: %w", err)
		}
		m.settings = fd.Settings
		if m.settings.MaxNameLength == 0 {
			m.settings.MaxNameLength = DefaultMaxNameLength
		}
		if m.settings.RetainHours == 0 {
			m.settings.RetainHours = DefaultRetainHours
		}
		m.keys = fd.Keys
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	m.rebuildLocked()
	return m, nil
}

func (m *Manager) saveLocked() error {
	fd := fileData{Settings: m.settings, Keys: m.keys}
	raw, err := json.MarshalIndent(fd, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(m.dir, "ech.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, filepath.Join(m.dir, "ech.json"))
}

func (m *Manager) activeLocked() *Key {
	var best *Key
	for _, k := range m.keys {
		if k.State == StateActive && (best == nil || k.Created.After(best.Created)) {
			best = k
		}
	}
	return best
}

func (m *Manager) rebuildLocked() {
	out := make([]tls.EncryptedClientHelloKey, 0, len(m.keys))
	act := m.activeLocked()
	for _, k := range m.keys {
		priv, err1 := base64.StdEncoding.DecodeString(k.PrivateKey)
		cfg, err2 := base64.StdEncoding.DecodeString(k.Config)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: priv, SendAsRetry: k == act})
	}
	m.cached = out
}

// TLSKeys returns the keys crypto/tls should try. The slice is never nil (crypto/tls requires that);
// it is empty while ECH is disabled, in which case ECH offers are simply ignored like on any server without ECH.
func (m *Manager) TLSKeys() []tls.EncryptedClientHelloKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.settings.Enabled {
		return []tls.EncryptedClientHelloKey{}
	}
	return m.cached
}

// Apply installs the ECH callback on a listener TLS config. Clones of the config (per-SNI mTLS configs) keep it.
func (m *Manager) Apply(cfg *tls.Config) {
	cfg.GetEncryptedClientHelloKeys = func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		return m.TLSKeys(), nil
	}
}

// Settings returns the current settings
func (m *Manager) Settings() Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settings
}

// SetSettings validates and stores settings. Enabling with no key (or a changed public name) generates a new key.
func (m *Manager) SetSettings(s Settings) error {
	if s.MaxNameLength == 0 {
		s.MaxNameLength = DefaultMaxNameLength
	}
	if s.RetainHours == 0 {
		s.RetainHours = DefaultRetainHours
	}
	if s.MaxNameLength < 1 || s.MaxNameLength > 255 {
		return errors.New("max name length must be 1-255")
	}
	if s.RotateEveryHours < 0 || s.RotateEveryHours > 24*365 {
		return errors.New("rotation interval must be 0-8760 hours")
	}
	if s.RetainHours < 1 || s.RetainHours > 24*365 {
		return errors.New("retain window must be 1-8760 hours")
	}
	if s.Enabled || s.PublicName != "" {
		if err := ValidatePublicName(s.PublicName); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	oldSettings := m.settings
	oldKeys := append([]*Key(nil), m.keys...)
	oldStates := make([]Key, len(m.keys))
	for i, k := range m.keys {
		oldStates[i] = *k
	}
	m.settings = s
	if s.Enabled {
		a := m.activeLocked()
		if a == nil || a.PublicName != s.PublicName || a.MaxNameLength != s.MaxNameLength {
			//A config is bound to its public name: changing it requires a new key (the old one keeps decrypting)
			if _, err := m.rotateLocked(); err != nil {
				m.restore(oldSettings, oldKeys, oldStates)
				return err
			}
		}
	}
	m.rebuildLocked()
	if err := m.saveLocked(); err != nil {
		m.restore(oldSettings, oldKeys, oldStates)
		return err
	}
	return nil
}

func (m *Manager) restore(s Settings, keys []*Key, states []Key) {
	for i, k := range keys {
		*k = states[i]
	}
	m.settings, m.keys = s, keys
	m.rebuildLocked()
}

// BuildConfig serialises a single ECHConfig (RFC 9849 section 4)
func BuildConfig(configID uint8, pub []byte, maxNameLen int, publicName string) []byte {
	var body []byte
	body = append(body, configID)
	body = binary.BigEndian.AppendUint16(body, kemX25519)
	body = binary.BigEndian.AppendUint16(body, uint16(len(pub)))
	body = append(body, pub...)
	suites := []byte{}
	for _, aead := range []uint16{aeadAES128, aeadChaCha} {
		suites = binary.BigEndian.AppendUint16(suites, kdfSHA256)
		suites = binary.BigEndian.AppendUint16(suites, aead)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)))
	body = append(body, suites...)
	body = append(body, byte(maxNameLen), byte(len(publicName)))
	body = append(body, publicName...)
	body = binary.BigEndian.AppendUint16(body, 0) // no extensions
	out := binary.BigEndian.AppendUint16(nil, echVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

// ConfigList wraps configs into an ECHConfigList
func ConfigList(configs ...[]byte) []byte {
	n := 0
	for _, c := range configs {
		n += len(c)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(n))
	for _, c := range configs {
		out = append(out, c...)
	}
	return out
}

func randomID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) freeConfigIDLocked() (uint8, error) {
	used := map[uint8]bool{}
	for _, k := range m.keys {
		used[k.ConfigID] = true
	}
	for i := 0; i < 1000; i++ {
		b := make([]byte, 1)
		_, _ = rand.Read(b)
		if !used[b[0]] {
			return b[0], nil
		}
	}
	return 0, errors.New("could not find a free config id")
}

// rotateLocked creates a new active key and retires the current active one(s)
func (m *Manager) rotateLocked() (*Key, error) {
	if err := ValidatePublicName(m.settings.PublicName); err != nil {
		return nil, fmt.Errorf("set a valid public name first: %w", err)
	}
	if len(m.keys) >= MaxKeys {
		return nil, errors.New("too many ECH keys, delete retired ones first")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id, err := m.freeConfigIDLocked()
	if err != nil {
		return nil, err
	}
	now := m.now()
	for _, k := range m.keys {
		if k.State == StateActive {
			k.State = StateRetired
			k.RetiredAt = now
		}
	}
	k := &Key{
		ID: randomID(), ConfigID: id, PublicName: m.settings.PublicName, MaxNameLength: m.settings.MaxNameLength,
		State: StateActive, Created: now,
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
		Config:     base64.StdEncoding.EncodeToString(BuildConfig(id, priv.PublicKey().Bytes(), m.settings.MaxNameLength, m.settings.PublicName)),
	}
	m.keys = append(m.keys, k)
	return k, nil
}

// Rotate generates a new active key; the previous one becomes decrypt-only until it is purged
func (m *Manager) Rotate() (*Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, err := m.rotateLocked()
	if err != nil {
		return nil, err
	}
	m.rebuildLocked()
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return k, nil
}

// Retire makes a key decrypt-only (it stops being advertised). The active key can be retired too, which leaves no advertised config.
func (m *Manager) Retire(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.keys {
		if k.ID == id {
			if k.State != StateRetired {
				k.State = StateRetired
				k.RetiredAt = m.now()
			}
			m.rebuildLocked()
			return m.saveLocked()
		}
	}
	return errors.New("key not found")
}

// Delete removes a key for good. Clients still holding its config are told to retry with the current list.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, k := range m.keys {
		if k.ID == id {
			m.keys = append(m.keys[:i:i], m.keys[i+1:]...)
			m.rebuildLocked()
			return m.saveLocked()
		}
	}
	return errors.New("key not found")
}

// Maintain performs automatic rotation and purges expired retired keys. Call it periodically.
func (m *Manager) Maintain() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.settings.Enabled {
		return
	}
	now := m.now()
	changed := false
	if h := m.settings.RotateEveryHours; h > 0 {
		a := m.activeLocked()
		if a != nil && now.Sub(a.Created) >= time.Duration(h)*time.Hour {
			if _, err := m.rotateLocked(); err == nil {
				changed = true
			}
		}
	}
	keep := m.keys[:0:0]
	retain := time.Duration(m.settings.RetainHours) * time.Hour
	for _, k := range m.keys {
		if k.State == StateRetired && !k.RetiredAt.IsZero() && now.Sub(k.RetiredAt) >= retain {
			changed = true
			continue
		}
		keep = append(keep, k)
	}
	m.keys = keep
	if changed {
		m.rebuildLocked()
		_ = m.saveLocked()
	}
}

// KeyInfo is the public view of a key (no private material)
type KeyInfo struct {
	ID            string
	ConfigID      uint8
	PublicName    string
	MaxNameLength int
	State         string
	Created       time.Time
	RetiredAt     time.Time `json:",omitzero"`
	Config        string    // base64 ECHConfig
	Advertised    bool
}

// Keys lists the keys, newest first
func (m *Manager) Keys() []KeyInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	act := m.activeLocked()
	out := make([]KeyInfo, 0, len(m.keys))
	for _, k := range m.keys {
		out = append(out, KeyInfo{k.ID, k.ConfigID, k.PublicName, k.MaxNameLength, k.State, k.Created, k.RetiredAt, k.Config, k == act})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// ConfigListBase64 returns the base64 ECHConfigList to publish (only the newest active key), or "" if there is none
func (m *Manager) ConfigListBase64() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a := m.activeLocked()
	if a == nil {
		return ""
	}
	cfg, err := base64.StdEncoding.DecodeString(a.Config)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(ConfigList(cfg))
}

// SVCBExample returns a copy-ready HTTPS record for host
func SVCBExample(host, configList string, h3 bool) string {
	alpn := "h2,http/1.1"
	if h3 {
		alpn = "h3,h2,http/1.1"
	}
	return fmt.Sprintf("%s. 300 IN HTTPS 1 . alpn=%q ech=%q", host, alpn, configList)
}

// Export returns a key in the "ECH PEM" format (RFC 9934): a PRIVATE KEY block followed by an ECHCONFIG block.
// The output contains the private key: only hand it to an authenticated admin.
func (m *Manager) Export(id string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range m.keys {
		if k.ID == id {
			priv, _ := base64.StdEncoding.DecodeString(k.PrivateKey)
			cfg, _ := base64.StdEncoding.DecodeString(k.Config)
			return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8X25519(priv)})) +
				string(pem.EncodeToMemory(&pem.Block{Type: "ECHCONFIG", Bytes: cfg})), nil
		}
	}
	return "", errors.New("key not found")
}

// pkcs8X25519 wraps a raw X25519 key into PKCS#8 (OID 1.3.101.110)
func pkcs8X25519(raw []byte) []byte {
	hdr := []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20}
	return append(hdr, raw...)
}

// Import adds a key from the ECH PEM format produced by Export (or other tools following RFC 9934).
func (m *Manager) Import(pemText string) (*Key, error) {
	var privDER, cfg []byte
	rest := []byte(pemText)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case "PRIVATE KEY":
			privDER = b.Bytes
		case "ECHCONFIG":
			cfg = b.Bytes
		}
	}
	if len(privDER) != 48 || len(cfg) < 8 {
		return nil, errors.New("expected one PRIVATE KEY (X25519) and one ECHCONFIG PEM block")
	}
	raw := privDER[len(privDER)-32:]
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(cfg) != echVersion || int(binary.BigEndian.Uint16(cfg[2:]))+4 != len(cfg) {
		return nil, errors.New("ECHCONFIG is not a single well formed ECH config")
	}
	configID := cfg[4]
	if binary.BigEndian.Uint16(cfg[5:]) != kemX25519 {
		return nil, errors.New("only DHKEM(X25519) keys can be imported")
	}
	pubLen := int(binary.BigEndian.Uint16(cfg[7:]))
	if 9+pubLen > len(cfg) || string(cfg[9:9+pubLen]) != string(priv.PublicKey().Bytes()) {
		return nil, errors.New("the private key does not match the config")
	}
	p := 9 + pubLen
	if p+2 > len(cfg) {
		return nil, errors.New("truncated config")
	}
	p += 2 + int(binary.BigEndian.Uint16(cfg[p:]))
	if p+2 > len(cfg) || p+2+int(cfg[p+1]) > len(cfg) {
		return nil, errors.New("truncated config")
	}
	maxName := int(cfg[p])
	name := string(cfg[p+2 : p+2+int(cfg[p+1])])
	if err := ValidatePublicName(name); err != nil {
		return nil, fmt.Errorf("config public name: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.keys) >= MaxKeys {
		return nil, errors.New("too many ECH keys")
	}
	for _, k := range m.keys {
		if k.ConfigID == configID {
			return nil, errors.New("a key with this config id already exists")
		}
	}
	k := &Key{ID: randomID(), ConfigID: configID, PublicName: name, MaxNameLength: maxName, State: StateRetired,
		Created: m.now(), RetiredAt: m.now(),
		PrivateKey: base64.StdEncoding.EncodeToString(raw), Config: base64.StdEncoding.EncodeToString(cfg)}
	m.keys = append(m.keys, k)
	m.rebuildLocked()
	return k, m.saveLocked()
}

// Observe counts one TLS request (called by the proxy per request, only meaningful while ECH is enabled)
func (m *Manager) Observe(accepted bool) {
	if !m.Settings().Enabled {
		return
	}
	if accepted {
		m.accepted.Add(1)
	} else {
		m.plain.Add(1)
	}
}

// Stats returns the request counters since start
func (m *Manager) Stats() (accepted, plain uint64) {
	return m.accepted.Load(), m.plain.Load()
}
