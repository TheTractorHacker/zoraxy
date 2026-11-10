package aiassist

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const dirName = "aiassist"

// Providers
const (
	ProviderAnthropic        = "anthropic"
	ProviderOpenAICompatible = "openai_compatible"

	DefaultAnthropicEndpoint = "https://api.anthropic.com"
	DefaultAnthropicModel    = "claude-sonnet-5-5"
)

// Features (each has its own toggle and API)
const (
	FeatureExplain = "explain"
	FeatureSuggest = "suggest"
	FeatureAudit   = "audit"
)

var allFeatures = []string{FeatureExplain, FeatureSuggest, FeatureAudit}

// Settings are stored in <conf>/aiassist/settings.json. The API key is NOT part of it.
type Settings struct {
	Enabled    bool   `json:"enabled"`
	Provider   string `json:"provider"`
	Endpoint   string `json:"endpoint"`
	Model      string `json:"model"`
	LocalModel bool   `json:"local_model"` // the admin confirms the endpoint is a model on this machine / LAN

	FeatureExplain bool `json:"feature_explain"`
	FeatureSuggest bool `json:"feature_suggest"`
	FeatureAudit   bool `json:"feature_audit"`

	// Data policy
	SendIPs    bool  `json:"send_ips"`   // real IPs; default off (stable pseudonyms are sent instead)
	SendPaths  bool  `json:"send_paths"` // request paths and query parameter NAMES (values are never sent)
	MaskHosts  bool  `json:"mask_hosts"` // replace host names by pseudonyms
	MonthlyCap int64 `json:"monthly_token_budget"`
	RatePerMin int   `json:"rate_per_minute"`

	// PreviewAcked records the features whose outbound payload the admin has seen
	PreviewAcked map[string]bool `json:"preview_acked,omitempty"`
}

// DefaultSettings: everything off, safest data policy.
func DefaultSettings() Settings {
	return Settings{
		Provider: ProviderAnthropic, Endpoint: DefaultAnthropicEndpoint, Model: DefaultAnthropicModel,
		FeatureExplain: true, FeatureSuggest: true, FeatureAudit: true,
		SendPaths: true, MonthlyCap: 500000, RatePerMin: 6,
		PreviewAcked: map[string]bool{},
	}
}

var modelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,99}$`)

// Validate normalises s in place and rejects unsafe values.
func (s *Settings) Validate() error {
	s.Provider = strings.TrimSpace(s.Provider)
	s.Endpoint = strings.TrimRight(strings.TrimSpace(s.Endpoint), "/")
	s.Model = strings.TrimSpace(s.Model)
	if s.Provider != ProviderAnthropic && s.Provider != ProviderOpenAICompatible {
		return errors.New("provider must be anthropic or openai_compatible")
	}
	if s.Endpoint == "" && s.Provider == ProviderAnthropic {
		s.Endpoint = DefaultAnthropicEndpoint
	}
	if s.Model == "" && s.Provider == ProviderAnthropic {
		s.Model = DefaultAnthropicModel
	}
	if !modelRe.MatchString(s.Model) {
		return errors.New("model name is empty or contains unsupported characters")
	}
	if s.LocalModel && s.Provider != ProviderOpenAICompatible {
		return errors.New("the local model option is only available for the OpenAI-compatible provider")
	}
	if _, err := ParseEndpoint(s.Endpoint, s.Provider, s.LocalModel); err != nil {
		return err
	}
	if s.MonthlyCap < 0 || s.MonthlyCap > 1_000_000_000 {
		return errors.New("monthly token budget must be between 0 and 1,000,000,000")
	}
	if s.RatePerMin < 1 || s.RatePerMin > 120 {
		return errors.New("rate limit must be between 1 and 120 calls per minute")
	}
	if s.PreviewAcked == nil {
		s.PreviewAcked = map[string]bool{}
	}
	return nil
}

// ParseEndpoint validates the configured endpoint URL syntactically (the address check happens at
// connect time, see ssrf.go). Plain http is only accepted for a local model.
func ParseEndpoint(raw, provider string, local bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("endpoint must be a full URL such as https://api.anthropic.com")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("endpoint must not contain credentials, a query or a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !(local && provider == ProviderOpenAICompatible) {
			return nil, errors.New("plain http endpoints are only allowed for a local model; use https")
		}
	default:
		return nil, errors.New("endpoint must use https (or http for a local model)")
	}
	if err := checkLiteralHost(u.Hostname(), provider == ProviderOpenAICompatible && local); err != nil {
		return nil, err
	}
	return u, nil
}

// Store persists Settings.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore keeps files in dir (<conf>/aiassist).
func NewStore(dir string) *Store { return &Store{dir: dir} }

// Dir is the folder holding settings, key file and usage counters.
func (st *Store) Dir() string { return st.dir }

// Load returns the stored settings or the defaults. A damaged file yields the defaults (disabled).
func (st *Store) Load() Settings {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.loadLocked()
}

func (st *Store) loadLocked() Settings {
	s := DefaultSettings()
	b, err := os.ReadFile(filepath.Join(st.dir, "settings.json"))
	if err != nil {
		return s
	}
	var f Settings = DefaultSettings()
	if json.Unmarshal(b, &f) != nil {
		return s
	}
	if f.Validate() != nil {
		d := DefaultSettings() // an invalid stored file must never leave the feature on
		return d
	}
	return f
}

// Save validates and writes the settings.
func (st *Store) Save(s Settings) (Settings, error) {
	if err := s.Validate(); err != nil {
		return s, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	b, _ := json.MarshalIndent(s, "", " ")
	return s, writeFileAtomic(filepath.Join(st.dir, "settings.json"), b, 0o600)
}

// Update applies fn to the stored settings atomically with respect to other Update calls.
func (st *Store) Update(fn func(*Settings)) (Settings, error) {
	st.mu.Lock()
	s := st.loadLocked()
	st.mu.Unlock()
	fn(&s)
	return st.Save(s)
}

// FeatureOn reports whether a feature toggle is on.
func (s Settings) FeatureOn(f string) bool {
	switch f {
	case FeatureExplain:
		return s.FeatureExplain
	case FeatureSuggest:
		return s.FeatureSuggest
	case FeatureAudit:
		return s.FeatureAudit
	}
	return false
}

// PublicView is what the settings API returns. It has no field that can hold the key.
type PublicView struct {
	Settings
	KeySet   bool   `json:"key_set"`
	KeyLast4 string `json:"key_last4,omitempty"`
	KeyError string `json:"key_error,omitempty"`
}
