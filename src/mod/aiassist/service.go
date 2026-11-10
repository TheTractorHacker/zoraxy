package aiassist

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Deps wires the service to the rest of the application. All fields are optional.
type Deps struct {
	// ConfDir is the configuration folder; files live in <ConfDir>/aiassist
	ConfDir string
	// Audit records one audit-log entry (feature, token counts, result; never prompt content)
	Audit func(event, detail string)
	// Posture feeds the configuration audit. Nil hides the feature.
	Posture PostureSource
	// Traffic feeds the rule suggestions.
	Traffic TrafficSource
	// Events finds the event an "Explain this" request is about (by id), so the model never sees
	// anything the server did not look up itself.
	Events EventLookup
}

// Service is the assistant. Creating it starts nothing: no goroutine, no timer, no network.
type Service struct {
	deps  Deps
	store *Store
	vault *Vault
	lim   *Limiter

	clientMu sync.Mutex
	// clientFn builds the HTTP client for a call (replaced in tests)
	clientFn func(allowLocal bool) *http.Client
}

// New creates the service.
func New(d Deps) *Service {
	dir := filepath.Join(d.ConfDir, dirName)
	return &Service{deps: d, store: NewStore(dir), vault: NewVault(dir), lim: NewLimiter(dir),
		clientFn: func(allowLocal bool) *http.Client { return newGuardedClient(allowLocal, 90*time.Second) }}
}

// Vault exposes the key vault (for tests and the backup exclusion).
func (s *Service) Vault() *Vault { return s.vault }

// AuditAvailable is true when a posture source is connected.
func (s *Service) AuditAvailable() bool { return s.deps.Posture != nil }

func (s *Service) redactor(st Settings) *Redactor {
	return &Redactor{P: Policy{SendIPs: st.SendIPs, SendPaths: st.SendPaths, MaskHosts: st.MaskHosts}, Pseudo: s.vault.Pseudonym}
}

func (s *Service) audit(event, detail string) {
	if s.deps.Audit != nil {
		s.deps.Audit(event, detail)
	}
}

// SettingsUpdate is the write model of the settings API. APIKey is write-only.
type SettingsUpdate struct {
	Settings
	APIKey   string `json:"api_key,omitempty"`
	ClearKey bool   `json:"clear_key,omitempty"`
}

// View returns the public settings.
func (s *Service) View() PublicView {
	st := s.store.Load()
	v := PublicView{Settings: st}
	set, last4, err := s.vault.Hint()
	v.KeySet, v.KeyLast4 = set, last4
	if err != nil {
		v.KeyError = err.Error()
	}
	return v
}

// Save validates and stores new settings. Changing where data goes or what is sent clears the
// "payload previewed" marks, so the admin sees the new payload before the next first use.
func (s *Service) Save(in SettingsUpdate) (PublicView, error) {
	old := s.store.Load()
	n := in.Settings
	n.PreviewAcked = old.PreviewAcked
	if n.Provider != old.Provider || n.Endpoint != old.Endpoint || n.SendIPs != old.SendIPs || n.SendPaths != old.SendPaths || n.MaskHosts != old.MaskHosts {
		n.PreviewAcked = map[string]bool{}
	}
	if err := n.Validate(); err != nil {
		return PublicView{}, err
	}
	if in.APIKey != "" {
		if err := s.vault.Set(in.APIKey); err != nil {
			return PublicView{}, err
		}
	} else if in.ClearKey {
		if err := s.vault.Clear(); err != nil {
			return PublicView{}, err
		}
	}
	if _, err := s.store.Save(n); err != nil {
		return PublicView{}, err
	}
	s.audit("ai.settings", "settings changed (enabled="+boolStr(n.Enabled)+", provider="+n.Provider+")")
	return s.View(), nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Usage returns the monthly counter.
func (s *Service) Usage() Usage { return s.lim.Usage() }

// PreviewView is the exact payload of a feature call.
type PreviewView struct {
	Feature    string `json:"feature"`
	Provider   string `json:"provider"`
	Host       string `json:"host"`
	Model      string `json:"model"`
	System     string `json:"system"`
	User       string `json:"user"`
	Schema     any    `json:"schema"`
	MaxTokens  int    `json:"max_tokens"`
	EstTokens  int64  `json:"estimated_input_tokens"`
	Acked      bool   `json:"acked"`
	DataPolicy string `json:"data_policy"`
}

func (s *Service) preview(st Settings, o *Outbound) *PreviewView {
	host := ""
	if u, err := url.Parse(st.Endpoint); err == nil {
		host = u.Host
	}
	pol := "real IPs: " + onOff(st.SendIPs) + "; paths and query parameter names: " + onOff(st.SendPaths) + "; query values: never; bodies and header values: never"
	return &PreviewView{Feature: o.Feature, Provider: st.Provider, Host: host, Model: st.Model, System: o.System, User: o.User,
		Schema: o.Schema, MaxTokens: o.MaxTokens, EstTokens: o.EstimateTokens(), Acked: st.PreviewAcked[o.Feature], DataPolicy: pol}
}

func onOff(b bool) string {
	if b {
		return "sent"
	}
	return "not sent"
}

// Ack records that the admin has seen the payload of a feature.
func (s *Service) Ack(feature string) error {
	if !inList(feature, []string{FeatureExplain, FeatureSuggest, featureRule, FeatureAudit}) {
		return errors.New("unknown feature")
	}
	_, err := s.store.Update(func(st *Settings) { st.PreviewAcked[feature] = true })
	return err
}

// errors for the API layer
var (
	ErrDisabled    = errors.New("the AI assistant is turned off")
	ErrFeatureOff  = errors.New("this AI feature is turned off in the AI assistant settings")
	ErrNeedPreview = errors.New("preview what will be sent before the first use of this feature")
	ErrNoKey       = errors.New("no API key is set")
)

const featureRule = "rule"

// gate checks the switches in the order that makes a disabled assistant cost nothing.
func (s *Service) gate(feature string, needAck bool) (Settings, error) {
	st := s.store.Load()
	if !st.Enabled {
		return st, ErrDisabled
	}
	tog := feature
	if feature == featureRule {
		tog = FeatureSuggest
	}
	if feature != "test" && !st.FeatureOn(tog) {
		return st, ErrFeatureOff
	}
	if feature == FeatureAudit && !s.AuditAvailable() {
		return st, ErrFeatureOff
	}
	if needAck && !st.PreviewAcked[feature] {
		return st, ErrNeedPreview
	}
	return st, nil
}

// call sends an already redacted Outbound. It enforces budget and rate limit, never logs content.
func (s *Service) call(ctx context.Context, st Settings, o *Outbound) (*Response, error) {
	key, hasKey, kerr := s.vault.Get()
	if kerr != nil {
		return nil, kerr
	}
	if !hasKey && st.Provider == ProviderAnthropic {
		return nil, ErrNoKey
	}
	est := o.EstimateTokens() + int64(o.MaxTokens)
	res, err := s.lim.Reserve(o.Feature, est, st.MonthlyCap, st.RatePerMin)
	if err != nil {
		s.audit("ai."+o.Feature, "refused: "+err.Error())
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	hc := s.clientFn(st.Provider == ProviderOpenAICompatible && st.LocalModel)
	var resp *Response
	switch st.Provider {
	case ProviderAnthropic:
		resp, err = callAnthropic(cctx, hc, st.Endpoint, key, st.Model, o)
	default:
		resp, err = callOpenAI(cctx, hc, st.Endpoint, key, st.Model, o)
	}
	var in, out int64
	if resp != nil {
		in, out = resp.InputTokens, resp.OutputTokens
	}
	if resp == nil && err != nil && !reachedNetwork(err) {
		res.Cancel()
	} else {
		res.Done(in + out)
	}
	result := "ok"
	if err != nil {
		result = "error: " + scrubKey(err.Error(), key)
	}
	s.audit("ai."+o.Feature, "tokens in="+itoa(in)+" out="+itoa(out)+" result="+capRunes(result, 160))
	if err != nil {
		return resp, errors.New(scrubKey(err.Error(), key))
	}
	return resp, nil
}

// reachedNetwork is false for errors that happen before a request could have been sent.
func reachedNetwork(err error) bool {
	var pe *providerError
	if errors.As(err, &pe) {
		return pe.msg != "invalid endpoint"
	}
	return true
}

func scrubKey(msg, key string) string {
	if len(key) >= 6 {
		msg = strings.ReplaceAll(msg, key, "[key]")
	}
	return msg
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Test sends a tiny request to check endpoint, model and key.
func (s *Service) Test(ctx context.Context) (string, error) {
	st, err := s.gate("test", false)
	if err != nil {
		return "", err
	}
	r := s.redactor(st)
	schema := objSchema(map[string]any{"ok": map[string]any{"type": "boolean"}}, "ok")
	o, err := r.Seal("test", "Connectivity check. Call the tool with ok set to true.", map[string]any{"ping": "ok"}, "report", "Report the result.", schema, 64)
	if err != nil {
		return "", err
	}
	resp, err := s.call(ctx, st, o)
	if err != nil {
		return "", err
	}
	var v struct {
		OK bool `json:"ok"`
	}
	if strictDecode(resp.JSON, &v) != nil || !v.OK {
		return "", invalid("test reply")
	}
	return "Connected to " + st.Model, nil
}
