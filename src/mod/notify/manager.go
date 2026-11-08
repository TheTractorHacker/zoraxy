package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

// SecretMask replaces the webhook secret in API responses; sending it back keeps the stored secret.
const SecretMask = "********"

// DefaultExpiryWarnDays is used when the config does not set a value.
const DefaultExpiryWarnDays = 14

// Config is persisted as JSON (mode 0600, it holds webhook secrets).
type Config struct {
	Webhooks            []WebhookConfig `json:"webhooks"`
	Command             CommandConfig   `json:"command"`
	AllowPrivateTargets bool            `json:"allowPrivateTargets"`
	ExpiryWarnDays      int             `json:"expiryWarnDays"`

	// Notification centre (center.go): channels, delivery rules
	Channels []ChannelConfig `json:"channels,omitempty"`
	Rules    *Rules          `json:"rules,omitempty"` // nil = DefaultRules()
}

// Manager owns the hook configuration and the dispatcher.
type Manager struct {
	path            string
	commandsAllowed bool
	offline         func() bool
	logf            func(format string, args ...any)

	mu  sync.RWMutex
	cfg Config

	Dispatcher *Dispatcher
	center     *center
}

// NewManager loads (or starts empty) the config at path. commandsAllowed is the -allow_hook_commands flag.
func NewManager(path string, commandsAllowed bool, offline func() bool, logf func(string, ...any)) (*Manager, error) {
	m := &Manager{path: path, commandsAllowed: commandsAllowed, offline: offline, logf: logf}
	if logf == nil {
		m.logf = func(string, ...any) {}
	}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &m.cfg); err != nil {
			return nil, errors.New("malformed notification config: " + err.Error())
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	m.Dispatcher = NewDispatcher(m.sinks)
	m.Dispatcher.Logf = func(f string, a ...any) { m.logf(f, a...) }
	m.initCenter()
	return m, nil
}

// CommandsAllowed tells whether command hooks may run in this process.
func (m *Manager) CommandsAllowed() bool { return m.commandsAllowed }

func (m *Manager) sinks() []Sink {
	return append(m.baseSinks(), m.channelSinks()...)
}

// baseSinks are the webhooks and the command hook (every delivery is added to the delivery log)
func (m *Manager) baseSinks() []Sink {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Sink{}
	for _, w := range m.cfg.Webhooks {
		out = append(out, &loggedSink{inner: &WebhookSink{Cfg: w, AllowPrivate: m.cfg.AllowPrivateTargets, Offline: m.offline}, kind: "webhook", m: m})
	}
	out = append(out, &loggedSink{inner: &CommandSink{Cfg: m.cfg.Command, Allowed: m.commandsAllowed, Logf: m.logf}, kind: "command", m: m})
	return out
}

// Emit forwards to the dispatcher.
func (m *Manager) Emit(ev Event) { m.Dispatcher.Emit(ev) }

// WarnDays is the number of days before expiry at which certificate.expiring is emitted.
func (m *Manager) WarnDays() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg.ExpiryWarnDays > 0 {
		return m.cfg.ExpiryWarnDays
	}
	return DefaultExpiryWarnDays
}

func (m *Manager) save() error {
	js, _ := json.MarshalIndent(m.cfg, "", " ")
	if err := os.MkdirAll(filepath.Dir(m.path), 0o775); err != nil {
		return err
	}
	if err := os.WriteFile(m.path, js, 0o600); err != nil {
		return err
	}
	return os.Chmod(m.path, 0o600)
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func validEvents(list []string) ([]string, error) {
	out := []string{}
	for _, e := range list {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		ok := IsKnownEvent(e)
		for _, k := range AllCertEvents {
			if k == e {
				ok = true
			}
		}
		if !ok {
			return nil, errors.New("unknown event " + e)
		}
		out = append(out, e)
	}
	return out, nil
}

// SaveWebhook creates (empty ID) or updates a webhook and returns its ID.
func (m *Manager) SaveWebhook(w WebhookConfig) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Name = strings.TrimSpace(w.Name)
	if w.Name == "" {
		return "", errors.New("name is required")
	}
	if err := ValidateWebhookURL(w.URL, m.cfg.AllowPrivateTargets); err != nil {
		return "", err
	}
	ev, err := validEvents(w.Events)
	if err != nil {
		return "", err
	}
	w.Events = ev
	if err := ValidateTemplate(w.Template); err != nil {
		return "", err
	}
	for i := range m.cfg.Webhooks {
		if m.cfg.Webhooks[i].ID == w.ID && w.ID != "" {
			if w.Secret == SecretMask {
				w.Secret = m.cfg.Webhooks[i].Secret
			}
			m.cfg.Webhooks[i] = w
			return w.ID, m.save()
		}
	}
	if w.ID != "" {
		return "", errors.New("webhook not found")
	}
	if w.Secret == SecretMask {
		w.Secret = ""
	}
	w.ID = newID()
	m.cfg.Webhooks = append(m.cfg.Webhooks, w)
	return w.ID, m.save()
}

// DeleteWebhook removes a webhook.
func (m *Manager) DeleteWebhook(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.cfg.Webhooks {
		if m.cfg.Webhooks[i].ID == id {
			m.cfg.Webhooks = append(m.cfg.Webhooks[:i], m.cfg.Webhooks[i+1:]...)
			return m.save()
		}
	}
	return errors.New("webhook not found")
}

// SetCommand stores the command hook. It is refused unless -allow_hook_commands was given.
func (m *Manager) SetCommand(c CommandConfig) error {
	if !m.commandsAllowed {
		return errors.New("command hooks are disabled: start Zoraxy with -allow_hook_commands to configure them")
	}
	if c.Enabled || c.Path != "" {
		if err := ValidateCommandPath(c.Path); err != nil {
			return err
		}
	}
	ev, err := validEvents(c.Events)
	if err != nil {
		return err
	}
	c.Events = ev
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Command = c
	return m.save()
}

// SetOptions updates the global options.
func (m *Manager) SetOptions(allowPrivate bool, warnDays int) error {
	if warnDays < 0 || warnDays > 365 {
		return errors.New("warning days must be between 0 and 365")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.AllowPrivateTargets = allowPrivate
	m.cfg.ExpiryWarnDays = warnDays
	return m.save()
}

// View is the API representation (secrets masked).
func (m *Manager) View() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hooks := make([]WebhookConfig, 0, len(m.cfg.Webhooks))
	for _, w := range m.cfg.Webhooks {
		if w.Secret != "" {
			w.Secret = SecretMask
		}
		hooks = append(hooks, w)
	}
	warn := m.cfg.ExpiryWarnDays
	if warn == 0 {
		warn = DefaultExpiryWarnDays
	}
	return map[string]any{
		"webhooks":            hooks,
		"command":             m.cfg.Command,
		"commandsAllowed":     m.commandsAllowed,
		"allowPrivateTargets": m.cfg.AllowPrivateTargets,
		"expiryWarnDays":      warn,
		"events":              AllCertEvents,
		"offline":             m.offline != nil && m.offline(),
	}
}

// SendTest delivers a test event to one webhook synchronously and reports the result.
func (m *Manager) SendTest(id string) error {
	m.mu.RLock()
	var found *WebhookConfig
	for i := range m.cfg.Webhooks {
		if m.cfg.Webhooks[i].ID == id {
			c := m.cfg.Webhooks[i]
			found = &c
		}
	}
	allow := m.cfg.AllowPrivateTargets
	m.mu.RUnlock()
	if found == nil {
		return errors.New("webhook not found")
	}
	found.Enabled = true
	sink := &WebhookSink{Cfg: *found, AllowPrivate: allow, Offline: m.offline, Attempts: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return sink.Deliver(ctx, Event{Event: EventTest, Time: time.Now().UTC(), Source: "test", Subject: "test event from Zoraxy"})
}

func jsonOut(w http.ResponseWriter, v any) {
	js, _ := json.Marshal(v)
	utils.SendJSONResponse(w, string(js))
}

// HandleHooks serves GET (config view) and POST op=saveWebhook|deleteWebhook|testWebhook|saveCommand|setOptions.
func (m *Manager) HandleHooks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, m.View())
		return
	}
	fail := func(err error) { utils.SendErrorResponse(w, strings.ReplaceAll(err.Error(), `"`, `'`)) }
	op, _ := utils.PostPara(r, "op")
	splitEvents := func() []string {
		v, _ := utils.PostPara(r, "events")
		return strings.Split(v, ",")
	}
	switch op {
	case "saveWebhook":
		wh := WebhookConfig{Events: splitEvents()}
		wh.ID, _ = utils.PostPara(r, "id")
		wh.Name, _ = utils.PostPara(r, "name")
		wh.URL, _ = utils.PostPara(r, "url")
		wh.Secret, _ = utils.PostPara(r, "secret")
		wh.Enabled, _ = utils.PostBool(r, "enabled")
		wh.Template, _ = utils.PostPara(r, "template")
		id, err := m.SaveWebhook(wh)
		if err != nil {
			fail(err)
			return
		}
		jsonOut(w, map[string]string{"id": id})
	case "deleteWebhook":
		id, _ := utils.PostPara(r, "id")
		if err := m.DeleteWebhook(id); err != nil {
			fail(err)
			return
		}
		utils.SendOK(w)
	case "testWebhook":
		id, _ := utils.PostPara(r, "id")
		if err := m.SendTest(id); err != nil {
			fail(err)
			return
		}
		utils.SendOK(w)
	case "saveCommand":
		c := CommandConfig{Events: splitEvents()}
		c.Enabled, _ = utils.PostBool(r, "enabled")
		c.Path, _ = utils.PostPara(r, "path")
		args, _ := utils.PostPara(r, "args") // JSON array of strings
		if args != "" {
			if err := json.Unmarshal([]byte(args), &c.Args); err != nil {
				fail(errors.New("args must be a JSON array of strings"))
				return
			}
		}
		if t, err := utils.PostPara(r, "timeout"); err == nil {
			json.Unmarshal([]byte(t), &c.Timeout)
		}
		if err := m.SetCommand(c); err != nil {
			fail(err)
			return
		}
		utils.SendOK(w)
	case "setOptions":
		allow, _ := utils.PostBool(r, "allowPrivateTargets")
		var days int
		if v, err := utils.PostPara(r, "expiryWarnDays"); err == nil {
			if err := json.Unmarshal([]byte(v), &days); err != nil {
				fail(errors.New("invalid number of days"))
				return
			}
		}
		if err := m.SetOptions(allow, days); err != nil {
			fail(err)
			return
		}
		utils.SendOK(w)
	default:
		utils.SendErrorResponse(w, "invalid operation")
	}
}
