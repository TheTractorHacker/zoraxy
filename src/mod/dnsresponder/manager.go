package dnsresponder

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
)

// Manager owns the configuration and the running Server, and serves the admin API
type Manager struct {
	mu      sync.Mutex
	cfg     Config
	srv     *Server
	names   NameSource
	save    func(Config) error
	logf    func(string, error)
	lastErr string
}

// NewManager creates a manager. save persists a config after it has been applied successfully.
func NewManager(initial Config, names NameSource, save func(Config) error, logf func(string, error)) *Manager {
	initial.Normalize()
	if logf == nil {
		logf = func(string, error) {}
	}
	return &Manager{cfg: initial, names: names, save: save, logf: logf}
}

// Start starts the responder if the stored configuration enables it
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startLocked(m.cfg)
}

func (m *Manager) startLocked(cfg Config) error {
	if m.srv != nil {
		m.srv.Stop()
		m.srv = nil
	}
	m.lastErr = ""
	if !cfg.Enabled {
		return nil
	}
	srv, err := NewServer(cfg, m.names, m.logf)
	if err == nil {
		err = srv.Start()
	}
	if err != nil {
		m.lastErr = err.Error()
		m.logf("DNS responder not started", err)
		return err
	}
	m.srv = srv
	m.logf("DNS responder listening on "+srv.Addr()+" (UDP+TCP)", nil)
	return nil
}

// Stop shuts the responder down
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.srv != nil {
		m.srv.Stop()
		m.srv = nil
	}
}

// Apply validates, applies and persists a new configuration. On failure the
// previous configuration keeps running.
func (m *Manager) Apply(cfg Config) error {
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.cfg
	if err := m.startLocked(cfg); err != nil {
		m.startLocked(old) //restore the previous state
		return err
	}
	m.cfg = cfg
	if m.save != nil {
		if err := m.save(cfg); err != nil {
			return err
		}
	}
	return nil
}

// Status is the runtime state shown in the UI
type Status struct {
	Running bool   `json:"running"`
	Bound   string `json:"bound"`
	Error   string `json:"error,omitempty"`
	Stats   Stats  `json:"stats"`
}

// Config returns the active configuration
func (m *Manager) Config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Status returns the runtime state
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Error: m.lastErr}
	if m.srv != nil {
		st.Running, st.Bound, st.Stats = true, m.srv.Addr(), m.srv.Stats()
	}
	return st
}

// HandleAPI serves GET (config + status) and POST (form field "config" = JSON Config).
// Authentication and CSRF are provided by the router it is registered on.
func (m *Manager) HandleAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fail := func(msg string) {
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{"config": m.Config(), "status": m.Status()})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		if err := r.ParseForm(); err != nil {
			fail("invalid request")
			return
		}
		cfg := DefaultConfig()
		if err := json.Unmarshal([]byte(r.PostFormValue("config")), &cfg); err != nil {
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &typeErr) && typeErr.Field != "" {
				//e.g. a negative number for an unsigned field: name the field instead of blaming the JSON
				fail(typeErr.Field + " has an invalid value (a whole number inside the allowed range is expected)")
				return
			}
			fail("config is not valid JSON")
			return
		}
		if err := m.Apply(cfg); err != nil {
			fail(err.Error())
			return
		}
		json.NewEncoder(w).Encode("OK")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fail("method not allowed")
	}
}
