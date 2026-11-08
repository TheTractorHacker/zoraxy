package plugins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Hook runtime

	Per plugin state for the filter API: admin settings (global attach, fail-closed
	consent), the circuit breaker and the secret token Zoraxy sends to the plugin.
*/

const (
	defaultBreakerThreshold = 5
	defaultBreakerCooldown  = 30 * time.Second
	hookDBTable             = "plugin_hooks"
)

// hookTunables can be overridden in tests
type hookTunables struct {
	BreakerThreshold int
	BreakerCooldown  time.Duration
}

func (m *Manager) breakerThreshold() int {
	if m.hookCfg.BreakerThreshold > 0 {
		return m.hookCfg.BreakerThreshold
	}
	return defaultBreakerThreshold
}

func (m *Manager) breakerCooldown() time.Duration {
	if m.hookCfg.BreakerCooldown > 0 {
		return m.hookCfg.BreakerCooldown
	}
	return defaultBreakerCooldown
}

type hookRuntime struct {
	mu                sync.Mutex
	token             string
	global            bool
	failClosedConsent bool
	consecFail        int
	openUntil         time.Time
	probing           bool
}

var errBreakerOpen = errors.New("circuit breaker open")

// HookAdminState is the admin controlled hook state of a plugin, as shown in the UI
type HookAdminState struct {
	Global             bool   //Attached to all endpoints
	FailClosedDeclared bool   //The manifest asks for fail_closed
	FailClosedConsent  bool   //The admin allowed fail_closed
	EffectivePolicy    string //fail_open or fail_closed
	BreakerOpen        bool
	ConsecutiveFailure int
}

func (p *Plugin) hookAdminState() HookAdminState {
	p.hook.mu.Lock()
	defer p.hook.mu.Unlock()
	declared := p.Spec != nil && p.Spec.Hooks != nil && p.Spec.Hooks.FailurePolicy == zoraxyPlugin.FailureClosed
	policy := zoraxyPlugin.FailureOpen
	if declared && p.hook.failClosedConsent {
		policy = zoraxyPlugin.FailureClosed
	}
	return HookAdminState{
		Global:             p.hook.global,
		FailClosedDeclared: declared,
		FailClosedConsent:  p.hook.failClosedConsent,
		EffectivePolicy:    string(policy),
		BreakerOpen:        time.Now().Before(p.hook.openUntil),
		ConsecutiveFailure: p.hook.consecFail,
	}
}

func (p *Plugin) isGlobal() bool {
	p.hook.mu.Lock()
	defer p.hook.mu.Unlock()
	return p.hook.global
}

// failsClosed is true only if the manifest declares fail_closed AND the admin consented
func (p *Plugin) failsClosed() bool {
	p.hook.mu.Lock()
	defer p.hook.mu.Unlock()
	return p.Spec != nil && p.Spec.Hooks != nil &&
		p.Spec.Hooks.FailurePolicy == zoraxyPlugin.FailureClosed && p.hook.failClosedConsent
}

func (p *Plugin) invokeToken() string {
	p.hook.mu.Lock()
	defer p.hook.mu.Unlock()
	return p.hook.token
}

func (p *Plugin) priority() int {
	if p.Spec != nil && p.Spec.Hooks != nil {
		return p.Spec.Hooks.Priority
	}
	return 0
}

func (p *Plugin) callTimeout() time.Duration {
	if p.Spec == nil {
		return time.Duration(zoraxyPlugin.DefaultHookTimeoutMs) * time.Millisecond
	}
	return p.Spec.Hooks.EffectiveTimeout() //nil-safe
}

// generateInvokeToken creates a fresh per-start secret for calls from Zoraxy to the plugin
func (p *Plugin) generateInvokeToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	p.hook.mu.Lock()
	p.hook.token = tok
	p.hook.mu.Unlock()
	return tok, nil
}

/* Circuit breaker */

// breakerAdmit reports whether a call may be made now
func (m *Manager) breakerAdmit(p *Plugin) bool {
	p.hook.mu.Lock()
	defer p.hook.mu.Unlock()
	if p.hook.consecFail < m.breakerThreshold() {
		return true
	}
	if time.Now().Before(p.hook.openUntil) {
		return false
	}
	//Cooldown over: let exactly one probe through (half open)
	if p.hook.probing {
		return false
	}
	p.hook.probing = true
	return true
}

func (m *Manager) breakerRecord(p *Plugin, err error) {
	p.hook.mu.Lock()
	wasOpen := p.hook.consecFail >= m.breakerThreshold()
	p.hook.probing = false
	var opened, recovered bool
	if err == nil {
		recovered = wasOpen
		p.hook.consecFail = 0
		p.hook.openUntil = time.Time{}
	} else {
		p.hook.consecFail++
		if p.hook.consecFail >= m.breakerThreshold() {
			p.hook.openUntil = time.Now().Add(m.breakerCooldown())
			opened = !wasOpen
		}
	}
	n := p.hook.consecFail
	p.hook.mu.Unlock()

	//Log once per state change, not once per request
	if opened {
		m.logf(p, fmt.Sprintf("circuit breaker opened after %d consecutive failures (last: %v), skipping plugin for %s", n, err, m.breakerCooldown()), nil)
	}
	if recovered {
		m.logf(p, "circuit breaker closed, plugin is responding again", nil)
	}
}

func (m *Manager) logf(p *Plugin, msg string, err error) {
	if m.Options == nil || m.Options.Logger == nil {
		return
	}
	if p != nil && p.Spec != nil {
		m.LogForPlugin(p, msg, err)
		return
	}
	m.Log(msg, err)
}

/* Calling the plugin */

// hookHTTPClient is shared by all plugin calls. Redirects are never followed, the
// proxy environment is ignored, and every call also carries its own context timeout.
var hookHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 1 * time.Second}).DialContext,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: time.Duration(zoraxyPlugin.MaxHookTimeoutMs) * time.Millisecond,
		DisableCompression:    true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func pluginURL(p *Plugin, path string) string {
	u := url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(p.AssignedPort)), Path: path}
	return u.String()
}

// callPlugin POSTs a JSON payload to a plugin endpoint and returns the (size limited) reply body.
// It returns the status code of the plugin so the caller can interpret it.
func (m *Manager) callPlugin(p *Plugin, path string, payload []byte, requestID string, limit int64) (int, []byte, error) {
	if p.AssignedPort <= 0 {
		return 0, nil, errors.New("plugin has no assigned port")
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.callTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pluginURL(p, path), bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(zoraxyPlugin.RequestIDHeader, requestID)
	if tok := p.invokeToken(); tok != "" {
		req.Header.Set(zoraxyPlugin.InvokeTokenHeader, tok)
	}
	resp, err := hookHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(body)) > limit {
		return resp.StatusCode, nil, errors.New("plugin reply too large")
	}
	return resp.StatusCode, body, nil
}

// callFilter calls the filter endpoint of the plugin for a stage and returns the validated verdict.
// The circuit breaker is consulted and updated here.
func (m *Manager) callFilter(p *Plugin, stage zoraxyPlugin.HookStage, fr *zoraxyPlugin.FilterRequest) (*cleanVerdict, error) {
	if !m.breakerAdmit(p) {
		return nil, errBreakerOpen
	}
	cv, err := m.doFilterCall(p, stage, fr)
	m.breakerRecord(p, err)
	return cv, err
}

func (m *Manager) doFilterCall(p *Plugin, stage zoraxyPlugin.HookStage, fr *zoraxyPlugin.FilterRequest) (*cleanVerdict, error) {
	payload, err := json.Marshal(fr)
	if err != nil {
		return nil, err
	}
	path := p.Spec.Hooks.PathForStage(stage)
	status, body, err := m.callPlugin(p, path, payload, fr.RequestID, zoraxyPlugin.MaxVerdictBytes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("plugin answered HTTP %d", status)
	}
	var verdict zoraxyPlugin.FilterVerdict
	if err := json.Unmarshal(body, &verdict); err != nil {
		return nil, fmt.Errorf("invalid verdict JSON: %v", err)
	}
	cv, err := sanitizeVerdict(stage, &verdict)
	if err != nil {
		return nil, fmt.Errorf("invalid verdict: %v", err)
	}
	return cv, nil
}

/* Admin settings */

type hookDBRecord struct {
	Global            bool
	FailClosedConsent bool
}

// loadHookAdminSettings restores the admin settings of a plugin from the database
func (m *Manager) loadHookAdminSettings(p *Plugin) {
	if m.Options == nil || m.Options.Database == nil || m.Options.Database.Backend == nil {
		return
	}
	var rec hookDBRecord
	if err := m.Options.Database.Read(hookDBTable, p.Spec.ID, &rec); err != nil {
		return
	}
	p.hook.mu.Lock()
	p.hook.global = rec.Global
	p.hook.failClosedConsent = rec.FailClosedConsent
	p.hook.mu.Unlock()
}

// SetHookAdminSettings changes the admin controlled hook settings of a plugin.
// nil leaves a value unchanged. Fail-closed consent can only be granted for a plugin
// that declares fail_closed in its manifest.
func (m *Manager) SetHookAdminSettings(pluginID string, global *bool, failClosedConsent *bool) error {
	p, err := m.GetPluginByID(pluginID)
	if err != nil {
		return err
	}
	if p.Spec.Type != zoraxyPlugin.PluginType_Router {
		return errors.New("plugin is not a router type plugin")
	}
	hasHooks := p.Spec.Hooks != nil && len(p.Spec.Hooks.Stages) > 0
	if global != nil && *global && !hasHooks && !p.AcceptDynamicRoute() {
		return errors.New("plugin has no filter hooks or dynamic capture, nothing to attach globally")
	}
	if failClosedConsent != nil && *failClosedConsent &&
		(p.Spec.Hooks == nil || p.Spec.Hooks.FailurePolicy != zoraxyPlugin.FailureClosed) {
		return errors.New("plugin does not declare fail_closed in its manifest")
	}
	p.hook.mu.Lock()
	if global != nil {
		p.hook.global = *global
	}
	if failClosedConsent != nil {
		p.hook.failClosedConsent = *failClosedConsent
	}
	rec := hookDBRecord{Global: p.hook.global, FailClosedConsent: p.hook.failClosedConsent}
	p.hook.mu.Unlock()

	if m.Options != nil && m.Options.Database != nil && m.Options.Database.Backend != nil {
		m.Options.Database.NewTable(hookDBTable)
		return m.Options.Database.Write(hookDBTable, pluginID, rec)
	}
	return nil
}

// HandleSetPluginHookSettings is the admin API: POST plugin_id, optional global, optional fail_closed
func (m *Manager) HandleSetPluginHookSettings(w http.ResponseWriter, r *http.Request) {
	pluginID, err := utils.PostPara(r, "plugin_id")
	if err != nil {
		utils.SendErrorResponse(w, "plugin_id not found")
		return
	}
	var global, consent *bool
	if v, err := utils.PostPara(r, "global"); err == nil {
		b := v == "true"
		global = &b
	}
	if v, err := utils.PostPara(r, "fail_closed"); err == nil {
		b := v == "true"
		consent = &b
	}
	if err := m.SetHookAdminSettings(pluginID, global, consent); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// pluginView is a plugin together with its admin hook state, for JSON output
type pluginView struct {
	*Plugin
	HookAdmin HookAdminState
}

func viewOf(p *Plugin) pluginView { return pluginView{Plugin: p, HookAdmin: p.hookAdminState()} }
