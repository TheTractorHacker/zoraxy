// Package zrok supervises the zrok CLI (https://zrok.io, openziti based tunnels), like the docker image does for ZeroTier.
//
// Zoraxy never links zrok code. It runs the external `zrok` / `zrok2` binary as a child process, so the feature is opt-in
// twice: the process must be started with -allow_external_tools and an administrator must configure the binary.
//
// Security model:
//   - no shell: commands are exec'd with an argument vector built from whitelisted, validated values (args.go);
//   - the child gets a minimal environment (PATH, HOME/USERPROFILE pointing into conf/zrok/home, temp dir), not Zoraxy's;
//   - the account token lives in conf/zrok/token (0600), is never returned by the API and is redacted from captured output.
//     zrok accepts the token only as a positional argument of `zrok enable <token>` (no environment variable or stdin
//     mechanism exists in the zrok source), so it is visible in the process list for the few seconds the enable command runs;
//   - children are stopped with SIGTERM and killed after a grace period when Zoraxy shuts down;
//   - crashes are restarted with exponential backoff; repeated immediate failures stop the tunnel instead of looping.
package zrok

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	StateStopped  = "stopped"
	StateStarting = "starting"
	StateRunning  = "running"
	StateBackoff  = "backoff"
	StateFailed   = "failed"

	maxLogLines   = 200
	maxLogLineLen = 1000
	maxTunnels    = 32
)

// Settings is the global zrok configuration (the token is stored separately)
type Settings struct {
	BinaryPath  string //Absolute path or file name; empty = search zrok2 then zrok in PATH
	Flavor      string //auto (default), v1, v2
	ApiEndpoint string //Optional: self hosted zrok API, applied with `zrok config set apiEndpoint`
	EnabledEnv  bool   //Set after a successful `zrok enable`
}

type fileData struct {
	Settings Settings
	Tunnels  []*Tunnel
	Reserved map[string]bool //tunnel IDs whose reserved share was created
}

// TunnelStatus is the runtime view of one tunnel
type TunnelStatus struct {
	Tunnel
	State     string
	Restarts  int
	LastExit  string    `json:",omitempty"`
	StartedAt time.Time `json:",omitzero"`
	PublicURL string    `json:",omitempty"` //Best effort, parsed from the zrok output
	Token     string    `json:",omitempty"` //Best effort: share token announced by a private share
	NextRetry time.Time `json:",omitzero"`
}

type runner struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	st     TunnelStatus
	logs   []string
}

// Manager owns settings, tunnels and the supervised processes
type Manager struct {
	dir     string
	allowed bool
	// Test hooks
	backoffBase time.Duration
	backoffMax  time.Duration
	stableAfter time.Duration
	termGrace   time.Duration

	mu       sync.Mutex
	settings Settings
	tunnels  []*Tunnel
	reserved map[string]bool
	token    string
	runners  map[string]*runner
	lastLogs map[string][]string
	lastStat map[string]TunnelStatus
	closed   bool
	events   func(msg string, err error)
}

// Open loads state from dir (conf/zrok). allowed is the -allow_external_tools switch: when false nothing can be executed.
func Open(dir string, allowed bool, logf func(msg string, err error)) (*Manager, error) {
	m := &Manager{dir: dir, allowed: allowed, runners: map[string]*runner{}, reserved: map[string]bool{}, events: logf,
		backoffBase: time.Second, backoffMax: 5 * time.Minute, stableAfter: time.Minute, termGrace: 8 * time.Second}
	if m.events == nil {
		m.events = func(string, error) {}
	}
	if err := os.MkdirAll(filepath.Join(dir, "home"), 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	if raw, err := os.ReadFile(filepath.Join(dir, "zrok.json")); err == nil {
		var fd fileData
		if err := json.Unmarshal(raw, &fd); err != nil {
			return nil, fmt.Errorf("zrok.json is corrupt: %w", err)
		}
		m.settings, m.tunnels = fd.Settings, fd.Tunnels
		if fd.Reserved != nil {
			m.reserved = fd.Reserved
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "token")); err == nil {
		m.token = strings.TrimSpace(string(raw))
	}
	return m, nil
}

func (m *Manager) saveLocked() error {
	raw, err := json.MarshalIndent(fileData{Settings: m.settings, Tunnels: m.tunnels, Reserved: m.reserved}, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(m.dir, "zrok.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, filepath.Join(m.dir, "zrok.json"))
}

// Allowed reports whether external tools may be executed
func (m *Manager) Allowed() bool { return m.allowed }

var errNotAllowed = errors.New("running external tools is disabled: start Zoraxy with -allow_external_tools to use zrok")

// ---- settings and token ----

func (m *Manager) Settings() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

func (m *Manager) TokenSet() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token != ""
}

// SetSettings validates and stores settings
func (m *Manager) SetSettings(s Settings) error {
	if err := ValidateBinary(s.BinaryPath); err != nil {
		return err
	}
	switch s.Flavor {
	case "", FlavorAuto, FlavorV1, FlavorV2:
	default:
		return errors.New("flavor must be auto, v1 or v2")
	}
	if err := ValidateAPIEndpoint(s.ApiEndpoint); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.BinaryPath != m.settings.BinaryPath || s.ApiEndpoint != m.settings.ApiEndpoint {
		s.EnabledEnv = false //a different binary / endpoint needs a fresh enable
	} else {
		s.EnabledEnv = m.settings.EnabledEnv
	}
	m.settings = s
	return m.saveLocked()
}

// SetToken stores the account token (0600). An empty token clears it.
func (m *Manager) SetToken(tok string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := filepath.Join(m.dir, "token")
	if tok == "" {
		m.token = ""
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := ValidateAccountToken(tok); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
		return err
	}
	_ = os.Chmod(p, 0o600)
	m.token = tok
	return nil
}

// ---- binary / environment ----

// Binary resolves the executable. Empty settings search zrok2 then zrok in PATH.
func (m *Manager) Binary() (string, error) {
	s := m.Settings()
	cands := []string{s.BinaryPath}
	if s.BinaryPath == "" {
		cands = []string{"zrok2", "zrok"}
	}
	var lastErr error
	for _, c := range cands {
		p, err := exec.LookPath(c)
		if err != nil {
			lastErr = err
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			lastErr = err
			continue
		}
		if err := ValidateBinary(abs); err != nil {
			lastErr = err
			continue
		}
		return abs, nil
	}
	return "", fmt.Errorf("zrok binary not found: %v", lastErr)
}

func (m *Manager) flavor(bin string) string { return FlavorFor(m.Settings().Flavor, bin) }

func (m *Manager) childEnv() []string {
	home := filepath.Join(m.dir, "home")
	env := []string{"HOME=" + home, "USERPROFILE=" + home, "TMPDIR=" + os.TempDir(), "LANG=C.UTF-8", "NO_COLOR=1"}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	if runtime.GOOS == "windows" {
		for _, k := range []string{"SystemRoot", "TEMP", "TMP", "ComSpec"} {
			if v := os.Getenv(k); v != "" {
				env = append(env, k+"="+v)
			}
		}
	}
	return env
}

func (m *Manager) redactor() func(string) string {
	m.mu.Lock()
	tok := m.token
	m.mu.Unlock()
	return func(s string) string {
		if tok != "" {
			s = strings.ReplaceAll(s, tok, "***")
		}
		if len(s) > maxLogLineLen {
			s = s[:maxLogLineLen] + "..."
		}
		return s
	}
}

// runOnce runs a short lived zrok command and returns its redacted combined output
func (m *Manager) runOnce(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	if !m.allowed {
		return "", errNotAllowed
	}
	bin, err := m.Binary()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = m.childEnv()
	cmd.Dir = filepath.Join(m.dir, "home")
	cmd.WaitDelay = 3 * time.Second
	red := m.redactor()
	var buf strings.Builder
	w := &limitedWriter{w: &buf, max: 16 * 1024}
	cmd.Stdout, cmd.Stderr = w, w
	err = cmd.Run()
	out := red(strings.TrimSpace(buf.String()))
	if err != nil {
		if ctx.Err() != nil {
			return out, fmt.Errorf("zrok %s timed out", args[0])
		}
		return out, fmt.Errorf("zrok %s failed: %v", args[0], err)
	}
	return out, nil
}

type limitedWriter struct {
	w   io.Writer
	max int
	n   int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n < l.max {
		k := len(p)
		if l.n+k > l.max {
			k = l.max - l.n
		}
		l.w.Write(p[:k])
		l.n += k
	}
	return len(p), nil
}

// Version returns the first line of `zrok version` (best effort)
func (m *Manager) Version(ctx context.Context) string {
	out, err := m.runOnce(ctx, 10*time.Second, "version")
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

// Enable configures the API endpoint (if set) and enables the zrok environment with the stored token
func (m *Manager) Enable(ctx context.Context) (string, error) {
	if !m.allowed {
		return "", errNotAllowed
	}
	m.mu.Lock()
	tok, ep := m.token, m.settings.ApiEndpoint
	m.mu.Unlock()
	if tok == "" {
		return "", errors.New("set the zrok account token first")
	}
	var log strings.Builder
	if ep != "" {
		out, err := m.runOnce(ctx, 30*time.Second, "config", "set", "apiEndpoint", ep)
		log.WriteString(out + "\n")
		if err != nil {
			return log.String(), err
		}
	}
	host, _ := os.Hostname()
	desc := "zoraxy-" + sanitizeDesc(host)
	//The token has to be an argument (zrok offers nothing else); it is validated above and redacted from the captured output
	out, err := m.runOnce(ctx, 90*time.Second, "enable", tok, "--headless", "--description", desc)
	log.WriteString(out)
	if err != nil {
		return log.String(), err
	}
	m.mu.Lock()
	m.settings.EnabledEnv = true
	err = m.saveLocked()
	m.mu.Unlock()
	return log.String(), err
}

var descRe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

func sanitizeDesc(s string) string {
	s = descRe.ReplaceAllString(s, "-")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// Disable stops all tunnels and disables the zrok environment
func (m *Manager) Disable(ctx context.Context) (string, error) {
	if !m.allowed {
		return "", errNotAllowed
	}
	m.StopAll()
	out, err := m.runOnce(ctx, 60*time.Second, "disable")
	if err != nil {
		return out, err
	}
	m.mu.Lock()
	m.settings.EnabledEnv = false
	m.reserved = map[string]bool{}
	err = m.saveLocked()
	m.mu.Unlock()
	return out, err
}

// ---- tunnels ----

func newID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Tunnels returns the stored tunnel definitions
func (m *Manager) Tunnels() []*Tunnel {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Tunnel, len(m.tunnels))
	for i, t := range m.tunnels {
		c := *t
		out[i] = &c
	}
	return out
}

// SaveTunnel adds (empty ID) or replaces a tunnel. A running tunnel is restarted with the new definition.
func (m *Manager) SaveTunnel(t Tunnel) (*Tunnel, error) {
	bin, _ := m.Binary()
	fl := m.flavor(bin)
	if err := t.Validate(fl); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if t.ID == "" {
		if len(m.tunnels) >= maxTunnels {
			m.mu.Unlock()
			return nil, errors.New("too many tunnels")
		}
		t.ID = newID()
		c := t
		m.tunnels = append(m.tunnels, &c)
	} else {
		found := false
		for i, ex := range m.tunnels {
			if ex.ID == t.ID {
				if ex.UniqueName != t.UniqueName || ex.Target != t.Target || ex.Kind != t.Kind {
					delete(m.reserved, t.ID)
				}
				c := t
				m.tunnels[i] = &c
				found = true
			}
		}
		if !found {
			m.mu.Unlock()
			return nil, errors.New("tunnel not found")
		}
	}
	err := m.saveLocked()
	_, running := m.runners[t.ID]
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if running {
		m.Stop(t.ID)
		if m.allowed {
			_ = m.Start(t.ID)
		}
	}
	return &t, nil
}

// DeleteTunnel stops and removes a tunnel
func (m *Manager) DeleteTunnel(id string) error {
	m.Stop(id)
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tunnels {
		if t.ID == id {
			m.tunnels = append(m.tunnels[:i:i], m.tunnels[i+1:]...)
			delete(m.reserved, id)
			return m.saveLocked()
		}
	}
	return errors.New("tunnel not found")
}

func (m *Manager) tunnelLocked(id string) *Tunnel {
	for _, t := range m.tunnels {
		if t.ID == id {
			c := *t
			return &c
		}
	}
	return nil
}

// Start begins supervising a tunnel
func (m *Manager) Start(id string) error {
	if !m.allowed {
		return errNotAllowed
	}
	bin, err := m.Binary()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("shutting down")
	}
	t := m.tunnelLocked(id)
	if t == nil {
		return errors.New("tunnel not found")
	}
	if !m.settings.EnabledEnv {
		return errors.New("the zrok environment is not enabled yet: save the token and click Enable first")
	}
	if r := m.runners[id]; r != nil {
		return errors.New("tunnel already running")
	}
	fl := FlavorFor(m.settings.Flavor, bin)
	if _, err := buildRunArgs(fl, t); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runner{cancel: cancel, done: make(chan struct{})}
	r.st = TunnelStatus{Tunnel: *t, State: StateStarting}
	m.runners[id] = r
	go m.supervise(ctx, r, bin, fl, t)
	return nil
}

// Stop stops a tunnel (graceful, then kill) and waits for it
func (m *Manager) Stop(id string) {
	m.mu.Lock()
	r := m.runners[id]
	m.mu.Unlock()
	if r == nil {
		return
	}
	r.cancel()
	<-r.done
}

// StopAll stops every tunnel
func (m *Manager) StopAll() {
	m.mu.Lock()
	rs := make([]*runner, 0, len(m.runners))
	for _, r := range m.runners {
		rs = append(rs, r)
	}
	m.mu.Unlock()
	for _, r := range rs {
		r.cancel()
	}
	for _, r := range rs {
		<-r.done
	}
}

// Close stops everything and refuses new starts (Zoraxy shutdown)
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.StopAll()
}

// StartAuto starts the tunnels flagged AutoStart (called at boot when the environment is enabled)
func (m *Manager) StartAuto() {
	if !m.allowed {
		return
	}
	for _, t := range m.Tunnels() {
		if t.AutoStart {
			if err := m.Start(t.ID); err != nil {
				m.events("zrok: could not auto start tunnel "+t.Name, err)
			}
		}
	}
}

// Status returns the runtime status of every tunnel
func (m *Manager) Status() []TunnelStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TunnelStatus, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		if r := m.runners[t.ID]; r != nil {
			r.mu.Lock()
			s := r.st
			r.mu.Unlock()
			s.Tunnel = *t
			out = append(out, s)
		} else if ls, ok := m.lastStat[t.ID]; ok {
			ls.Tunnel = *t
			if ls.State != StateFailed {
				ls.State, ls.PublicURL, ls.Token = StateStopped, "", ""
			}
			out = append(out, ls)
		} else {
			out = append(out, TunnelStatus{Tunnel: *t, State: StateStopped})
		}
	}
	return out
}

// Logs returns the captured (redacted) output of a tunnel
func (m *Manager) Logs(id string) []string {
	m.mu.Lock()
	r := m.runners[id]
	m.mu.Unlock()
	if r == nil {
		m.mu.Lock()
		last := m.lastLogs[id]
		m.mu.Unlock()
		return last
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.logs...)
}

func (r *runner) addLog(line string) {
	r.mu.Lock()
	r.logs = append(r.logs, line)
	if len(r.logs) > maxLogLines {
		r.logs = r.logs[len(r.logs)-maxLogLines:]
	}
	r.mu.Unlock()
}

var (
	urlRe   = regexp.MustCompile(`https?://[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}[^\s"']*`)
	tokenRx = regexp.MustCompile(`access private ([A-Za-z0-9_\-]{4,64})`)
)

func (r *runner) set(f func(s *TunnelStatus)) {
	r.mu.Lock()
	f(&r.st)
	r.mu.Unlock()
}

// supervise runs the tunnel until its context is cancelled, restarting it with backoff
func (m *Manager) supervise(ctx context.Context, r *runner, bin, flavor string, t *Tunnel) {
	defer func() {
		r.mu.Lock()
		logs := append([]string(nil), r.logs...)
		r.mu.Unlock()
		m.mu.Lock()
		if m.lastLogs == nil {
			m.lastLogs = map[string][]string{}
		}
		m.lastLogs[t.ID] = logs
		if m.lastStat == nil {
			m.lastStat = map[string]TunnelStatus{}
		}
		r.mu.Lock()
		m.lastStat[t.ID] = r.st
		r.mu.Unlock()
		delete(m.runners, t.ID)
		m.mu.Unlock()
		close(r.done)
	}()

	//Reserved shares (zrok v1) are created once
	if rv := buildReserveArgs(flavor, t); rv != nil {
		m.mu.Lock()
		done := m.reserved[t.ID]
		m.mu.Unlock()
		if !done {
			out, err := m.runOnce(ctx, 60*time.Second, rv...)
			for _, l := range strings.Split(out, "\n") {
				r.addLog("[reserve] " + l)
			}
			if err != nil && !strings.Contains(strings.ToLower(out), "already") {
				r.set(func(s *TunnelStatus) { s.State, s.LastExit = StateFailed, "reserve failed: "+err.Error() })
				m.events("zrok: reserving the share of "+t.Name+" failed", err)
				return
			}
			m.mu.Lock()
			m.reserved[t.ID] = true
			_ = m.saveLocked()
			m.mu.Unlock()
		}
	}

	args, err := buildRunArgs(flavor, t)
	if err != nil {
		r.set(func(s *TunnelStatus) { s.State, s.LastExit = StateFailed, err.Error() })
		return
	}
	backoff := m.backoffBase
	fast := 0
	for ctx.Err() == nil {
		start := time.Now()
		r.set(func(s *TunnelStatus) { s.State, s.StartedAt, s.NextRetry = StateStarting, start, time.Time{} })
		code, runErr := m.runChild(ctx, r, bin, args)
		if ctx.Err() != nil {
			r.set(func(s *TunnelStatus) { s.State, s.LastExit = StateStopped, "stopped" })
			return
		}
		ran := time.Since(start)
		msg := fmt.Sprintf("exit code %d", code)
		if runErr != nil && code < 0 {
			msg = runErr.Error()
		}
		r.addLog("[supervisor] process ended: " + msg)
		if ran >= m.stableAfter {
			backoff, fast = m.backoffBase, 0
		} else if ran < 5*time.Second {
			fast++
		}
		if fast >= 8 {
			r.set(func(s *TunnelStatus) {
				s.State, s.LastExit = StateFailed, msg+" (stopped after repeated immediate failures)"
			})
			m.events("zrok: tunnel "+t.Name+" keeps failing immediately, not restarting", nil)
			return
		}
		next := time.Now().Add(backoff)
		r.set(func(s *TunnelStatus) {
			s.State, s.LastExit, s.NextRetry = StateBackoff, msg, next
			s.Restarts++
		})
		r.addLog(fmt.Sprintf("[supervisor] restarting in %s", backoff))
		select {
		case <-ctx.Done():
			r.set(func(s *TunnelStatus) { s.State = StateStopped })
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > m.backoffMax {
			backoff = m.backoffMax
		}
	}
}

// runChild runs one process until it exits or ctx is cancelled (SIGTERM, then kill after the grace period)
func (m *Manager) runChild(ctx context.Context, r *runner, bin string, args []string) (int, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env = m.childEnv()
	cmd.Dir = filepath.Join(m.dir, "home")
	cmd.WaitDelay = 2 * time.Second
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	red := m.redactor()
	if err := cmd.Start(); err != nil {
		pw.Close()
		return -1, err
	}
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		for sc.Scan() {
			line := red(sc.Text())
			r.addLog(line)
			r.set(func(s *TunnelStatus) {
				if s.State == StateStarting {
					s.State = StateRunning
				}
				if u := urlRe.FindString(line); u != "" && s.PublicURL == "" {
					s.PublicURL = u
				}
				if mm := tokenRx.FindStringSubmatch(line); mm != nil {
					s.Token = mm[1]
				}
			})
		}
		io.Copy(io.Discard, pr)
	}()
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait(); pw.Close() }()

	//A process that is still alive after a moment counts as running even when it prints nothing
	runTimer := time.AfterFunc(2*time.Second, func() {
		r.set(func(s *TunnelStatus) {
			if s.State == StateStarting {
				s.State = StateRunning
			}
		})
	})
	defer runTimer.Stop()

	var werr error
	select {
	case werr = <-waitCh:
	case <-ctx.Done():
		r.addLog("[supervisor] stopping (SIGTERM)")
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			_ = cmd.Process.Kill() //platforms without SIGTERM
		}
		select {
		case werr = <-waitCh:
		case <-time.After(m.termGrace):
			r.addLog("[supervisor] did not exit in time, killing")
			_ = cmd.Process.Kill()
			werr = <-waitCh
		}
	}
	<-scanDone
	code := 0
	if werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return code, werr
}
