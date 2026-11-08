package updater

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Hooks are the side-effecting operations that tests replace with fakes.
type Hooks struct {
	// Smoke runs `<bin> -version` and returns its output.
	Smoke func(ctx context.Context, bin string) (string, error)
	// Restart replaces the running process with exe. On success it does not return.
	Restart func(exe string, args []string) error
	// SpawnWatchdog launches the out-of-process rollback watchdog.
	SpawnWatchdog func(prevBin, markerPath string) error
	// FreeSpace returns the free bytes on the filesystem holding dir.
	FreeSpace func(dir string) (uint64, error)
	// Now returns the current time.
	Now func() time.Time
	// RestartDelay lets the UI observe the "restarting" state before exec.
	RestartDelay time.Duration
}

// Config configures a Manager.
type Config struct {
	Repo      string
	APIBase   string
	Client    *http.Client
	AllowHTTP bool // tests only: permit http:// release URLs

	ConfDir, DBPath, UUIDPath string
	CurrentVersion            string // SYSTEM_VERSION
	InDocker                  bool
	DockerEnvFile             string // default /.dockerenv

	Executable string   // override os.Executable (tests)
	Args       []string // arguments the process was started with (default os.Args[1:])
	GOOS       string
	GOARCH     string
	Getenv     func(string) string
	PubKey     ed25519.PublicKey // default: embedded key

	// Migrate runs the existing config/database migrations (update.RunConfigUpdate).
	Migrate func() error
	// Shutdown runs the application's orderly shutdown sequence before a restart.
	Shutdown func()
	Logf     func(format string, a ...any)

	HealthyTimeout time.Duration // default 90s
	KeepPrev       int           // default 3
	Hooks          Hooks
}

// Manager coordinates checks and updates. All state changing operations are
// serialised: only one may run at a time.
type Manager struct {
	cfg Config
	st  *store
	src *source

	mu      sync.Mutex
	running bool
	status  Status

	cacheMu   sync.Mutex
	cacheAt   time.Time
	cacheRes  *CheckResult
	cacheChan string

	relMu      sync.Mutex
	limitedErr *RateLimitError // last rate limit answer; requests are held back until it resets
	tokenMu    sync.Mutex
	token      string
	tokenLoad  bool

	shaOnce sync.Once
	exeSHA  string
}

// New builds a Manager, filling defaults. It performs no I/O.
func New(cfg Config) *Manager {
	if cfg.Repo == "" {
		cfg.Repo = DefaultRepo
	}
	if cfg.APIBase == "" {
		cfg.APIBase = DefaultAPIBase
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if cfg.GOOS == "" {
		cfg.GOOS = runtime.GOOS
	}
	if cfg.GOARCH == "" {
		cfg.GOARCH = runtime.GOARCH
	}
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	if cfg.DockerEnvFile == "" {
		cfg.DockerEnvFile = "/.dockerenv"
	}
	if cfg.Args == nil && len(os.Args) > 1 {
		cfg.Args = os.Args[1:]
	}
	if cfg.HealthyTimeout == 0 {
		cfg.HealthyTimeout = 90 * time.Second
	}
	if cfg.KeepPrev == 0 {
		cfg.KeepPrev = 3
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.PubKey == nil {
		cfg.PubKey, _ = EmbeddedPublicKey()
	}
	m := &Manager{cfg: cfg, st: newStore(cfg.ConfDir)}
	m.src = &source{repo: cfg.Repo, apiBase: cfg.APIBase, client: cfg.Client, allowHTTP: cfg.AllowHTTP, token: m.githubToken}
	h := &m.cfg.Hooks
	if h.Now == nil {
		h.Now = time.Now
	}
	if h.FreeSpace == nil {
		h.FreeSpace = freeSpace
	}
	if h.Smoke == nil {
		h.Smoke = defaultSmoke
	}
	if h.Restart == nil {
		h.Restart = m.defaultRestart
	}
	if h.SpawnWatchdog == nil {
		h.SpawnWatchdog = m.defaultSpawnWatchdog
	}
	if h.RestartDelay == 0 {
		h.RestartDelay = 2 * time.Second
	}
	return m
}

func defaultSmoke(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-version").CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (m *Manager) defaultRestart(exe string, args []string) error {
	if m.cfg.Shutdown != nil {
		done := make(chan struct{})
		go func() { m.cfg.Shutdown(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			m.cfg.Logf("[updater] shutdown sequence timed out, continuing restart")
		}
	}
	err := execInPlace(exe, args)
	// exec failed: exit with a non-zero status so a supervisor restarts us.
	m.cfg.Logf("[updater] in-place exec failed (%v); exiting with status 75 for the supervisor to restart", err)
	os.Exit(75)
	return err
}

func (m *Manager) defaultSpawnWatchdog(prevBin, markerPath string) error {
	_, err := spawnDetached(prevBin, []string{"-updater_watchdog", markerPath}, m.st.path("watchdog.log"))
	return err
}

// Settings returns the persisted settings.
func (m *Manager) Settings() Settings {
	s := m.st.settings()
	s.HasToken = m.githubToken() != ""
	return s
}

func (m *Manager) githubToken() string {
	m.tokenMu.Lock()
	defer m.tokenMu.Unlock()
	if !m.tokenLoad {
		m.token, m.tokenLoad = m.st.loadToken(), true
	}
	return m.token
}

// SetGitHubToken stores an optional GitHub token that raises the API rate limit.
// It is written with mode 0600, only sent to the GitHub API host and never returned
// by any API. An empty value removes it.
func (m *Manager) SetGitHubToken(tok string) error {
	tok = strings.TrimSpace(tok)
	if len(tok) > 255 || strings.ContainsAny(tok, " \t\r\n\"") {
		return errors.New("that does not look like a GitHub token")
	}
	if err := m.st.saveToken(tok); err != nil {
		return err
	}
	m.tokenMu.Lock()
	m.token, m.tokenLoad = tok, true
	m.tokenMu.Unlock()
	m.relMu.Lock()
	m.limitedErr = nil
	m.relMu.Unlock()
	if tok == "" {
		m.audit("", "GitHub token removed")
	} else {
		m.audit("", "GitHub token set")
	}
	return nil
}

// releases returns the release list. With useCache a copy younger than releaseCacheTTL is
// used without any network request. Otherwise a conditional request is made, so an
// unchanged list costs no rate limit quota (HTTP 304).
func (m *Manager) releases(ctx context.Context, useCache bool) ([]Release, error) {
	m.relMu.Lock()
	defer m.relMu.Unlock()
	now := m.cfg.Hooks.Now()
	var c releaseCache
	have := m.st.readJSON(releaseCacheFile, &c) == nil && c.Repo == m.cfg.Repo && len(c.Body) > 0
	if have && useCache && !now.Before(c.FetchedAt) && now.Sub(c.FetchedAt) < releaseCacheTTL {
		if rels, err := parseReleases(c.Body); err == nil {
			return rels, nil
		}
	}
	if l := m.limitedErr; l != nil && !l.ResetAt.IsZero() && now.Before(l.ResetAt) {
		return nil, l
	}
	etag := ""
	if have {
		etag = c.ETag
	}
	body, newETag, notModified, err := m.src.fetchReleases(ctx, etag, now)
	if err != nil {
		var rl *RateLimitError
		if errors.As(err, &rl) {
			m.limitedErr = rl
		}
		return nil, err
	}
	m.limitedErr = nil
	if notModified {
		rels, err := parseReleases(c.Body)
		if err != nil {
			return nil, err
		}
		c.FetchedAt = now
		_ = m.st.writeJSON(releaseCacheFile, c)
		return rels, nil
	}
	rels, err := parseReleases(body)
	if err != nil {
		return nil, err
	}
	_ = m.st.writeJSON(releaseCacheFile, releaseCache{Repo: m.cfg.Repo, ETag: newETag, FetchedAt: now, Body: body})
	return rels, nil
}

// SetChannel persists the update channel.
func (m *Manager) SetChannel(ch string) error {
	if !ValidChannel(ch) {
		return fmt.Errorf("unknown channel %q", ch)
	}
	s := m.st.settings()
	s.Channel = ch
	m.cacheMu.Lock()
	m.cacheRes = nil
	m.cacheMu.Unlock()
	m.audit("", "channel set to "+ch)
	return m.st.saveSettings(s)
}

// SetBackupFirst persists the "back up first" default.
func (m *Manager) SetBackupFirst(v bool) error {
	s := m.st.settings()
	s.BackupFirst = v
	m.audit("", fmt.Sprintf("backup-first set to %v", v))
	return m.st.saveSettings(s)
}

// History returns the update history, newest last.
func (m *Manager) History() []HistoryEntry { return m.st.history() }

func (m *Manager) audit(actor, msg string) {
	m.st.audit(m.cfg.Hooks.Now(), actor, msg)
	m.cfg.Logf("[updater] %s", msg)
}

// exePath resolves the running executable (symlinks resolved).
func (m *Manager) exePath() (string, error) {
	p := m.cfg.Executable
	if p == "" {
		var err error
		if p, err = os.Executable(); err != nil {
			return "", err
		}
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return filepath.Abs(p)
}

// RestartMethod reports how the process is supervised: docker, systemd or manual.
func (m *Manager) RestartMethod() string {
	if m.cfg.InDocker {
		return "docker"
	}
	if _, err := os.Stat(m.cfg.DockerEnvFile); err == nil {
		return "docker"
	}
	if m.cfg.Getenv("INVOCATION_ID") != "" {
		return "systemd"
	}
	return "manual"
}

// current describes the running build.
type Current struct {
	Version   string    `json:"version"`   // SYSTEM_VERSION
	Tag       string    `json:"tag"`       // installed release tag, or "" if unknown
	Published time.Time `json:"published"` // zero if unknown
	Known     bool      `json:"known"`     // true when Tag came from a verified install record
}

func (m *Manager) current() (Current, BuildID) {
	c := Current{Version: m.cfg.CurrentVersion}
	if inst := m.st.installed(); inst != nil {
		m.shaOnce.Do(func() {
			if exe, err := m.exePath(); err == nil {
				m.exeSHA, _ = fileSHA256(exe)
			}
		})
		if m.exeSHA != "" && inst.SHA256 == m.exeSHA {
			if t, err := ParseTag(inst.Tag); err == nil {
				c.Tag, c.Published, c.Known = inst.Tag, inst.Published, true
				return c, BuildID{Tag: t, Published: inst.Published}
			}
		}
	}
	t, _ := ParseTag(m.cfg.CurrentVersion)
	return c, BuildID{Tag: t}
}

func (c Current) label() string {
	if c.Tag != "" {
		return c.Tag
	}
	return "v" + c.Version
}

// CheckResult is the outcome of a release check.
type CheckResult struct {
	Channel         string    `json:"channel"`
	Repo            string    `json:"repo"`
	Current         Current   `json:"current"`
	Latest          *Release  `json:"latest,omitempty"`
	AssetName       string    `json:"asset_name"`
	AssetSize       int64     `json:"asset_size"`
	UpdateAvailable bool      `json:"update_available"`
	Reason          string    `json:"reason"`
	CheckedAt       time.Time `json:"checked_at"`
}

type resolved struct {
	rel          Release
	asset        Asset
	sums, sig    Asset
	hasAssets    bool
	newer        bool
	reason       string
	assetNameStr string
}

// resolve looks up the latest release on the channel and decides if it is an
// acceptable (newer, signed, platform-matching) update.
func (m *Manager) resolve(ctx context.Context, useCache bool) (*resolved, Current, error) {
	cur, curID := m.current()
	rels, err := m.releases(ctx, useCache)
	if err != nil {
		return nil, cur, err
	}
	ch := m.st.settings().Channel
	latest, err := LatestForChannel(rels, ch)
	if err != nil {
		return nil, cur, err
	}
	r := &resolved{rel: *latest, assetNameStr: AssetName(m.cfg.GOOS, m.cfg.GOARCH)}
	id, _ := latest.ID()
	cmp := CompareReleases(id, curID)
	if cur.Known && cur.Tag == latest.Tag {
		// The same tag is the same build, even if GitHub reports a later published-at
		// (re-published release). Ordering must not depend on that timestamp.
		cmp = 0
	}
	if cmp <= 0 {
		if cmp == 0 {
			r.reason = "You are running the latest release."
		} else {
			r.reason = "The latest release on this channel is older than the running build; updates are forward-only."
		}
		return r, cur, nil
	}
	r.newer = true
	var ok1, ok2, ok3 bool
	r.asset, ok1 = FindAsset(*latest, r.assetNameStr)
	r.sums, ok2 = FindAsset(*latest, SumsAsset)
	r.sig, ok3 = FindAsset(*latest, SigAsset)
	switch {
	case !ok1:
		r.reason = fmt.Sprintf("Release %s has no asset %s for this platform.", latest.Tag, r.assetNameStr)
	case !ok2 || !ok3:
		r.reason = fmt.Sprintf("Release %s is not signed (missing %s or %s); refusing.", latest.Tag, SumsAsset, SigAsset)
	default:
		r.hasAssets = true
	}
	return r, cur, nil
}

// Check queries GitHub (results are cached for 30 s unless force is set).
func (m *Manager) Check(ctx context.Context, force bool) (*CheckResult, error) {
	ch := m.st.settings().Channel
	m.cacheMu.Lock()
	if !force && m.cacheRes != nil && m.cacheChan == ch && m.cfg.Hooks.Now().Sub(m.cacheAt) < 30*time.Second {
		res := *m.cacheRes
		m.cacheMu.Unlock()
		return &res, nil
	}
	m.cacheMu.Unlock()
	r, cur, err := m.resolve(ctx, !force)
	if err != nil {
		return nil, err
	}
	res := &CheckResult{
		Channel: ch, Repo: m.cfg.Repo, Current: cur, Latest: &r.rel, AssetName: r.assetNameStr,
		AssetSize: r.asset.Size, UpdateAvailable: r.newer && r.hasAssets, Reason: r.reason,
		CheckedAt: m.cfg.Hooks.Now(),
	}
	m.audit("", fmt.Sprintf("check: channel=%s latest=%s update_available=%v", ch, r.rel.Tag, res.UpdateAvailable))
	m.cacheMu.Lock()
	m.cacheRes, m.cacheAt, m.cacheChan = res, res.CheckedAt, ch
	m.cacheMu.Unlock()
	return res, nil
}

var (
	errBusy = errors.New("another update operation is already running")
)

// ---- status ----------------------------------------------------------------

// LogLine is one line of the live update log.
type LogLine struct {
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// Status is the pollable progress of the current / last operation.
type Status struct {
	State    string    `json:"state"` // idle | running | restarting | done | failed
	Op       string    `json:"op"`    // app | db | rollback
	Stage    string    `json:"stage"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Done     int64     `json:"done"`
	Total    int64     `json:"total"`
	Log      []LogLine `json:"log"`
}

// Status returns a snapshot.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Log = append([]LogLine(nil), s.Log...)
	if s.State == "" {
		s.State = "idle"
	}
	return s
}

func (m *Manager) begin(op, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return errBusy
	}
	m.running = true
	m.status = Status{State: "running", Op: op, Started: m.cfg.Hooks.Now()}
	m.audit(actor, "operation started: "+op)
	return nil
}

func (m *Manager) logf(actor, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	m.mu.Lock()
	m.status.Log = append(m.status.Log, LogLine{Time: m.cfg.Hooks.Now(), Text: msg})
	if n := len(m.status.Log); n > 500 {
		m.status.Log = m.status.Log[n-500:]
	}
	m.mu.Unlock()
	m.audit(actor, msg)
}

func (m *Manager) stage(actor, name string) {
	m.mu.Lock()
	m.status.Stage = name
	m.mu.Unlock()
	m.logf(actor, "== %s", name)
}

func (m *Manager) progress(done, total int64) {
	m.mu.Lock()
	m.status.Done, m.status.Total = done, total
	m.mu.Unlock()
}

func (m *Manager) finish(actor string, err error, restarting bool) {
	m.mu.Lock()
	m.status.Finished = m.cfg.Hooks.Now()
	switch {
	case err != nil:
		m.status.State, m.status.Error = "failed", err.Error()
		m.running = false
	case restarting:
		m.status.State = "restarting" // stays "running" for throttling purposes
	default:
		m.status.State = "done"
		m.running = false
	}
	m.mu.Unlock()
	if err != nil {
		m.audit(actor, "operation FAILED: "+err.Error())
	}
}

// Busy reports whether an operation is running.
func (m *Manager) Busy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}
