package logger

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/*
	Per-site (per proxy rule) request log files

	Everything here is opt-in. With the default configuration (mode "off") no site
	log is written and the global log behaves exactly as before.

	Layout: <log folder>/sites/<safe name>/<safe name>.log (active file)
	        <log folder>/sites/<safe name>/<safe name>.<timestamp>.log[.gz] (rotated)

	Modes: off   = global log only (default)
	       also  = global log and site log
	       only  = site log instead of the global request log
*/

// Site log modes
const (
	SiteLogOff  = "off"
	SiteLogAlso = "also"
	SiteLogOnly = "only"
)

// Site log line formats
const (
	SiteLogFormatText = "text"
	SiteLogFormatJSON = "json"
)

const (
	siteLogDirName   = "sites"
	maxOpenSiteFiles = 48
)

// SiteLogConfig is persisted as JSON
type SiteLogConfig struct {
	Mode   string            `json:"mode"`   // default mode for rules without an override
	Format string            `json:"format"` // text or json
	Rules  map[string]string `json:"rules"`  // per rule key: off / also / only (absent = use default mode)

	MaxSizeMB  int  `json:"maxSizeMB"`  // rotate when the active file exceeds this size (0 = 50)
	MaxAgeDays int  `json:"maxAgeDays"` // delete rotated files older than this (0 = keep)
	MaxBackups int  `json:"maxBackups"` // keep at most this many rotated files per site (0 = 10)
	Compress   bool `json:"compress"`   // gzip rotated files
}

// DefaultSiteLogConfig is the upstream compatible default: disabled
func DefaultSiteLogConfig() SiteLogConfig {
	return SiteLogConfig{Mode: SiteLogOff, Format: SiteLogFormatText, Rules: map[string]string{}, MaxSizeMB: 50, MaxBackups: 10, Compress: true}
}

// Validate normalises and checks the configuration
func (c *SiteLogConfig) Validate() error {
	if c.Mode == "" {
		c.Mode = SiteLogOff
	}
	if c.Format == "" {
		c.Format = SiteLogFormatText
	}
	if !validSiteMode(c.Mode) {
		return errors.New("invalid mode")
	}
	if c.Format != SiteLogFormatText && c.Format != SiteLogFormatJSON {
		return errors.New("invalid format")
	}
	if c.MaxSizeMB < 0 || c.MaxSizeMB > 100000 || c.MaxAgeDays < 0 || c.MaxAgeDays > 36500 || c.MaxBackups < 0 || c.MaxBackups > 10000 {
		return errors.New("rotation values out of range")
	}
	if len(c.Rules) > 5000 {
		return errors.New("too many rule overrides")
	}
	for k, v := range c.Rules {
		if !validSiteMode(v) || k == "" || len(k) > 253 {
			return errors.New("invalid rule override for " + k)
		}
	}
	if c.Rules == nil {
		c.Rules = map[string]string{}
	}
	return nil
}

func validSiteMode(m string) bool { return m == SiteLogOff || m == SiteLogAlso || m == SiteLogOnly }

// SafeSiteName turns an arbitrary rule key (host name, possibly attacker
// influenced, possibly containing "/", "..", NUL, unicode tricks) into a single
// path component. Names that needed changes get a short hash suffix so two
// different hosts can not collide on the same file.
func SafeSiteName(key string) string {
	var b strings.Builder
	changed := false
	for _, r := range strings.ToLower(key) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
			changed = true
		}
	}
	name := b.String()
	if strings.ToLower(key) != name {
		changed = true
	}
	// no leading dots (hidden files, "." and ".."), no trailing dots (Windows)
	trimmed := strings.Trim(name, ".")
	if trimmed != name {
		changed = true
		name = trimmed
	}
	if strings.Contains(name, "..") {
		name = strings.ReplaceAll(name, "..", "_")
		changed = true
	}
	if len(name) > 80 {
		name = name[:80]
		changed = true
	}
	if name == "" {
		name = "site"
		changed = true
	}
	switch strings.ToUpper(strings.SplitN(name, ".", 2)[0]) { // Windows reserved names
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3":
		name = "_" + name
		changed = true
	}
	if changed {
		sum := sha256.Sum256([]byte(key))
		name += "-" + hex.EncodeToString(sum[:3])
	}
	return name
}

type siteWriter struct {
	mu      sync.Mutex
	f       *os.File
	size    int64
	path    string
	lastUse atomic.Int64 // unix nano
}

// SiteLogs manages the per-site log files
type SiteLogs struct {
	mu      sync.RWMutex
	cfg     SiteLogConfig
	root    string // <log folder>/sites
	writers map[string]*siteWriter
	Now     func() time.Time

	stop chan struct{}
}

// NewSiteLogs creates the manager; logFolder is the global log folder. An
// empty folder (file logging disabled) yields a manager that never writes.
func NewSiteLogs(logFolder string, cfg SiteLogConfig) (*SiteLogs, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &SiteLogs{cfg: cfg, writers: map[string]*siteWriter{}, Now: time.Now, stop: make(chan struct{})}
	if logFolder != "" {
		s.root = filepath.Join(logFolder, siteLogDirName)
	}
	return s, nil
}

// StartJanitor applies retention hourly until Close
func (s *SiteLogs) StartJanitor() {
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.Retention()
			case <-s.stop:
				return
			}
		}
	}()
}

// Close closes all open files and stops the janitor
func (s *SiteLogs) Close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, w := range s.writers {
		w.mu.Lock()
		if w.f != nil {
			w.f.Close()
		}
		w.mu.Unlock()
		delete(s.writers, k)
	}
}

// Config returns a copy of the active configuration
func (s *SiteLogs) Config() SiteLogConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.Rules = map[string]string{}
	for k, v := range s.cfg.Rules {
		c.Rules[k] = v
	}
	return c
}

// SetConfig validates and applies a new configuration
func (s *SiteLogs) SetConfig(c SiteLogConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
	return nil
}

// ModeFor returns the effective mode for a rule key
func (s *SiteLogs) ModeFor(key string) string {
	if s == nil || s.root == "" || key == "" {
		return SiteLogOff
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.cfg.Rules[key]; ok {
		return m
	}
	return s.cfg.Mode
}

// SiteLine is the structured request record written to a site log
type SiteLine struct {
	Time     time.Time `json:"time"`
	Class    string    `json:"class"`
	Site     string    `json:"site"`
	Origin   string    `json:"origin"`
	Upstream string    `json:"upstream,omitempty"`
	Client   string    `json:"client"`
	Agent    string    `json:"useragent"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	Status   int       `json:"status"`
}

// FormatText renders the line in the same text format as the global request log
func (l SiteLine) FormatText() string {
	return "[" + l.Time.Format("2006-01-02 15:04:05.000000") + "] [router:" + l.Class + "] [origin:" + l.Origin +
		"] [client: " + l.Client + "] [useragent: " + l.Agent + "] " + l.Method + " " + l.URI + " " + fmt.Sprint(l.Status)
}

func oneLine(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	}
	return s
}

// Write appends one request to the site log of key (when its mode asks for it)
func (s *SiteLogs) Write(key string, line SiteLine) error {
	if s.ModeFor(key) == SiteLogOff {
		return nil
	}
	s.mu.RLock()
	format := s.cfg.Format
	s.mu.RUnlock()
	line.Site = key
	line.Origin, line.Client, line.Agent, line.URI = oneLine(line.Origin), oneLine(line.Client), oneLine(line.Agent), oneLine(line.URI)
	var text string
	if format == SiteLogFormatJSON {
		js, err := json.Marshal(line)
		if err != nil {
			return err
		}
		text = string(js)
	} else {
		text = line.FormatText()
	}
	return s.appendLine(key, text+"\n")
}

func (s *SiteLogs) appendLine(key, text string) error {
	name := SafeSiteName(key)
	// Never take s.mu while holding a writer lock (evictOldestLocked does the opposite order)
	s.mu.RLock()
	maxSize := int64(s.cfg.MaxSizeMB) * 1024 * 1024
	compress := s.cfg.Compress
	s.mu.RUnlock()
	if maxSize == 0 {
		maxSize = 50 * 1024 * 1024
	}
	for attempt := 0; attempt < 3; attempt++ {
		w, err := s.writerFor(name)
		if err != nil {
			return err
		}
		w.mu.Lock()
		if w.f == nil { // evicted between lookup and lock: get a fresh writer
			w.mu.Unlock()
			continue
		}
		if w.size >= maxSize {
			if err := s.rotateLocked(name, w, compress); err != nil {
				w.mu.Unlock()
				return err
			}
		}
		n, err := io.WriteString(w.f, text)
		w.size += int64(n)
		w.lastUse.Store(s.Now().UnixNano())
		w.mu.Unlock()
		return err
	}
	return errors.New("site log busy")
}

func (s *SiteLogs) writerFor(name string) (*siteWriter, error) {
	s.mu.RLock()
	w := s.writers[name]
	s.mu.RUnlock()
	if w != nil {
		return w, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if w = s.writers[name]; w != nil {
		return w, nil
	}
	if len(s.writers) >= maxOpenSiteFiles {
		s.evictOldestLocked()
	}
	dir := filepath.Join(s.root, name)
	if err := os.MkdirAll(dir, 0o775); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	st, _ := f.Stat()
	w = &siteWriter{f: f, path: path}
	w.lastUse.Store(s.Now().UnixNano())
	if st != nil {
		w.size = st.Size()
	}
	s.writers[name] = w
	return w, nil
}

func (s *SiteLogs) evictOldestLocked() {
	var oldestK string
	var oldest int64
	for k, w := range s.writers {
		if lu := w.lastUse.Load(); oldestK == "" || lu < oldest {
			oldestK, oldest = k, lu
		}
	}
	if oldestK != "" {
		w := s.writers[oldestK]
		w.mu.Lock()
		if w.f != nil {
			w.f.Close()
			w.f = nil
		}
		w.mu.Unlock()
		delete(s.writers, oldestK)
	}
}

// rotateLocked renames the active file and reopens a fresh one. w.mu is held.
func (s *SiteLogs) rotateLocked(name string, w *siteWriter, compress bool) error {
	w.f.Close()
	w.f = nil
	stamp := s.Now().Format("20060102-150405.000")
	rotated := filepath.Join(filepath.Dir(w.path), name+"."+stamp+".log")
	if err := os.Rename(w.path, rotated); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	w.f, w.size = f, 0
	go func() {
		if compress {
			if err := gzipFile(rotated); err == nil {
				os.Remove(rotated)
			}
		}
		s.retainDir(filepath.Dir(w.path), name)
	}()
	return nil
}

func gzipFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := path + ".gz.tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path+".gz")
}

// retainDir applies MaxAgeDays / MaxBackups to the rotated files of one site
func (s *SiteLogs) retainDir(dir, name string) {
	cfg := s.Config()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type rf struct {
		path string
		mod  time.Time
	}
	var rotated []rf
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, name+".") || n == name+".log" {
			continue
		}
		if !(strings.HasSuffix(n, ".log") || strings.HasSuffix(n, ".log.gz")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		rotated = append(rotated, rf{filepath.Join(dir, n), info.ModTime()})
	}
	sort.Slice(rotated, func(i, j int) bool { return rotated[i].mod.After(rotated[j].mod) })
	keep := cfg.MaxBackups
	if keep == 0 {
		keep = 10
	}
	cutoff := time.Time{}
	if cfg.MaxAgeDays > 0 {
		cutoff = s.Now().AddDate(0, 0, -cfg.MaxAgeDays)
	}
	for i, f := range rotated {
		if i >= keep || (!cutoff.IsZero() && f.mod.Before(cutoff)) {
			os.Remove(f.path)
		}
	}
}

// Retention applies the retention settings to every site folder now
func (s *SiteLogs) Retention() {
	if s.root == "" {
		return
	}
	dirs, err := os.ReadDir(s.root)
	if err != nil {
		return
	}
	for _, d := range dirs {
		if d.IsDir() {
			s.retainDir(filepath.Join(s.root, d.Name()), d.Name())
		}
	}
}

// ---- Logger integration ----

// LogHTTPRequestSite is LogHTTPRequest with per-site log routing. siteKey is the
// proxy rule key; an empty key (or SiteLogs not configured) logs to the global
// log only, as before. Must run in the caller's goroutine like LogHTTPRequest.
func (l *Logger) LogHTTPRequestSite(siteKey string, r *http.Request, reqclass string, statusCode int, downstreamHostname string, upstreamHostname string, clientIP string) {
	mode := SiteLogOff
	if l.Sites != nil {
		mode = l.Sites.ModeFor(siteKey)
	}
	if mode != SiteLogOnly {
		l.LogHTTPRequest(r, reqclass, statusCode, downstreamHostname, upstreamHostname, clientIP)
	}
	if mode != SiteLogOff {
		line := SiteLine{
			Time: time.Now(), Class: reqclass, Origin: downstreamHostname, Upstream: upstreamHostname,
			Client: clientIP, Agent: r.UserAgent(), Method: r.Method, URI: r.RequestURI, Status: statusCode,
		}
		go func() {
			if err := l.Sites.Write(siteKey, line); err != nil {
				fmt.Println("[sitelog] write failed:", err)
			}
		}()
	}
}
