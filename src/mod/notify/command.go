package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CommandConfig describes the command hook. It only ever runs when the process was started with
// -allow_hook_commands (CommandSink.Allowed).
type CommandConfig struct {
	Enabled bool     `json:"enabled"`
	Path    string   `json:"path"`    // absolute path of the executable; no shell is involved
	Args    []string `json:"args"`    // fixed arguments; they are NOT expanded or interpreted
	Events  []string `json:"events"`  // empty = all events
	Timeout int      `json:"timeout"` // seconds, default 30, max 600
}

// MaxCommandOutput bounds how much stdout/stderr is kept for the log
const MaxCommandOutput = 4096

// CommandSink runs an executable for each event.
type CommandSink struct {
	Cfg CommandConfig
	// Allowed mirrors the -allow_hook_commands start flag. When false nothing is ever executed.
	Allowed bool
	// Logf receives the captured output (may be nil)
	Logf func(format string, args ...any)
}

func (s *CommandSink) Name() string { return "command" }

func (s *CommandSink) Wants(eventType string) bool {
	if !s.Allowed || !s.Cfg.Enabled || s.Cfg.Path == "" {
		return false
	}
	if len(s.Cfg.Events) == 0 {
		return true
	}
	for _, e := range s.Cfg.Events {
		if e == eventType {
			return true
		}
	}
	return false
}

// ValidateCommandPath requires an absolute path to an existing regular file.
func ValidateCommandPath(p string) error {
	if !filepath.IsAbs(p) {
		return errors.New("the command must be an absolute path")
	}
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("the command is not a regular file")
	}
	return nil
}

type limitedBuffer struct {
	buf bytes.Buffer
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := MaxCommandOutput - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil // pretend everything was written so the child never blocks
}

// EventEnv renders the event as environment variables for the hook.
func EventEnv(ev Event) []string {
	env := []string{
		"ZORAXY_EVENT=" + ev.Event,
		"ZORAXY_SOURCE=" + ev.Source,
		"ZORAXY_SUBJECT=" + ev.Subject,
		"ZORAXY_DOMAINS=" + strings.Join(ev.Domains, ","),
		"ZORAXY_CA=" + ev.CA,
		"ZORAXY_ERROR=" + ev.Error,
		"ZORAXY_TIME=" + ev.Time.UTC().Format(time.RFC3339),
	}
	if ev.Expiry != nil {
		env = append(env, "ZORAXY_EXPIRY="+ev.Expiry.UTC().Format(time.RFC3339))
	} else {
		env = append(env, "ZORAXY_EXPIRY=")
	}
	if ev.DaysLeft != nil {
		env = append(env, fmt.Sprintf("ZORAXY_DAYS_LEFT=%d", *ev.DaysLeft))
	}
	js, _ := json.Marshal(ev)
	return append(env, "ZORAXY_EVENT_JSON="+string(js))
}

// Run executes the command for one event and returns its (truncated) combined output.
func (s *CommandSink) Run(ctx context.Context, ev Event) (string, error) {
	if !s.Allowed {
		return "", errors.New("command hooks are disabled: start Zoraxy with -allow_hook_commands")
	}
	if err := ValidateCommandPath(s.Cfg.Path); err != nil {
		return "", err
	}
	timeout := time.Duration(s.Cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.Cfg.Path, s.Cfg.Args...) // no shell
	// Minimal environment: the parent's secrets (flags, tokens in env) are not handed to the hook
	cmd.Env = append([]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, EventEnv(ev)...)
	cmd.Dir = filepath.Dir(s.Cfg.Path)
	out := &limitedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", timeout)
	}
	return out.buf.String(), err
}

func (s *CommandSink) Deliver(ctx context.Context, ev Event) error {
	out, err := s.Run(ctx, ev)
	if s.Logf != nil {
		s.Logf("[notify] command hook for %s finished (err=%v) output: %q", ev.Event, err, out)
	}
	return err
}
