package dynamicproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"imuslab.com/zoraxy/mod/luascript"
)

/*
	script_handler.go

	Per proxy rule Lua script (fork #88 / upstream #367). Sandbox and limits live in mod/luascript.

	Two modes:
	  handler  the script produces the response, no upstream is contacted ("serve a Lua script instead of a backend")
	  hook     the script runs before the upstream: it may answer (respond / redirect / response table changed) or let the request
	           continue, optionally changing request headers (request_header_set / request_header_del)

	The script runs after authentication (the same place as static responses that sit behind auth), so it only sees requests that
	passed the access list, WAF, rate limit, CAPTCHA and authentication of the rule.
*/

const (
	ScriptModeHandler = "handler"
	ScriptModeHook    = "hook"
)

type ScriptConfig struct {
	Enabled       bool
	Mode          string //"handler" (default) or "hook"
	Code          string //Lua source, at most 64 KiB
	PathPrefix    string `json:",omitempty"` //Optional: only run for paths below this prefix (segment boundary), other requests continue to the upstream
	TimeoutMs     int    `json:",omitempty"` //Wall clock limit, default 100, max 2000
	MaxResponseKB int    `json:",omitempty"` //Response body cap, default 256, max 1024
	Concurrency   int    `json:",omitempty"` //Parallel runs of this script, default 4, max 32

	rt atomic.Pointer[scriptRuntime] `json:"-"`
}

type scriptRuntime struct {
	script *luascript.Script
	err    error
}

// Validate checks the config and compiles the script
func (c *ScriptConfig) Validate() error {
	if c == nil {
		return nil
	}
	switch c.Mode {
	case "", ScriptModeHandler, ScriptModeHook:
	default:
		return errors.New("script mode must be handler or hook")
	}
	if c.PathPrefix != "" {
		if !strings.HasPrefix(c.PathPrefix, "/") || hasControl(c.PathPrefix) || len(c.PathPrefix) > 512 {
			return errors.New("script path prefix must start with /")
		}
	}
	if c.TimeoutMs < 0 || c.TimeoutMs > int(luascript.MaxTimeout/time.Millisecond) {
		return fmt.Errorf("script timeout must be 0-%d ms", int(luascript.MaxTimeout/time.Millisecond))
	}
	if c.MaxResponseKB < 0 || c.MaxResponseKB > luascript.MaxMaxResponse/1024 {
		return fmt.Errorf("script response limit must be 0-%d KiB", luascript.MaxMaxResponse/1024)
	}
	if c.Concurrency < 0 || c.Concurrency > luascript.MaxConcurrency {
		return fmt.Errorf("script concurrency must be 0-%d", luascript.MaxConcurrency)
	}
	if c.Enabled || strings.TrimSpace(c.Code) != "" {
		if _, err := c.compile("validate"); err != nil {
			return err
		}
	}
	return nil
}

func (c *ScriptConfig) limits() luascript.Limits {
	return luascript.Limits{
		Timeout:          time.Duration(c.TimeoutMs) * time.Millisecond,
		MaxResponseBytes: c.MaxResponseKB * 1024,
		Concurrency:      c.Concurrency,
	}
}

func (c *ScriptConfig) compile(name string) (*luascript.Script, error) {
	return luascript.Compile(name, c.Code, c.limits(), luascript.StoreFor(name))
}

func (c *ScriptConfig) runtime(rule string) *scriptRuntime {
	if rt := c.rt.Load(); rt != nil {
		return rt
	}
	s, err := c.compile(rule)
	rt := &scriptRuntime{script: s, err: err}
	c.rt.Store(rt)
	return rt
}

func (c *ScriptConfig) appliesTo(path string) bool {
	if c.PathPrefix == "" {
		return true
	}
	p := strings.TrimSuffix(c.PathPrefix, "/")
	return path == p || strings.HasPrefix(path, p+"/")
}

// ScriptRequestFrom builds the sandbox view of an HTTP request (shared by the proxy and the admin "test run")
func scriptRequestFrom(r *http.Request, rule, id, clientIP string, body []byte) *luascript.Request {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return &luascript.Request{
		Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Host: r.Host, ClientIP: clientIP,
		RuleName: rule, RequestID: id, Scheme: scheme, Headers: r.Header, Body: body,
	}
}

// handleScript runs the rule's script. It returns true when the request was answered.
func (h *ProxyHandler) handleScript(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	sc := sep.Script
	if sc == nil || !sc.Enabled || !sc.appliesTo(r.URL.Path) {
		return false
	}
	st := opsStateFrom(r)
	id, clientIP := "", ""
	if st != nil {
		id, clientIP = st.id, st.clientIP
	}
	fail := func(code int, msg string, err error) bool {
		h.Parent.Option.Logger.PrintAndLog("proxy-script", "Script of "+sep.RootOrMatchingDomain+" failed (request "+id+")", err)
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, strconv.Itoa(code)+" - "+msg+" (request id "+id+")", code)
		h.Parent.logRequest(r, false, code, "script-error", r.Host, "", sep)
		return true
	}
	rt := sc.runtime(sep.RootOrMatchingDomain)
	if rt.err != nil {
		return fail(http.StatusInternalServerError, "Script error", rt.err)
	}
	var body []byte
	if sc.Mode != ScriptModeHook && r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(r.Body, luascript.MaxRequestBody+1))
		if err != nil {
			return fail(http.StatusBadRequest, "Bad request", err)
		}
		if len(b) > luascript.MaxRequestBody {
			http.Error(w, "413 - Request body too large for a script handler", http.StatusRequestEntityTooLarge)
			return true
		}
		body = b
	}
	res, err := rt.script.Run(r.Context(), scriptRequestFrom(r, sep.RootOrMatchingDomain, id, clientIP, body))
	if err != nil {
		if errors.Is(err, luascript.ErrBusy) {
			w.Header().Set("Retry-After", "1")
			return fail(http.StatusServiceUnavailable, "Script busy", err)
		}
		return fail(http.StatusInternalServerError, "Script error", err)
	}
	for _, l := range res.Logs {
		h.Parent.Option.Logger.PrintAndLog("proxy-script", sep.RootOrMatchingDomain+": "+l, nil)
	}
	if sc.Mode == ScriptModeHook && !res.Responded {
		for _, kv := range res.ReqSet {
			r.Header.Set(kv[0], kv[1])
		}
		for _, n := range res.ReqDel {
			r.Header.Del(n)
		}
		return false
	}
	hd := w.Header()
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	for _, kv := range res.Headers {
		hd.Set(kv[0], kv[1])
	}
	if hd.Get("Content-Type") == "" && len(res.Body) > 0 {
		hd.Set("Content-Type", "text/plain; charset=utf-8")
	}
	hd.Set("Content-Length", strconv.Itoa(len(res.Body)))
	w.WriteHeader(res.Status)
	if r.Method != http.MethodHead && res.Status != http.StatusNoContent && res.Status != http.StatusNotModified {
		w.Write(res.Body)
	}
	h.Parent.logRequest(r, true, res.Status, "script", r.Host, "", sep)
	return true
}

// TestScript runs a script once with a sample request without touching any endpoint (admin "Test run").
type ScriptTestRequest struct {
	Method, Path, Query, Host, ClientIP, Body string
	Headers                                   map[string]string
}

type ScriptTestResult struct {
	Responded  bool
	Status     int
	Headers    [][2]string
	Body       string
	Truncated  bool
	ReqSet     [][2]string
	ReqDel     []string
	Logs       []string
	DurationMs float64
	Error      string
}

func RunScriptTest(cfg *ScriptConfig, rule string, in ScriptTestRequest) *ScriptTestResult {
	out := &ScriptTestResult{}
	if err := cfg.Validate(); err != nil {
		out.Error = err.Error()
		return out
	}
	//A throw-away store so test runs never touch the persistent KV of the real rule
	s, err := luascript.Compile("test:"+rule, cfg.Code, cfg.limits(), luascript.NewKV())
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if in.Method == "" {
		in.Method = "GET"
	}
	if in.Path == "" {
		in.Path = "/"
	}
	if len(in.Body) > luascript.MaxRequestBody {
		out.Error = "sample body too large"
		return out
	}
	hdr := map[string][]string{}
	for k, v := range in.Headers {
		hdr[k] = []string{v}
	}
	body := []byte(in.Body)
	if cfg.Mode == ScriptModeHook {
		body = nil
	}
	res, err := s.Run(context.Background(), &luascript.Request{
		Method: strings.ToUpper(in.Method), Path: in.Path, RawQuery: in.Query, Host: in.Host, ClientIP: in.ClientIP,
		RuleName: rule, RequestID: "test-run", Scheme: "https", Headers: hdr, Body: body,
	})
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Responded = res.Responded || cfg.Mode != ScriptModeHook
	out.Status, out.Headers, out.ReqSet, out.ReqDel, out.Logs = res.Status, res.Headers, res.ReqSet, res.ReqDel, res.Logs
	out.DurationMs = float64(res.Duration.Microseconds()) / 1000
	out.Body = string(res.Body)
	if len(out.Body) > 32*1024 {
		out.Body, out.Truncated = out.Body[:32*1024], true
	}
	return out
}
