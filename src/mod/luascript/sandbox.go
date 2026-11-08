// Package luascript runs administrator-authored Lua scripts (gopher-lua) inside the proxy process.
//
// This is code execution on the proxy host's CPU and heap, so the sandbox is deliberately small:
//
//   - only the base, table, string and math libraries are opened; dofile, loadfile, load, loadstring, require, module,
//     getfenv, setfenv, collectgarbage and print are removed. There is no os, io, package, debug or coroutine library,
//     no socket access and no way to load code at run time.
//   - every run gets a fresh Lua state (no cross-request globals), a call stack and registry cap (deep recursion and
//     huge unpack() fail with "stack overflow"), a wall-clock deadline enforced through context cancellation (checked on
//     every VM instruction), a live-heap growth watchdog, and a response size cap.
//   - the string functions that could allocate or spin without bound are replaced: string.rep and string.format are size
//     capped and the pattern functions use a step-budgeted matcher (lpattern.go).
//   - at most Concurrency runs of one script execute at the same time, extra requests wait for the remaining time budget and
//     then fail with ErrBusy. Panics are recovered and reported as errors.
//
// Known limits (documented in DEVELOPMENT.md): the instruction limit is time based, the heap watchdog is sampled (2 ms) and
// process wide, so a script can briefly overshoot its allocation ceiling by a small multiple.
package luascript

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime/metrics"
	"strings"
	"sync/atomic"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

const (
	DefaultTimeout     = 100 * time.Millisecond
	MaxTimeout         = 2 * time.Second
	DefaultMaxResponse = 256 * 1024
	MaxMaxResponse     = 1024 * 1024
	MaxSourceBytes     = 64 * 1024
	MaxRequestBody     = 64 * 1024
	DefaultConcurrency = 4
	MaxConcurrency     = 32
	DefaultHeapGrowth  = 64 << 20
	maxRepBytes        = 1 << 20
	stopSentinel       = "\x00zoraxy-script-stop"
)

var (
	ErrTimeout = errors.New("script timed out")
	ErrBusy    = errors.New("script is busy (too many concurrent runs)")
	ErrMemory  = errors.New("script exceeded its memory ceiling")
)

// Limits bound one script. Zero values take the defaults.
type Limits struct {
	Timeout          time.Duration
	MaxResponseBytes int
	MaxHeapGrowth    uint64
	Concurrency      int
}

func (l Limits) normalised() Limits {
	if l.Timeout <= 0 {
		l.Timeout = DefaultTimeout
	}
	if l.Timeout > MaxTimeout {
		l.Timeout = MaxTimeout
	}
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = DefaultMaxResponse
	}
	if l.MaxResponseBytes > MaxMaxResponse {
		l.MaxResponseBytes = MaxMaxResponse
	}
	if l.MaxHeapGrowth == 0 {
		l.MaxHeapGrowth = DefaultHeapGrowth
	}
	if l.Concurrency <= 0 {
		l.Concurrency = DefaultConcurrency
	}
	if l.Concurrency > MaxConcurrency {
		l.Concurrency = MaxConcurrency
	}
	return l
}

// Request is the read-only view of the HTTP request handed to the script
type Request struct {
	Method, Path, RawQuery, Host, ClientIP, RuleName, RequestID, Scheme string
	Headers                                                             map[string][]string
	Body                                                                []byte // optional, at most MaxRequestBody bytes
}

// Result is what a run produced
type Result struct {
	Responded bool // respond() / redirect() was called or the response table was changed
	Status    int
	Headers   [][2]string
	Body      []byte
	ReqSet    [][2]string // request headers to set on the proxied request (hook mode)
	ReqDel    []string
	Logs      []string
	Duration  time.Duration
}

// Script is a compiled script. It is safe for concurrent use.
type Script struct {
	name   string
	proto  *lua.FunctionProto
	limits Limits
	sem    chan struct{}
	kv     *KV
}

// ScriptError is a script failure (syntax is reported by Compile). Message may contain line numbers but never source text.
type ScriptError struct{ Msg string }

func (e *ScriptError) Error() string { return e.Msg }

// Compile parses src. name identifies the script for its KV store and error messages.
func Compile(name, src string, lim Limits, kv *KV) (*Script, error) {
	if len(src) > MaxSourceBytes {
		return nil, fmt.Errorf("script is larger than %d bytes", MaxSourceBytes)
	}
	if strings.TrimSpace(src) == "" {
		return nil, errors.New("script is empty")
	}
	if strings.HasPrefix(src, "\x1bLua") {
		return nil, errors.New("precompiled chunks are not accepted")
	}
	stmts, err := parse.Parse(strings.NewReader(src), "script")
	if err != nil {
		return nil, &ScriptError{Msg: "syntax error: " + cleanErr(err.Error())}
	}
	proto, err := lua.Compile(stmts, "script")
	if err != nil {
		return nil, &ScriptError{Msg: "compile error: " + cleanErr(err.Error())}
	}
	lim = lim.normalised()
	if kv == nil {
		kv = NewKV()
	}
	return &Script{name: name, proto: proto, limits: lim, sem: make(chan struct{}, lim.Concurrency), kv: kv}, nil
}

func cleanErr(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

var abandoned atomic.Int64 // runs whose goroutine did not stop after the grace period (a native function stuck; should stay 0)

// Abandoned returns the number of runs that had to be abandoned
func Abandoned() int64 { return abandoned.Load() }

func liveHeap() uint64 {
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() == metrics.KindUint64 {
		return sample[0].Value.Uint64()
	}
	return 0
}

// Run executes the script. parent cancels the run too (client went away).
func (s *Script) Run(parent context.Context, req *Request) (*Result, error) {
	ctx, cancel := context.WithTimeout(parent, s.limits.Timeout)
	defer cancel()

	//Concurrency pool: wait for a slot within the time budget
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrBusy
	}
	if abandoned.Load() > 16 {
		<-s.sem
		return nil, errors.New("too many stuck script runs, refusing to run scripts")
	}

	start := time.Now()
	var res *Result
	var runErr error
	var memExceeded atomic.Bool
	done := make(chan struct{})

	go func() {
		defer func() {
			<-s.sem
			close(done)
		}()
		defer func() {
			if r := recover(); r != nil {
				runErr = &ScriptError{Msg: fmt.Sprintf("script panic: %v", r)}
			}
		}()
		res, runErr = s.execute(ctx, req)
	}()

	//Heap watchdog
	base := liveHeap()
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	grace := time.NewTimer(s.limits.Timeout + 250*time.Millisecond)
	defer grace.Stop()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-tick.C:
			if h := liveHeap(); h > base && h-base > s.limits.MaxHeapGrowth && !memExceeded.Load() {
				memExceeded.Store(true)
				cancel()
			}
		case <-grace.C:
			abandoned.Add(1)
			go func() { <-done; abandoned.Add(-1) }()
			return nil, ErrTimeout
		}
	}
	if memExceeded.Load() {
		return nil, ErrMemory
	}
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && isContextErr(runErr) {
			return nil, ErrTimeout
		}
		if isContextErr(runErr) {
			return nil, ErrTimeout
		}
		return nil, runErr
	}
	res.Duration = time.Since(start)
	return res, nil
}

func isContextErr(err error) bool {
	m := err.Error()
	return strings.Contains(m, "context deadline exceeded") || strings.Contains(m, "context canceled")
}

func (s *Script) execute(ctx context.Context, req *Request) (*Result, error) {
	L := lua.NewState(lua.Options{
		SkipOpenLibs:        true,
		CallStackSize:       120,
		RegistrySize:        1024,
		RegistryMaxSize:     40960,
		RegistryGrowStep:    256,
		MinimizeStackMemory: true,
	})
	defer L.Close()
	L.SetContext(ctx)
	openSandboxLibs(L)

	r := &runState{res: &Result{Status: 200}, lim: s.limits, kv: s.kv, name: s.name}
	r.install(L, req)

	fn := L.NewFunctionFromProto(s.proto)
	L.Push(fn)
	err := L.PCall(0, 0, nil)
	if err != nil {
		if ae, ok := err.(*lua.ApiError); ok {
			if str, ok := ae.Object.(lua.LString); ok && string(str) == stopSentinel {
				err = nil
			}
		}
	}
	if err != nil {
		return nil, &ScriptError{Msg: cleanErr(err.Error())}
	}
	if err := r.collect(L); err != nil {
		return nil, err
	}
	return r.res, nil
}

// openSandboxLibs opens the safe subset and removes the dangerous base functions
func openSandboxLibs(L *lua.LState) {
	for _, lib := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		L.Push(L.NewFunction(lib.fn))
		L.Push(lua.LString(lib.name))
		L.Call(1, 0)
	}
	for _, name := range []string{"dofile", "loadfile", "load", "loadstring", "require", "module", "getfenv", "setfenv",
		"collectgarbage", "print", "_printregs", "newproxy", "coroutine", "os", "io", "debug", "package"} {
		L.SetGlobal(name, lua.LNil)
	}
	//math.random is seeded by gopher-lua from the clock; keep it, it is not security relevant here
	str := L.GetGlobal("string").(*lua.LTable)
	L.SetField(str, "find", L.NewFunction(strFind))
	L.SetField(str, "match", L.NewFunction(strMatch))
	L.SetField(str, "gmatch", L.NewFunction(strGmatch))
	L.SetField(str, "gsub", L.NewFunction(strGsub))
	L.SetField(str, "rep", L.NewFunction(strRep))
	origFormat := L.GetField(str, "format")
	L.SetField(str, "format", L.NewFunction(func(L *lua.LState) int {
		f := L.CheckString(1)
		if len(f) > 512 {
			L.ArgError(1, "format string too long")
		}
		for i := 0; i < len(f); i++ {
			if f[i] != '%' {
				continue
			}
			i++
			num := 0
			for i < len(f) && (f[i] >= '0' && f[i] <= '9' || f[i] == '.' || f[i] == '-' || f[i] == '+' || f[i] == ' ' || f[i] == '#') {
				if f[i] >= '0' && f[i] <= '9' {
					num = num*10 + int(f[i]-'0')
					if num > 99 {
						L.ArgError(1, "format width or precision too large")
					}
				} else {
					num = 0
				}
				i++
			}
		}
		top := L.GetTop()
		args := make([]lua.LValue, 0, top)
		for i := 1; i <= top; i++ {
			args = append(args, L.Get(i))
		}
		L.Push(origFormat)
		for _, a := range args {
			L.Push(a)
		}
		L.Call(len(args), 1)
		out := L.Get(-1)
		if s, ok := out.(lua.LString); ok && len(s) > maxRepBytes {
			L.RaiseError("result too large")
		}
		return 1
	}))
	//The shared string metatable resolves ("x"):rep() through the string table, so the replacements above apply to it as well
}

func strRep(L *lua.LState) int {
	s := L.CheckString(1)
	n := L.CheckInt(2)
	if n <= 0 || len(s) == 0 {
		L.Push(lua.LString(""))
		return 1
	}
	if len(s) > maxRepBytes || n > maxRepBytes || len(s)*n > maxRepBytes {
		L.RaiseError("resulting string too large")
	}
	L.Push(lua.LString(strings.Repeat(s, n)))
	return 1
}

// runState is the per run Go side of the sandbox API
type runState struct {
	res  *Result
	lim  Limits
	kv   *KV
	name string
	resp *lua.LTable
	logN int
}

func (r *runState) log(msg string) {
	if len(r.res.Logs) >= 50 {
		return
	}
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	r.res.Logs = append(r.res.Logs, msg)
}

func validHeaderName(n string) bool {
	if n == "" || len(n) > 100 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

func validHeaderValue(v string) bool {
	if len(v) > 8192 {
		return false
	}
	return !strings.ContainsAny(v, "\r\n\x00")
}

var forbiddenResponseHeaders = map[string]bool{
	"content-length": true, "transfer-encoding": true, "connection": true, "upgrade": true, "host": true,
	"trailer": true, "te": true, "keep-alive": true, "proxy-authenticate": true, "proxy-authorization": true,
}

func (r *runState) install(L *lua.LState, req *Request) {
	// request
	rt := L.NewTable()
	L.SetField(rt, "method", lua.LString(req.Method))
	L.SetField(rt, "path", lua.LString(req.Path))
	L.SetField(rt, "query", lua.LString(req.RawQuery))
	L.SetField(rt, "host", lua.LString(req.Host))
	L.SetField(rt, "client_ip", lua.LString(req.ClientIP))
	L.SetField(rt, "rule", lua.LString(req.RuleName))
	L.SetField(rt, "request_id", lua.LString(req.RequestID))
	L.SetField(rt, "scheme", lua.LString(req.Scheme))
	L.SetField(rt, "body", lua.LString(string(req.Body)))
	hdr := L.NewTable()
	for k, v := range req.Headers {
		L.SetField(hdr, strings.ToLower(k), lua.LString(strings.Join(v, ", ")))
	}
	L.SetField(rt, "headers", hdr)
	args := L.NewTable()
	for _, kv := range strings.Split(req.RawQuery, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		k, v = queryUnescape(k), queryUnescape(v)
		if L.GetField(args, k) == lua.LNil {
			L.SetField(args, k, lua.LString(v))
		}
	}
	L.SetField(rt, "args", args)
	L.SetGlobal("request", rt)

	// response
	r.resp = L.NewTable()
	L.SetField(r.resp, "status", lua.LNumber(200))
	L.SetField(r.resp, "body", lua.LString(""))
	L.SetField(r.resp, "headers", L.NewTable())
	L.SetGlobal("response", r.resp)

	stop := func(L *lua.LState) { L.Error(lua.LString(stopSentinel), 0) }

	L.SetGlobal("respond", L.NewFunction(func(L *lua.LState) int {
		L.SetField(r.resp, "status", lua.LNumber(L.CheckInt(1)))
		L.SetField(r.resp, "body", lua.LString(L.OptString(2, "")))
		if ct := L.OptString(3, ""); ct != "" {
			L.SetField(L.GetField(r.resp, "headers"), "Content-Type", lua.LString(ct))
		}
		r.res.Responded = true
		stop(L)
		return 0
	}))
	L.SetGlobal("redirect", L.NewFunction(func(L *lua.LState) int {
		loc := L.CheckString(1)
		code := L.OptInt(2, 302)
		if code < 300 || code > 399 || code == 304 {
			L.ArgError(2, "redirect status must be 300-399 (not 304)")
		}
		if !validHeaderValue(loc) || loc == "" {
			L.ArgError(1, "invalid redirect location")
		}
		L.SetField(r.resp, "status", lua.LNumber(code))
		L.SetField(L.GetField(r.resp, "headers"), "Location", lua.LString(loc))
		L.SetField(r.resp, "body", lua.LString(""))
		r.res.Responded = true
		stop(L)
		return 0
	}))
	L.SetGlobal("request_header_set", L.NewFunction(func(L *lua.LState) int {
		n, v := L.CheckString(1), L.CheckString(2)
		if !validHeaderName(n) || !validHeaderValue(v) || forbiddenResponseHeaders[strings.ToLower(n)] {
			L.ArgError(1, "invalid header")
		}
		if len(r.res.ReqSet) >= 50 {
			L.RaiseError("too many request header changes")
		}
		r.res.ReqSet = append(r.res.ReqSet, [2]string{n, v})
		return 0
	}))
	L.SetGlobal("request_header_del", L.NewFunction(func(L *lua.LState) int {
		n := L.CheckString(1)
		if !validHeaderName(n) {
			L.ArgError(1, "invalid header")
		}
		if len(r.res.ReqDel) >= 50 {
			L.RaiseError("too many request header changes")
		}
		r.res.ReqDel = append(r.res.ReqDel, n)
		return 0
	}))
	L.SetGlobal("log", L.NewFunction(func(L *lua.LState) int {
		top := L.GetTop()
		parts := make([]string, 0, top)
		for i := 1; i <= top; i++ {
			parts = append(parts, L.ToStringMeta(L.Get(i)).String())
		}
		r.log(strings.Join(parts, " "))
		return 0
	}))
	installLibs(L, r)
}

// collect reads the response table into the Result
func (r *runState) collect(L *lua.LState) error {
	status := L.GetField(r.resp, "status")
	n, ok := status.(lua.LNumber)
	if !ok {
		return &ScriptError{Msg: "response.status must be a number"}
	}
	code := int(n)
	if code < 200 || code > 599 {
		return &ScriptError{Msg: "response.status must be between 200 and 599"}
	}
	r.res.Status = code
	body := L.GetField(r.resp, "body")
	switch b := body.(type) {
	case lua.LString:
		r.res.Body = []byte(b)
	case lua.LNumber:
		r.res.Body = []byte(b.String())
	case *lua.LNilType:
	default:
		return &ScriptError{Msg: "response.body must be a string"}
	}
	if len(r.res.Body) > r.lim.MaxResponseBytes {
		return &ScriptError{Msg: fmt.Sprintf("response body larger than %d bytes", r.lim.MaxResponseBytes)}
	}
	if ht, ok := L.GetField(r.resp, "headers").(*lua.LTable); ok {
		count := 0
		var herr error
		ht.ForEach(func(k, v lua.LValue) {
			ks, ok1 := k.(lua.LString)
			vs, ok2 := v.(lua.LString)
			if vn, isNum := v.(lua.LNumber); isNum {
				vs, ok2 = lua.LString(vn.String()), true
			}
			if !ok1 || !ok2 || !validHeaderName(string(ks)) || !validHeaderValue(string(vs)) {
				herr = &ScriptError{Msg: "invalid response header"}
				return
			}
			if forbiddenResponseHeaders[strings.ToLower(string(ks))] {
				herr = &ScriptError{Msg: "response header " + string(ks) + " is not allowed"}
				return
			}
			count++
			if count > 50 {
				herr = &ScriptError{Msg: "too many response headers"}
				return
			}
			r.res.Headers = append(r.res.Headers, [2]string{string(ks), string(vs)})
		})
		if herr != nil {
			return herr
		}
	}
	if !r.res.Responded {
		//Hook mode treats an untouched response table as "continue"; a changed status/body/headers counts as an answer
		if code != 200 || len(r.res.Body) > 0 || len(r.res.Headers) > 0 {
			r.res.Responded = true
		}
	}
	return nil
}

func queryUnescape(s string) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isxdigit(s[i+1]) && isxdigit(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}
