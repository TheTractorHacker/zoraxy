package dynamicproxy

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"imuslab.com/zoraxy/mod/dynamicproxy/rewrite"
)

/*
	ops_handlers.go

	Request side of the ops options: request state, the response wrapper (CORS headers,
	error page interception, bandwidth limit), CORS preflight and static responses.
*/

// ---- global default error pages ----

var globalErrorPages atomic.Pointer[globalErrPages]

type globalErrPages struct {
	cfg *ErrorPagesConfig
	rt  *errorPagesRuntime
}

// SetGlobalErrorPages installs the default error pages used by rules that inherit. nil or mode != "on" disables.
func SetGlobalErrorPages(c *ErrorPagesConfig) error {
	if c == nil || c.Mode != ErrorPagesOn {
		globalErrorPages.Store(nil)
		return c.Validate()
	}
	if err := c.Validate(); err != nil {
		return err
	}
	globalErrorPages.Store(&globalErrPages{cfg: c, rt: buildErrorPagesRuntime(c)})
	return nil
}

// GetGlobalErrorPages returns the active global config (nil = off)
func GetGlobalErrorPages() *ErrorPagesConfig {
	if g := globalErrorPages.Load(); g != nil {
		return g.cfg
	}
	return nil
}

// errorPagesFor resolves the error page runtime that applies to an endpoint
func (ep *ProxyEndpoint) errorPagesFor() *errorPagesRuntime {
	if ep.Ops != nil && ep.Ops.ErrorPages != nil {
		switch ep.Ops.ErrorPages.Mode {
		case ErrorPagesOff:
			return nil
		case ErrorPagesOn:
			return ep.Ops.runtime().errPages
		}
	}
	if g := globalErrorPages.Load(); g != nil {
		return g.rt
	}
	return nil
}

// ---- per request state ----

type opsState struct {
	ep       *ProxyEndpoint
	clientIP string
	id       string
	armed    atomic.Bool //error pages only apply once the request is being proxied
}

type opsStateKey struct{}

// opsBegin attaches the request vars ({{request_id}} etc.), and returns the response wrapper if the
// endpoint needs one. r is updated in place so every later stage sees the new context.
func (router *Router) opsBegin(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) http.ResponseWriter {
	id := rewrite.SanitizeRequestID(r.Header.Get("X-Request-Id"))
	if id == "" {
		id = rewrite.NewRequestID()
	}
	st := &opsState{ep: sep, id: id, clientIP: router.GetClientIPForEndpoint(r, sep)}
	vars := &rewrite.RequestVars{RequestID: id, RuleName: sep.RootOrMatchingDomain, ClientIP: st.clientIP}
	*r = *rewrite.WithRequestVars(r, vars)
	*r = *r.WithContext(contextWithOpsState(r, st))

	if sep.Ops != nil {
		if sep.Ops.ForwardRequestID {
			r.Header.Set("X-Request-Id", id)
		}
		if sep.Ops.ExposeRequestID {
			w.Header().Set("X-Request-Id", id)
		}
	}
	if sep.Ops == nil && globalErrorPages.Load() == nil {
		return w
	}
	ow := &opsWriter{ResponseWriter: w, r: r, st: st, ep: sep}
	if sep.Ops != nil {
		ow.rt = sep.Ops.runtime()
	}
	ow.errPages = sep.errorPagesFor()
	return ow
}

// armOps marks the request as being proxied: from now on error statuses are replaced
func armOps(r *http.Request) {
	if st := opsStateFrom(r); st != nil {
		st.armed.Store(true)
	}
}

// ---- response wrapper ----

type opsWriter struct {
	http.ResponseWriter
	r        *http.Request
	st       *opsState
	ep       *ProxyEndpoint
	rt       *opsRuntime
	errPages *errorPagesRuntime

	wroteHeader bool
	discard     bool
	hijacked    bool
	bw          *bwConn
}

func (o *opsWriter) Unwrap() http.ResponseWriter { return o.ResponseWriter }

func (o *opsWriter) WriteHeader(code int) {
	if o.wroteHeader {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		o.ResponseWriter.WriteHeader(code) //informational, may repeat
		return
	}
	o.wroteHeader = true
	if o.rt != nil && o.rt.cors() {
		o.applyCORSHeaders()
	}
	if code >= 400 && o.errPages != nil && o.st.armed.Load() && o.errPages.statuses[code] && o.interceptable() {
		o.discard = true
		o.serveErrorPage(code)
		return
	}
	if o.rt != nil && o.rt.bw != nil && code != http.StatusSwitchingProtocols && code != http.StatusNoContent && code != http.StatusNotModified {
		o.bw = o.rt.bw.newConn(o.st.clientIP, o.r.Context())
	}
	o.ResponseWriter.WriteHeader(code)
}

// interceptable is false for streaming style responses that must be passed through untouched
func (o *opsWriter) interceptable() bool {
	h := o.Header()
	ct := strings.ToLower(h.Get("Content-Type"))
	if strings.HasPrefix(ct, "text/event-stream") || strings.HasPrefix(ct, "application/grpc") {
		return false
	}
	if h.Get("Grpc-Status") != "" || h.Get("Trailer") != "" || h.Get("Upgrade") != "" {
		return false
	}
	reqCT := strings.ToLower(o.r.Header.Get("Content-Type"))
	if strings.HasPrefix(reqCT, "application/grpc") || o.r.Header.Get("Upgrade") != "" || o.r.Method == http.MethodConnect {
		return false
	}
	return true
}

func (o *opsWriter) serveErrorPage(code int) {
	h := o.Header()
	for _, k := range []string{"Content-Length", "Content-Encoding", "Content-Type", "Content-Range", "Content-Disposition",
		"Etag", "Last-Modified", "Accept-Ranges", "Transfer-Encoding", "Trailer", "Content-Md5", "Content-Language", "Digest", "Location"} {
		h.Del(k)
	}
	tpl := o.errPages.def
	if t, ok := o.errPages.perStatus[code]; ok {
		tpl = t
	}
	var buf bytes.Buffer
	data := ErrorPageData{Status: code, StatusText: http.StatusText(code), RequestID: o.st.id, Host: o.r.Host, Path: o.r.URL.Path, RuleName: o.ep.RootOrMatchingDomain}
	if data.StatusText == "" {
		data.StatusText = "Error"
	}
	if err := tpl.Execute(&buf, data); err != nil || buf.Len() > MaxOpsTemplateBytes*4 {
		buf.Reset()
		buf.WriteString(strconv.Itoa(code) + " " + data.StatusText)
		h.Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		h.Set("Content-Type", "text/html; charset=utf-8")
	}
	if o.errPages.retryAfter > 0 && (code == 429 || code == 503) && h.Get("Retry-After") == "" {
		h.Set("Retry-After", strconv.Itoa(o.errPages.retryAfter))
	}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	o.ResponseWriter.WriteHeader(code)
	if o.r.Method != http.MethodHead {
		o.ResponseWriter.Write(buf.Bytes())
	}
}

func (o *opsWriter) Write(p []byte) (int, error) {
	if !o.wroteHeader {
		o.WriteHeader(http.StatusOK)
	}
	if o.discard {
		return len(p), nil
	}
	if o.bw != nil {
		return o.bw.write(o.ResponseWriter, p)
	}
	return o.ResponseWriter.Write(p)
}

func (o *opsWriter) Flush() {
	if !o.wroteHeader {
		o.WriteHeader(http.StatusOK)
	}
	if o.discard {
		return
	}
	if f, ok := o.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (o *opsWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := o.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	o.hijacked = true
	return hj.Hijack()
}

// ---- CORS ----

func (rt *opsRuntime) cors() bool { return len(rt.corsOrigins) > 0 }

// corsAllowOrigin returns the Access-Control-Allow-Origin value for the request origin
func (o *opsWriter) corsDecision(origin string) (string, bool) {
	return o.ep.Ops.corsAllowOrigin(origin)
}

func (c *OpsConfig) corsAllowOrigin(origin string) (string, bool) {
	rt := c.runtime()
	if origin == "" || !rt.cors() {
		return "", false
	}
	for _, m := range rt.corsOrigins {
		if m.any {
			if c.CORS.AllowCredentials {
				continue //never "*" with credentials
			}
			return "*", true
		}
		if m.match(origin) {
			return origin, true
		}
	}
	return "", false
}

func addVary(h http.Header, vals ...string) {
	existing := map[string]bool{}
	for _, v := range h.Values("Vary") {
		for _, p := range strings.Split(v, ",") {
			existing[strings.ToLower(strings.TrimSpace(p))] = true
		}
	}
	for _, v := range vals {
		if !existing[strings.ToLower(v)] {
			h.Add("Vary", v)
		}
	}
}

func (o *opsWriter) applyCORSHeaders() {
	cfg := o.ep.Ops.CORS
	h := o.Header()
	//Remove CORS headers the upstream set itself: the proxy policy is authoritative
	for _, k := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers"} {
		h.Del(k)
	}
	if !o.rt.corsAnyOrigin || cfg.AllowCredentials {
		addVary(h, "Origin")
	}
	allow, ok := o.corsDecision(o.r.Header.Get("Origin"))
	if !ok {
		return
	}
	h.Set("Access-Control-Allow-Origin", allow)
	if cfg.AllowCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if len(cfg.ExposeHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposeHeaders, ", "))
	}
}

// handleCORSPreflight answers OPTIONS preflights itself. Returns true if the request was answered.
func (h *ProxyHandler) handleCORSPreflight(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if sep.Ops == nil || sep.Ops.CORS == nil || !sep.Ops.CORS.Enabled {
		return false
	}
	if r.Method != http.MethodOptions || r.Header.Get("Origin") == "" || r.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	cfg := sep.Ops.CORS
	rt := sep.Ops.runtime()
	hd := w.Header()
	if !rt.corsAnyOrigin || cfg.AllowCredentials {
		addVary(hd, "Origin")
	}
	addVary(hd, "Access-Control-Request-Method", "Access-Control-Request-Headers")
	allow, ok := sep.Ops.corsAllowOrigin(r.Header.Get("Origin"))
	reqMethod := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
	methodOK := false
	for _, m := range rt.corsMethods {
		if m == "*" || strings.ToUpper(m) == reqMethod {
			methodOK = true
		}
	}
	reqHeaders := splitList(r.Header.Get("Access-Control-Request-Headers"))
	headersOK := true
	if len(cfg.AllowedHeaders) > 0 {
		anyHdr := false
		set := map[string]bool{}
		for _, a := range cfg.AllowedHeaders {
			if a == "*" {
				anyHdr = true
			}
			set[strings.ToLower(a)] = true
		}
		for _, rh := range reqHeaders {
			if !anyHdr && !set[strings.ToLower(rh)] {
				headersOK = false
			}
		}
	}
	if !ok || !methodOK || !headersOK {
		hd.Set("Content-Length", "0")
		w.WriteHeader(http.StatusForbidden)
		return true
	}
	hd.Set("Access-Control-Allow-Origin", allow)
	if cfg.AllowCredentials {
		hd.Set("Access-Control-Allow-Credentials", "true")
	}
	hd.Set("Access-Control-Allow-Methods", strings.Join(rt.corsMethods, ", "))
	if len(reqHeaders) > 0 {
		hd.Set("Access-Control-Allow-Headers", strings.Join(reqHeaders, ", ")) //only reached when allowed above
	}
	if cfg.MaxAgeSeconds > 0 {
		hd.Set("Access-Control-Max-Age", strconv.Itoa(cfg.MaxAgeSeconds))
	}
	hd.Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
	return true
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---- static responses ----

func (s *StaticResponse) matches(r *http.Request) bool {
	p := r.URL.Path
	if s.MatchMode == "prefix" {
		base := strings.TrimSuffix(s.Path, "/")
		if p != base && !strings.HasPrefix(p, base+"/") {
			return false
		}
	} else if p != s.Path {
		return false
	}
	methods := s.Methods
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD"}
	}
	for _, m := range methods {
		m = strings.ToUpper(m)
		if m == r.Method || (m == "GET" && r.Method == http.MethodHead) {
			return true
		}
	}
	return false
}

// handleStaticResponses serves the first matching static response with the given public flag
func (h *ProxyHandler) handleStaticResponses(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint, public bool) bool {
	if sep.Ops == nil || len(sep.Ops.StaticResponses) == 0 {
		return false
	}
	for _, s := range sep.Ops.runtime().statics {
		if s.Public != public || !s.matches(r) {
			continue
		}
		hd := w.Header()
		for _, kv := range s.Headers {
			hd.Set(kv.Name, rewrite.ExpandTemplateVars(r, kv.Value))
		}
		if s.Location != "" {
			hd.Set("Location", rewrite.ExpandTemplateVars(r, s.Location))
		}
		hasBody := s.Status != http.StatusNoContent && s.Status != http.StatusNotModified && s.Body != ""
		var body string
		if hasBody {
			ct := s.ContentType
			if ct == "" {
				ct = "text/plain; charset=utf-8"
			}
			hd.Set("Content-Type", ct)
			body = rewrite.ExpandTemplateVars(r, s.Body)
			hd.Set("Content-Length", strconv.Itoa(len(body)))
		}
		hd.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(s.Status)
		if hasBody && r.Method != http.MethodHead {
			w.Write([]byte(body))
		}
		h.Parent.logRequest(r, true, s.Status, "static-response", r.Host, "", sep)
		return true
	}
	return false
}
