package plugins

import (
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"

	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

/*
	Verdict validation

	Everything a plugin returns is untrusted. These functions validate a verdict
	completely BEFORE anything is applied, so a malformed verdict never leaves a
	request half modified.
*/

// hop-by-hop headers and headers that describe the message framing; a plugin may never touch them
var framingHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Proxy-Connection": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
	"Content-Length": true, "Content-Encoding": true, "Expect": true,
}

// headers that carry the client identity / routing, owned by Zoraxy
var identityRequestHeaders = map[string]bool{
	"Host": true, "X-Forwarded-For": true, "X-Forwarded-Host": true, "X-Forwarded-Proto": true,
	"X-Forwarded-Port": true, "X-Real-Ip": true, "Forwarded": true, "Origin-Host": true,
}

// response headers a plugin may not change besides the framing ones
var protectedResponseHeaders = map[string]bool{
	"Content-Range": true, "Accept-Ranges": true, "Content-Length": true,
}

// deny page headers a plugin may set (plus every X- header)
var denyHeaderAllowList = map[string]bool{
	"Content-Type": true, "Cache-Control": true, "Retry-After": true, "Content-Language": true,
	"Www-Authenticate": true, "Content-Security-Policy": true, "Referrer-Policy": true,
	"Expires": true, "Pragma": true,
}

const maxDenyHeaders = 16

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func validHeaderName(name string) error {
	if name == "" || len(name) > 128 {
		return errors.New("invalid header name length")
	}
	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return fmt.Errorf("invalid character in header name %q", name)
		}
	}
	return nil
}

func validHeaderValue(v string) error {
	if len(v) > zoraxyPlugin.MaxHeaderValueBytes {
		return errors.New("header value too large")
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return errors.New("control character in header value")
		}
	}
	return nil
}

type headerKind int

const (
	kindRequest headerKind = iota
	kindResponse
)

// checkHeaderOp validates one header operation. op is "add", "set" or "remove".
func checkHeaderOp(kind headerKind, op, rawName string) (string, error) {
	if err := validHeaderName(rawName); err != nil {
		return "", err
	}
	name := textproto.CanonicalMIMEHeaderKey(rawName)
	if framingHeaders[name] {
		return "", fmt.Errorf("header %s cannot be modified by plugins", name)
	}
	switch kind {
	case kindRequest:
		if identityRequestHeaders[name] {
			return "", fmt.Errorf("request header %s cannot be modified by plugins", name)
		}
		if strings.HasPrefix(name, "X-Zoraxy-") {
			return "", fmt.Errorf("request header %s is reserved", name)
		}
	case kindResponse:
		if protectedResponseHeaders[name] {
			return "", fmt.Errorf("response header %s cannot be modified by plugins", name)
		}
		//Plugins may append their own cookies but can never replace or delete cookies
		//(that would break the SSO / session cookies Zoraxy and the upstream set)
		if name == "Set-Cookie" && op != "add" {
			return "", errors.New("Set-Cookie can only be added, not set or removed")
		}
	}
	return name, nil
}

// sanitizeHeaderOps returns a canonicalised copy of ops, or an error if anything is not allowed.
func sanitizeHeaderOps(kind headerKind, ops *zoraxyPlugin.HeaderOps) (*zoraxyPlugin.HeaderOps, error) {
	if ops == nil {
		return nil, nil
	}
	if len(ops.Add)+len(ops.Set)+len(ops.Remove) > zoraxyPlugin.MaxHeaderOps {
		return nil, errors.New("too many header operations")
	}
	out := &zoraxyPlugin.HeaderOps{}
	total := 0
	if len(ops.Add) > 0 {
		out.Add = map[string]string{}
	}
	if len(ops.Set) > 0 {
		out.Set = map[string]string{}
	}
	for k, v := range ops.Add {
		name, err := checkHeaderOp(kind, "add", k)
		if err != nil {
			return nil, err
		}
		if err := validHeaderValue(v); err != nil {
			return nil, err
		}
		out.Add[name] = v
		total += len(v)
	}
	for k, v := range ops.Set {
		name, err := checkHeaderOp(kind, "set", k)
		if err != nil {
			return nil, err
		}
		if err := validHeaderValue(v); err != nil {
			return nil, err
		}
		out.Set[name] = v
		total += len(v)
	}
	for _, k := range ops.Remove {
		name, err := checkHeaderOp(kind, "remove", k)
		if err != nil {
			return nil, err
		}
		out.Remove = append(out.Remove, name)
	}
	if total > 4*zoraxyPlugin.MaxHeaderValueBytes {
		return nil, errors.New("header operations too large")
	}
	return out, nil
}

// applyHeaderOps applies already sanitised ops: remove, then set, then add
func applyHeaderOps(h http.Header, ops *zoraxyPlugin.HeaderOps) {
	if ops == nil {
		return
	}
	for _, k := range ops.Remove {
		h.Del(k)
	}
	for k, v := range ops.Set {
		h.Set(k, v)
	}
	for k, v := range ops.Add {
		h.Add(k, v)
	}
}

func validateRewritePath(p string) error {
	if p == "" || len(p) > zoraxyPlugin.MaxPathBytes {
		return errors.New("invalid path length")
	}
	if p[0] != '/' || strings.HasPrefix(p, "//") {
		return errors.New("path must be absolute and must not start with //")
	}
	if strings.ContainsAny(p, "?#\\") {
		return errors.New("path must not contain ?, # or backslash (use the query field)")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return errors.New("control character in path")
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return errors.New("path must not contain .. segments")
		}
	}
	return nil
}

func validateRewriteQuery(q string) error {
	if len(q) > zoraxyPlugin.MaxQueryBytes {
		return errors.New("query too large")
	}
	if strings.HasPrefix(q, "?") || strings.Contains(q, "#") {
		return errors.New("query must be the raw query without ? or #")
	}
	for i := 0; i < len(q); i++ {
		if q[i] < 0x20 || q[i] == 0x7f || q[i] == ' ' {
			return errors.New("control character or space in query")
		}
	}
	return nil
}

// cleanVerdict is a verdict that passed validation for a stage
type cleanVerdict struct {
	Action     string
	Reason     string
	DenyStatus int
	DenyBody   string
	DenyHeader map[string]string
	ReqHeaders *zoraxyPlugin.HeaderOps
	ResHeaders *zoraxyPlugin.HeaderOps
	Path       *string
	Query      *string
}

func sanitizeReason(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// sanitizeVerdict validates a verdict for the given stage
func sanitizeVerdict(stage zoraxyPlugin.HookStage, v *zoraxyPlugin.FilterVerdict) (*cleanVerdict, error) {
	if v == nil {
		return nil, errors.New("empty verdict")
	}
	if v.Version > zoraxyPlugin.HookAPIVersion {
		return nil, fmt.Errorf("unsupported verdict version %d", v.Version)
	}
	out := &cleanVerdict{Action: v.Action, Reason: sanitizeReason(v.Reason)}
	isResponse := stage == zoraxyPlugin.HookStageResponse
	switch v.Action {
	case zoraxyPlugin.ActionAllow:
		return out, nil
	case zoraxyPlugin.ActionCapture:
		//Whether capture is honoured at this stage is decided by the caller
		if isResponse {
			return nil, errors.New("capture is not valid at the response stage")
		}
		return out, nil
	case zoraxyPlugin.ActionDeny:
		if isResponse {
			return nil, errors.New("deny is not valid at the response stage")
		}
		d := v.Deny
		if d == nil {
			d = &zoraxyPlugin.DenyAction{}
		}
		out.DenyStatus = d.Status
		if out.DenyStatus == 0 {
			out.DenyStatus = http.StatusForbidden
		}
		if out.DenyStatus < 400 || out.DenyStatus > 599 {
			return nil, fmt.Errorf("deny status %d out of range 400-599", d.Status)
		}
		if len(d.Body) > zoraxyPlugin.MaxDenyBodyBytes {
			return nil, errors.New("deny body too large")
		}
		out.DenyBody = d.Body
		if len(d.Headers) > maxDenyHeaders {
			return nil, errors.New("too many deny headers")
		}
		if len(d.Headers) > 0 {
			out.DenyHeader = map[string]string{}
		}
		for k, val := range d.Headers {
			if err := validHeaderName(k); err != nil {
				return nil, err
			}
			name := textproto.CanonicalMIMEHeaderKey(k)
			if !denyHeaderAllowList[name] && !strings.HasPrefix(name, "X-") {
				return nil, fmt.Errorf("deny header %s is not allowed", name)
			}
			if strings.HasPrefix(name, "X-Zoraxy-") {
				return nil, fmt.Errorf("deny header %s is reserved", name)
			}
			if err := validHeaderValue(val); err != nil {
				return nil, err
			}
			out.DenyHeader[name] = val
		}
		return out, nil
	case zoraxyPlugin.ActionModify:
		m := v.Modify
		if m == nil {
			return nil, errors.New("modify verdict without modify object")
		}
		if isResponse {
			if m.RequestHeaders != nil || m.Path != nil || m.Query != nil {
				return nil, errors.New("only response_headers can be modified at the response stage")
			}
			h, err := sanitizeHeaderOps(kindResponse, m.ResponseHeaders)
			if err != nil {
				return nil, err
			}
			out.ResHeaders = h
			return out, nil
		}
		if m.ResponseHeaders != nil {
			return nil, errors.New("response_headers can only be modified at the response stage")
		}
		h, err := sanitizeHeaderOps(kindRequest, m.RequestHeaders)
		if err != nil {
			return nil, err
		}
		out.ReqHeaders = h
		if m.Path != nil {
			if err := validateRewritePath(*m.Path); err != nil {
				return nil, err
			}
			p := *m.Path
			out.Path = &p
		}
		if m.Query != nil {
			if err := validateRewriteQuery(*m.Query); err != nil {
				return nil, err
			}
			q := *m.Query
			out.Query = &q
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown action %q", v.Action)
}

// applyRequestModify applies a validated verdict to the request. The host
// (r.Host, r.URL.Host) is never touched.
func applyRequestModify(r *http.Request, c *cleanVerdict) {
	applyHeaderOps(r.Header, c.ReqHeaders)
	if c.Path != nil || c.Query != nil {
		if c.Path != nil {
			r.URL.Path = *c.Path
			r.URL.RawPath = ""
		}
		if c.Query != nil {
			r.URL.RawQuery = *c.Query
		}
		r.RequestURI = r.URL.RequestURI()
	}
}

// sanitizeHookSpec normalises the optional hooks block of an introspection payload.
// It never fails: unusable parts are dropped and reported as warnings.
func sanitizeHookSpec(spec *zoraxyPlugin.IntroSpect) []string {
	var warns []string
	h := spec.Hooks
	if h == nil {
		return nil
	}
	if h.Version == 0 {
		h.Version = 1
	}
	if h.Version > zoraxyPlugin.HookAPIVersion {
		spec.Hooks = nil
		return []string{fmt.Sprintf("hooks version %d is newer than supported version %d, hooks ignored", h.Version, zoraxyPlugin.HookAPIVersion)}
	}
	stages := []zoraxyPlugin.HookStage{}
	seen := map[zoraxyPlugin.HookStage]bool{}
	for _, s := range h.Stages {
		switch s {
		case zoraxyPlugin.HookStagePreAuth, zoraxyPlugin.HookStagePostAuth, zoraxyPlugin.HookStageResponse:
			if !seen[s] {
				seen[s] = true
				stages = append(stages, s)
			}
		default:
			warns = append(warns, fmt.Sprintf("unknown hook stage %q ignored", s))
		}
	}
	h.Stages = stages
	h.FilterRequestPath = cleanEndpointPath(h.FilterRequestPath)
	h.FilterResponsePath = cleanEndpointPath(h.FilterResponsePath)
	if len(stages) > 0 && h.PathForStage(zoraxyPlugin.HookStagePreAuth) == "" {
		warns = append(warns, "hooks declared without a valid filter_request_path, hooks ignored")
		h.Stages = nil
	}
	switch h.FailurePolicy {
	case "", zoraxyPlugin.FailureOpen, zoraxyPlugin.FailureClosed:
	default:
		warns = append(warns, fmt.Sprintf("unknown failure policy %q, using fail_open", h.FailurePolicy))
		h.FailurePolicy = zoraxyPlugin.FailureOpen
	}
	if h.TimeoutMs < 0 {
		h.TimeoutMs = 0
	}
	if h.TimeoutMs > zoraxyPlugin.MaxHookTimeoutMs {
		h.TimeoutMs = zoraxyPlugin.MaxHookTimeoutMs
	}
	if h.BodyPreviewBytes < 0 {
		h.BodyPreviewBytes = 0
	}
	if h.BodyPreviewBytes > zoraxyPlugin.MaxBodyPreviewBytes {
		h.BodyPreviewBytes = zoraxyPlugin.MaxBodyPreviewBytes
	}
	return warns
}

// cleanEndpointPath returns a safe endpoint path ("" if unusable)
func cleanEndpointPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.ContainsAny(p, "?#\\ ") || strings.Contains(p, "..") || strings.HasPrefix(p, "//") {
		return ""
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return ""
		}
	}
	return p
}
