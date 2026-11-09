package waf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	pathpkg "path"
	"strconv"
	"strings"
	"time"
)

/*
	apiguard.go

	Guard enforces the API protection of one endpoint: URL / header / query
	limits, the method + content type allow-list, bounded body structure
	checks (JSON, XML, forms) and the optional OpenAPI validation. It runs
	before (and independently of) the Coraza based Instance.

	Body handling: bodies up to the configured limit are buffered, checked and
	replayed byte for byte (same replayBody as Inspect, so the CRS inspection
	that may follow reads the same bytes). Bodies above the limit are rejected
	(413) in block mode or replayed untouched in log mode. At most limit+1 bytes
	are ever buffered, and the checkers do not build trees.
*/

// Violation codes. Each has a pseudo rule ID (shown in the events table), an HTTP status and a title.
const (
	codeURLLen             = "url.length"
	codeHeaderCount        = "header.count"
	codeHeaderSize         = "header.size"
	codeQueryParams        = "query.params"
	codeQueryParamLen      = "query.param-length"
	codeBodySize           = "body.size"
	codeSyntax             = "content-type.mismatch"
	codeJSONDepth          = "json.depth"
	codeJSONKeys           = "json.keys"
	codeJSONArrayLen       = "json.array-length"
	codeJSONStringLen      = "json.string-length"
	codeJSONDupKey         = "json.duplicate-key"
	codeJSONUTF8           = "json.utf8"
	codeXMLDoctype         = "xml.doctype"
	codeXMLDepth           = "xml.depth"
	codeXMLElements        = "xml.elements"
	codeXMLAttrs           = "xml.attributes"
	codeFormFields         = "form.fields"
	codeMultipartParts     = "multipart.parts"
	codeMultipartFiles     = "multipart.files"
	codeAllowMethod        = "allow.method"
	codeAllowContentType   = "allow.content-type"
	codeOpenAPIPath        = "openapi.path"
	codeOpenAPIMethod      = "openapi.method"
	codeOpenAPIParam       = "openapi.parameter"
	codeOpenAPIBody        = "openapi.body"
	codeOpenAPIContentType = "openapi.content-type"
	codeOpenAPIError       = "openapi.error"
)

// APIRuleBase is the first pseudo rule ID of API protection events (CRS uses 9xxxxx)
const APIRuleBase = 800000

// APIViolationInfo describes one violation kind
type APIViolationInfo struct {
	Code   string `json:"code"`
	ID     int    `json:"id"`
	Status int    `json:"status"`
	Title  string `json:"title"`
}

var apiViolationList = []APIViolationInfo{
	{codeURLLen, 800010, 414, "URL too long"},
	{codeHeaderCount, 800011, 431, "Too many request headers"},
	{codeHeaderSize, 800012, 431, "Request header too large"},
	{codeQueryParams, 800013, 400, "Too many query parameters"},
	{codeQueryParamLen, 800014, 400, "Query or form parameter too long"},
	{codeBodySize, 800020, 413, "Request body too large"},
	{codeSyntax, 800021, 400, "Body does not match its Content-Type"},
	{codeJSONDepth, 800030, 400, "JSON nested too deeply"},
	{codeJSONKeys, 800031, 400, "Too many keys in a JSON object"},
	{codeJSONArrayLen, 800032, 400, "JSON array too long"},
	{codeJSONStringLen, 800033, 400, "JSON string too long"},
	{codeJSONDupKey, 800034, 400, "Duplicate key in a JSON object"},
	{codeJSONUTF8, 800035, 400, "Invalid UTF-8 in JSON"},
	{codeXMLDoctype, 800040, 400, "XML DOCTYPE / entity declaration (XXE)"},
	{codeXMLDepth, 800041, 400, "XML nested too deeply"},
	{codeXMLElements, 800042, 400, "Too many XML elements"},
	{codeXMLAttrs, 800043, 400, "Too many XML attributes"},
	{codeFormFields, 800050, 400, "Too many form fields"},
	{codeMultipartParts, 800051, 400, "Too many multipart parts"},
	{codeMultipartFiles, 800052, 400, "Too many uploaded files"},
	{codeAllowMethod, 800060, 405, "Method not allowed for this path"},
	{codeAllowContentType, 800061, 415, "Content type not allowed for this path"},
	{codeOpenAPIPath, 800070, 404, "Path not in the OpenAPI spec"},
	{codeOpenAPIMethod, 800071, 405, "Method not in the OpenAPI spec"},
	{codeOpenAPIParam, 800072, 400, "Parameter violates the OpenAPI spec"},
	{codeOpenAPIBody, 800073, 400, "Body violates the OpenAPI spec"},
	{codeOpenAPIContentType, 800074, 415, "Content type not in the OpenAPI spec"},
	{codeOpenAPIError, 800075, 400, "OpenAPI validation unavailable"},
}

var apiViolations = func() map[string]APIViolationInfo {
	m := make(map[string]APIViolationInfo, len(apiViolationList))
	for _, v := range apiViolationList {
		m[v.Code] = v
	}
	return m
}()

// APIViolations lists every violation kind (for the UI legend and the rule reference)
func APIViolations() []APIViolationInfo { return append([]APIViolationInfo(nil), apiViolationList...) }

// APIViolationStatus returns the HTTP status used for a violation code (400 for unknown codes)
func APIViolationStatus(code string) int {
	if vi, ok := apiViolations[code]; ok {
		return vi.Status
	}
	return http.StatusBadRequest
}

// IsAPIRuleID reports pseudo rule IDs produced by API protection
func IsAPIRuleID(id int) bool { return id >= 800010 && id < 800100 }

type bodyType int

const (
	kindNone bodyType = iota
	kindOther
	kindJSON
	kindXML
	kindForm
	kindMultipart
)

// bodyKind classifies a Content-Type header value
func bodyKind(ct string) (bodyType, map[string]string) {
	if strings.TrimSpace(ct) == "" {
		return kindNone, nil
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil && mt == "" {
		return kindOther, nil
	}
	mt = strings.ToLower(mt)
	switch {
	case mt == "application/json" || mt == "text/json" || strings.HasSuffix(mt, "+json"):
		return kindJSON, params
	case mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml"):
		return kindXML, params
	case mt == "application/x-www-form-urlencoded":
		return kindForm, params
	case strings.HasPrefix(mt, "multipart/"):
		return kindMultipart, params
	}
	return kindOther, params
}

type compiledAllow struct {
	path    string // lower case
	raw     bool   // trailing "*": plain string prefix
	methods map[string]bool
	types   []string // lower case, "type/sub" or "type/*"
}

func (a *compiledAllow) matches(p string) bool {
	if !strings.HasPrefix(p, a.path) {
		return false
	}
	if a.raw || len(p) == len(a.path) || strings.HasSuffix(a.path, "/") {
		return true
	}
	return p[len(a.path)] == '/'
}

func compileAllow(rules []APIAllowRule) []compiledAllow {
	var out []compiledAllow
	for _, r := range rules {
		c := compiledAllow{path: strings.ToLower(r.Path)}
		if strings.HasSuffix(c.path, "*") {
			c.raw = true
			c.path = strings.TrimSuffix(c.path, "*")
		}
		if len(r.Methods) > 0 {
			c.methods = map[string]bool{}
			for _, m := range r.Methods {
				c.methods[strings.ToUpper(strings.TrimSpace(m))] = true
			}
		}
		for _, t := range r.ContentTypes {
			c.types = append(c.types, strings.ToLower(strings.TrimSpace(t)))
		}
		out = append(out, c)
	}
	return out
}

func typeAllowed(types []string, mt string) bool {
	for _, t := range types {
		if t == mt || strings.HasSuffix(t, "/*") && strings.HasPrefix(mt, t[:len(t)-1]) {
			return true
		}
	}
	return false
}

// Guard is the compiled API protection of one endpoint
type Guard struct {
	cfg    APIConfig
	lim    APILimits // effective, 0 = unlimited
	block  bool
	allow  []compiledAllow
	oa     *OpenAPIRuntime
	oaCfg  OpenAPIConfig
	oaErr  string
	events *eventStore
}

// NewGuard compiles a merged API config (see MergeAPI). nil / off returns (nil, nil). An invalid
// config returns an error; a spec that fails to compile does not (the guard fails open or closed
// as configured, see OpenAPIConfig.BlockUnknown) so a bad spec can never prevent the proxy from loading.
func (m *Manager) NewGuard(c *APIConfig) (*Guard, error) {
	if c == nil {
		return nil, nil
	}
	mode := strings.ToLower(strings.TrimSpace(c.Mode))
	if mode != APIModeLog && mode != APIModeBlock {
		return nil, nil
	}
	if err := c.Limits.Validate(); err != nil {
		return nil, err
	}
	if len(c.AllowList) > MaxAPIAllowRules {
		return nil, errTooManyAllow
	}
	for i := range c.AllowList {
		if err := c.AllowList[i].Validate(); err != nil {
			return nil, err
		}
	}
	g := &Guard{cfg: *c, lim: c.Limits.Effective(), block: mode == APIModeBlock, events: m.events}
	g.allow = compileAllow(c.AllowList)
	if c.OpenAPI != nil && strings.TrimSpace(c.OpenAPI.Spec) != "" {
		g.oaCfg = *c.OpenAPI
		rt, err := CompileOpenAPI(c.OpenAPI.Spec)
		if err != nil {
			g.oaErr = err.Error()
		} else {
			g.oa = rt
		}
	}
	return g, nil
}

// SpecError returns why the OpenAPI spec could not be used, or "" (for the coverage table)
func (g *Guard) SpecError() string {
	if g == nil {
		return ""
	}
	return g.oaErr
}

// Mode returns log or block
func (g *Guard) Mode() string {
	if g.block {
		return APIModeBlock
	}
	return APIModeLog
}

func newTxID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var errTooManyAllow = errors.New("too many allow-list entries")

func itoa64(i int64) string { return strconv.FormatInt(i, 10) }

func over(v, limit int) bool { return limit > 0 && v > limit }

// Inspect checks the request. It returns true if the request was blocked and the response has
// been written. The body is replayed untouched when the request is allowed (or only logged).
func (g *Guard) Inspect(w http.ResponseWriter, r *http.Request, info RequestInfo) (blocked bool) {
	if g == nil || shouldBypass(r) {
		return false
	}
	defer func() {
		if rec := recover(); rec != nil {
			blocked = false // fail open
		}
	}()
	v := g.check(r)
	if v == nil {
		return false
	}
	vi, ok := apiViolations[v.Code]
	if !ok {
		vi = APIViolationInfo{Code: v.Code, ID: 800099, Status: 400, Title: "API protection"}
	}
	txid := newTxID()
	action, mode := "detected", ModeDetectionOnly
	if g.block {
		action, mode = "blocked", ModeBlock
	}
	ev := Event{
		Time:          time.Now(),
		TransactionID: txid,
		Endpoint:      info.Endpoint,
		ClientIP:      info.ClientIP,
		Method:        r.Method,
		Host:          r.Host,
		Path:          truncate(r.URL.Path, 512),
		URI:           truncate(r.URL.RequestURI(), 512),
		Action:        action,
		WouldBlock:    true,
		Mode:          mode,
		Source:        info.Source,
		Kind:          EventKindAPI,
		Violation:     v.Code,
		Rules:         []RuleHit{{ID: vi.ID, Message: "API protection: " + vi.Title, Severity: "WARNING", Data: cleanMsg(v.Detail)}},
	}
	g.events.add(ev)
	if info.OnEvent != nil {
		info.OnEvent(ev)
	}
	if !g.block {
		return false
	}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Request-Id", txid)
	if vi.Status == http.StatusMethodNotAllowed {
		if allow := g.allowedMethodsFor(r); allow != "" {
			h.Set("Allow", allow)
		}
	}
	if vi.Status == http.StatusRequestEntityTooLarge {
		h.Set("Connection", "close")
	}
	w.WriteHeader(vi.Status)
	io.WriteString(w, http.StatusText(vi.Status)+" (request ID "+txid+")\n")
	return true
}

func (g *Guard) allowedMethodsFor(r *http.Request) string {
	for _, rule := range g.matchingRules(r) {
		if len(rule.methods) > 0 {
			var ms []string
			for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
				if rule.methods[m] {
					ms = append(ms, m)
				}
			}
			return strings.Join(ms, ", ")
		}
	}
	return ""
}

// matchingRules returns, for the request path and its cleaned form, the most specific
// (longest prefix, later layers win ties) rule of each.
func (g *Guard) matchingRules(r *http.Request) []*compiledAllow {
	if len(g.allow) == 0 {
		return nil
	}
	p := strings.ToLower(r.URL.Path)
	cands := []string{p}
	if c := pathpkg.Clean(p); c != p && c != "." {
		cands = append(cands, c)
		if strings.HasSuffix(p, "/") && c != "/" {
			cands = append(cands, c+"/")
		}
	}
	var out []*compiledAllow
	for _, cp := range cands {
		var best *compiledAllow
		for i := range g.allow {
			a := &g.allow[i]
			if a.matches(cp) && (best == nil || len(a.path) >= len(best.path)) {
				best = a
			}
		}
		if best != nil {
			out = append(out, best)
		}
	}
	return out
}

// check returns the first violation of the request, or nil
func (g *Guard) check(r *http.Request) *violation {
	lim := g.lim

	// URL, headers, query string
	if lim.URLMaxLen > 0 {
		uri := r.RequestURI
		if uri == "" {
			uri = r.URL.RequestURI()
		}
		if len(uri) > lim.URLMaxLen {
			return &violation{codeURLLen, "request target longer than " + itoa(lim.URLMaxLen) + " bytes"}
		}
	}
	if lim.HeaderMaxCount > 0 || lim.HeaderMaxSize > 0 {
		n := 0
		for k, vs := range r.Header {
			for _, v := range vs {
				n++
				if lim.HeaderMaxSize > 0 && len(k)+len(v) > lim.HeaderMaxSize {
					return &violation{codeHeaderSize, "a header is larger than " + itoa(lim.HeaderMaxSize) + " bytes"}
				}
			}
		}
		if over(n, lim.HeaderMaxCount) {
			return &violation{codeHeaderCount, "more than " + itoa(lim.HeaderMaxCount) + " request headers"}
		}
	}
	if r.URL.RawQuery != "" {
		if v := checkParams(r.URL.RawQuery, lim.QueryMaxParams, lim.QueryMaxParamLen, codeQueryParams, codeQueryParamLen, "query parameters"); v != nil {
			return v
		}
	}

	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	ctHeader := r.Header.Get("Content-Type")
	kind, params := bodyKind(ctHeader)

	// Allow-list per path prefix
	for _, rule := range g.matchingRules(r) {
		if len(rule.methods) > 0 && !rule.methods[strings.ToUpper(r.Method)] {
			return &violation{codeAllowMethod, "method " + truncate(r.Method, 16) + " is not allowed for this path"}
		}
		if len(rule.types) > 0 && hasBody {
			mt := ""
			if m, _, err := mime.ParseMediaType(ctHeader); err == nil || m != "" {
				mt = strings.ToLower(m)
			}
			if !typeAllowed(rule.types, mt) {
				return &violation{codeAllowContentType, "content type " + truncate(mt, 60) + " is not allowed for this path"}
			}
		}
	}

	// Body
	var body []byte
	if hasBody {
		if r.ContentLength > lim.MaxBodyBytes {
			return &violation{codeBodySize, "Content-Length " + itoa64(r.ContentLength) + " exceeds " + itoa64(lim.MaxBodyBytes)}
		}
		oaBody := g.oa != nil && !g.oaCfg.SkipBody && kind == kindJSON
		if (kind != kindNone && kind != kindOther) || r.ContentLength < 0 || oaBody {
			buf, tooBig := g.bufferBody(r)
			if tooBig {
				return &violation{codeBodySize, "body exceeds " + itoa64(lim.MaxBodyBytes) + " bytes"}
			}
			body = buf
			if v, syntax := g.checkBody(kind, params, buf); v != nil {
				if !(syntax && lim.AllowContentTypeMismatch) {
					return v
				}
			}
		}
	}

	// OpenAPI
	if g.oaErr != "" {
		// the error is surfaced through SpecError / the coverage table, not per request
		if g.oaCfg.BlockUnknown {
			return &violation{codeOpenAPIError, "OpenAPI spec unusable, blocking as configured"}
		}
	} else if g.oa != nil {
		res := g.oa.Validate(r, body, &g.oaCfg)
		if !res.OK {
			if res.Err && !g.oaCfg.BlockUnknown {
				return nil // internal validator failure: fail open
			}
			return &violation{res.Code, res.Detail}
		}
	}
	return nil
}

// bufferBody reads at most limit+1 bytes and installs a replaying body on the request. tooBig is
// true when the body is larger than the limit (the request then still replays everything).
func (g *Guard) bufferBody(r *http.Request) (buf []byte, tooBig bool) {
	limit := g.lim.MaxBodyBytes
	orig := r.Body
	size := int64(512)
	if r.ContentLength > 0 && r.ContentLength < limit {
		size = r.ContentLength + 1
	}
	b := bytes.NewBuffer(make([]byte, 0, size))
	_, err := io.Copy(b, io.LimitReader(orig, limit+1))
	buf = b.Bytes()
	switch {
	case err != nil:
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf), errReader{err}), closer: orig}
		return nil, false
	case int64(len(buf)) > limit:
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf), orig), closer: orig}
		return nil, true
	}
	r.Body = &replayBody{Reader: bytes.NewReader(buf), closer: orig}
	return buf, false
}

func (g *Guard) checkBody(kind bodyType, params map[string]string, b []byte) (*violation, bool) {
	if len(b) == 0 {
		return nil, false
	}
	switch kind {
	case kindJSON:
		v := checkJSON(b, g.lim)
		return v, v != nil && v.Code == codeSyntax
	case kindXML:
		return checkXML(b, g.lim)
	case kindForm:
		return checkURLEncoded(b, g.lim), false
	case kindMultipart:
		return checkMultipart(b, params["boundary"], g.lim)
	}
	return nil, false
}
