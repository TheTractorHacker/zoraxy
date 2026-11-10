package ruleset

import (
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

/*
	fields.go

	The typed field registry and the request view (Env) the fields are read from.

	Adding a field: add a FieldDef to fieldDefs (name, type, doc, example), a constant to the fieldID
	list, and a case to Env.value / Env.exists. Nothing else: the parser, the printer, the JSON tree
	and the meta API (for the visual builder) are driven by this table.
*/

// Type is the static type of a field
type Type string

const (
	TString Type = "string"
	TInt    Type = "int"
	TBool   Type = "bool"
	TIP     Type = "ip"
)

type fieldID int

const (
	fHost fieldID = iota + 1
	fPath
	fRawPath
	fQuery
	fMethod
	fScheme
	fVersion
	fUserAgent
	fReferer
	fContentType
	fHeader
	fCookie
	fQueryArg
	fIPSrc
	fIPCountry
	fIPPrivate
	fTLSVersion
	fTLSSNI
	fReqSize
)

// FieldDef describes one field
type FieldDef struct {
	Name    string `json:"name"`
	Type    Type   `json:"type"`
	Indexed bool   `json:"indexed,omitempty"` // needs a key: http.header["name"]
	Country bool   `json:"country,omitempty"` // values are ISO 3166 alpha-2 codes
	Doc     string `json:"doc"`
	Example string `json:"example"`
	id      fieldID
}

var fieldDefs = []*FieldDef{
	{Name: "http.host", Type: TString, id: fHost, Doc: "Host header, lower case, without port.", Example: `http.host == "app.example.com"`},
	{Name: "http.path", Type: TString, id: fPath, Doc: "Normalised path: percent-decoded once, dot segments and duplicate slashes resolved, backslashes read as slashes, ;params and everything after a NUL removed, no trailing slash (except /). Case sensitive.", Example: `http.path starts_with "/admin"`},
	{Name: "http.raw_path", Type: TString, id: fRawPath, Doc: "Path exactly as received (still percent-encoded, not normalised).", Example: `http.raw_path contains "%2e"`},
	{Name: "http.query", Type: TString, id: fQuery, Doc: "Raw query string without the leading ?.", Example: `http.query contains "debug=1"`},
	{Name: "http.method", Type: TString, id: fMethod, Doc: "Request method, as received (upper case for every real client).", Example: `http.method in ["POST", "PUT", "DELETE"]`},
	{Name: "http.scheme", Type: TString, id: fScheme, Doc: `"https" when the connection to Zoraxy used TLS, else "http". Forwarded-proto headers are never trusted.`, Example: `http.scheme == "http"`},
	{Name: "http.version", Type: TString, id: fVersion, Doc: `Protocol of the client connection: "HTTP/1.0", "HTTP/1.1", "HTTP/2.0" or "HTTP/3.0".`, Example: `http.version == "HTTP/1.0"`},
	{Name: "http.user_agent", Type: TString, id: fUserAgent, Doc: "User-Agent header (several headers are joined with \", \").", Example: `lower(http.user_agent) contains "sqlmap"`},
	{Name: "http.referer", Type: TString, id: fReferer, Doc: "Referer header.", Example: `http.referer not starts_with "https://example.com/"`},
	{Name: "http.content_type", Type: TString, id: fContentType, Doc: "Content-Type header, as sent (with parameters).", Example: `lower(http.content_type) starts_with "application/json"`},
	{Name: "http.header", Type: TString, Indexed: true, id: fHeader, Doc: "Request header by name. The name is case-insensitive; several headers of the same name are joined with \", \". Use exists to test presence.", Example: `http.header["x-api-key"] exists`},
	{Name: "http.cookie", Type: TString, Indexed: true, id: fCookie, Doc: "Request cookie by name. The name is case-sensitive; the first cookie of that name wins.", Example: `http.cookie["session"] exists`},
	{Name: "http.query_arg", Type: TString, Indexed: true, id: fQueryArg, Doc: "Query string parameter by name (decoded, case-sensitive, first value).", Example: `http.query_arg["id"] matches "^[0-9]+$"`},
	{Name: "ip.src", Type: TIP, id: fIPSrc, Doc: "Client address after trusted-proxy resolution (never a spoofable forwarded header from an untrusted peer).", Example: `ip.src in $office`},
	{Name: "ip.country", Type: TString, Country: true, id: fIPCountry, Doc: `ISO 3166 alpha-2 country of ip.src from the GeoIP database, upper case; "XX" when unknown (private addresses, no database).`, Example: `ip.country in ["CN", "RU"]`},
	{Name: "ip.is_private", Type: TBool, id: fIPPrivate, Doc: "ip.src is loopback, private (RFC 1918 / ULA), link-local, unspecified or carrier-grade NAT.", Example: `not ip.is_private`},
	{Name: "tls.version", Type: TString, id: fTLSVersion, Doc: `TLS version of the client connection: "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", or "" on plain HTTP.`, Example: `tls.version in ["TLSv1.0", "TLSv1.1"]`},
	{Name: "tls.sni", Type: TString, id: fTLSSNI, Doc: `Server name the client sent in the TLS handshake (lower case), "" on plain HTTP or without SNI.`, Example: `tls.sni == ""`},
	{Name: "req.size", Type: TInt, id: fReqSize, Doc: "Declared body size in bytes (Content-Length); -1 when unknown (chunked), so a size limit does not apply to chunked bodies.", Example: `req.size > 1048576`},
}

var fieldByName = func() map[string]*FieldDef {
	m := map[string]*FieldDef{}
	for _, f := range fieldDefs {
		m[f.Name] = f
	}
	return m
}()

// unavailableFields are names users may expect but that this build cannot provide
var unavailableFields = map[string]string{
	"ip.asn":  "ip.asn is not available: the bundled GeoIP database only maps addresses to countries, it has no ASN data",
	"ip.city": "ip.city is not available: the bundled GeoIP database only maps addresses to countries",
}

// Fields lists the fields for the builder UI
func Fields() []FieldDef {
	out := make([]FieldDef, len(fieldDefs))
	for i, f := range fieldDefs {
		out[i] = *f
	}
	return out
}

// maxFieldBytes caps every string a condition looks at. Longer values are cut (a documented limit, see the
// security model in DEVELOPMENT.md): it bounds the cost of a condition independent of what the client sends.
const maxFieldBytes = 32 << 10

// Env is the request as the rules see it. Values are computed on first use and cached for the request.
type Env struct {
	R        *http.Request
	ClientIP string
	// Country resolves a client address to an ISO code (nil or "" = unknown)
	Country func(ip string) string

	pathDone, hostDone, cookiesDone, queryDone, addrDone, countryDone bool
	path, host, country                                               string
	cookies                                                           []*http.Cookie
	query                                                             url.Values
	addr                                                              netip.Addr
}

func capStr(s string) string {
	if len(s) > maxFieldBytes {
		return s[:maxFieldBytes]
	}
	return s
}

func (e *Env) header(name string) (string, bool) {
	canon := http.CanonicalHeaderKey(name)
	if canon == "Host" {
		return e.R.Host, e.R.Host != ""
	}
	vs := e.R.Header[canon]
	switch len(vs) {
	case 0:
		return "", false
	case 1:
		return vs[0], true
	}
	return strings.Join(vs, ", "), true
}

func (e *Env) hostLower() string {
	if !e.hostDone {
		h := e.R.Host
		if strings.HasPrefix(h, "[") {
			if i := strings.IndexByte(h, ']'); i > 0 {
				h = h[:i+1]
			}
		} else if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
			h = h[:i]
		}
		e.host = strings.TrimSuffix(strings.ToLower(h), ".")
		e.hostDone = true
	}
	return e.host
}

func (e *Env) normPath() string {
	if !e.pathDone {
		e.path = NormalizePath(e.R)
		e.pathDone = true
	}
	return e.path
}

func (e *Env) cookie(name string) (string, bool) {
	if !e.cookiesDone {
		e.cookies = e.R.Cookies()
		e.cookiesDone = true
	}
	for _, c := range e.cookies {
		if c.Name == name {
			return c.Value, true
		}
	}
	return "", false
}

func (e *Env) queryArg(name string) (string, bool) {
	if !e.queryDone {
		e.query, _ = url.ParseQuery(e.R.URL.RawQuery) //a partial result is fine: bad pairs are skipped
		e.queryDone = true
	}
	vs, ok := e.query[name]
	if !ok || len(vs) == 0 {
		return "", ok
	}
	return vs[0], true
}

// Addr is the client address (zero when it does not parse)
func (e *Env) Addr() netip.Addr {
	if !e.addrDone {
		e.addrDone = true
		ip := e.ClientIP
		if h, _, err := netSplit(ip); err == nil {
			ip = h
		}
		if a, err := netip.ParseAddr(strings.Trim(ip, "[]")); err == nil {
			e.addr = a.Unmap().WithZone("")
		}
	}
	return e.addr
}

func (e *Env) countryCode() string {
	if !e.countryDone {
		e.countryDone = true
		if e.Country != nil && e.ClientIP != "" {
			e.country = strings.ToUpper(strings.TrimSpace(e.Country(e.ClientIP)))
		}
		if e.country == "" {
			e.country = "XX"
		}
	}
	return e.country
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isPrivateAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || cgnat.Contains(a)
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLSv1.0"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	case 0x0304:
		return "TLSv1.3"
	}
	return "TLS-0x" + strconv.FormatUint(uint64(v), 16)
}

// strValue reads a string field. ok is false when an indexed key is absent.
func (e *Env) strValue(f *FieldDef, key string) (string, bool) {
	r := e.R
	switch f.id {
	case fHost:
		return e.hostLower(), true
	case fPath:
		return capStr(e.normPath()), true
	case fRawPath:
		return capStr(r.URL.EscapedPath()), true
	case fQuery:
		return capStr(r.URL.RawQuery), true
	case fMethod:
		return r.Method, true
	case fScheme:
		if r.TLS != nil {
			return "https", true
		}
		return "http", true
	case fVersion:
		return r.Proto, true
	case fUserAgent:
		v, ok := e.header("User-Agent")
		return capStr(v), ok
	case fReferer:
		v, ok := e.header("Referer")
		return capStr(v), ok
	case fContentType:
		v, ok := e.header("Content-Type")
		return capStr(v), ok
	case fHeader:
		v, ok := e.header(key)
		return capStr(v), ok
	case fCookie:
		v, ok := e.cookie(key)
		return capStr(v), ok
	case fQueryArg:
		v, ok := e.queryArg(key)
		return capStr(v), ok
	case fIPCountry:
		return e.countryCode(), true
	case fTLSVersion:
		if r.TLS == nil {
			return "", true
		}
		return tlsVersionName(r.TLS.Version), true
	case fTLSSNI:
		if r.TLS == nil {
			return "", true
		}
		return strings.ToLower(r.TLS.ServerName), true
	}
	return "", false
}

func (e *Env) intValue(f *FieldDef) int64 {
	if f.id == fReqSize {
		return e.R.ContentLength
	}
	return 0
}

func (e *Env) boolValue(f *FieldDef) bool {
	if f.id == fIPPrivate {
		return isPrivateAddr(e.Addr())
	}
	return false
}

// NormalizePath is the reading of the request path that http.path exposes. It folds the encodings a
// backend might read differently, so a rule on /admin cannot be dodged with //admin, /./admin, /x/../admin,
// /admin;x, /admin%00.png or \admin.
func NormalizePath(r *http.Request) string {
	p := ""
	if r.URL != nil {
		p = r.URL.Path
	}
	return cleanPath(p)
}
