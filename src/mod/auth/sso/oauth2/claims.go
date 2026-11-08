package oauth2

import (
	"fmt"
	"net/http"
	"strings"
)

/*
	claims.go

	Claim helpers: group allow-list, claim -> upstream header mapping, and safe redirect handling.
*/

// DefaultGroupsClaim is the claim consulted for the group allow-list when none is configured.
const DefaultGroupsClaim = "groups"

// HeaderMapping maps one claim to one upstream request header.
type HeaderMapping struct {
	Header string
	Claim  string
}

// headers that may never be set from a claim: they would let a claim value alter routing,
// framing or credentials of the upstream request.
var forbiddenMappedHeaders = map[string]bool{
	"host": true, "content-length": true, "content-type": true, "transfer-encoding": true,
	"connection": true, "upgrade": true, "te": true, "trailer": true, "keep-alive": true,
	"cookie": true, "authorization": true, "proxy-authorization": true, "forwarded": true,
	"x-forwarded-for": true, "x-forwarded-host": true, "x-forwarded-proto": true,
	"x-forwarded-uri": true, "x-real-ip": true, "x-original-url": true, "origin": true,
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// ParseHeaderMappings parses "Header=claim,Header2=claim2". Invalid entries are reported.
func ParseHeaderMappings(s string) ([]HeaderMapping, error) {
	var out []HeaderMapping
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx <= 0 || idx == len(part)-1 {
			return nil, fmt.Errorf("invalid mapping %q, expected Header=claim", part)
		}
		h := strings.TrimSpace(part[:idx])
		c := strings.TrimSpace(part[idx+1:])
		if !validHeaderName(h) {
			return nil, fmt.Errorf("invalid header name %q", h)
		}
		if forbiddenMappedHeaders[strings.ToLower(h)] {
			return nil, fmt.Errorf("header %q cannot be set from a claim", h)
		}
		out = append(out, HeaderMapping{Header: http.CanonicalHeaderKey(h), Claim: c})
	}
	return out, nil
}

// claimValue resolves a claim by name. A name containing dots is first tried literally (URL style
// claims such as https://example.com/roles) and then as a nested path (realm_access.roles).
// Path segments may themselves contain dots (Keycloak client ids: resource_access.my.app.roles):
// at every level the longest matching key wins.
func claimValue(claims map[string]any, name string) (any, bool) {
	if v, ok := claims[name]; ok {
		return v, true
	}
	if !strings.Contains(name, ".") {
		return nil, false
	}
	return resolveClaimPath(claims, strings.Split(name, "."))
}

func resolveClaimPath(cur map[string]any, parts []string) (any, bool) {
	for n := len(parts); n >= 1; n-- {
		v, ok := cur[strings.Join(parts[:n], ".")]
		if !ok {
			continue
		}
		if n == len(parts) {
			return v, true
		}
		if m, isMap := v.(map[string]any); isMap {
			if r, found := resolveClaimPath(m, parts[n:]); found {
				return r, true
			}
		}
	}
	return nil, false
}

// claimStrings flattens a claim into a list of strings (string, []string, []any of scalars).
func claimStrings(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		return t
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, claimStrings(e)...)
		}
		return out
	case bool, float64, int, int64:
		return []string{fmt.Sprint(t)}
	}
	return nil
}

// splitList splits a comma separated config value.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// groupsAllowed implements the group allow-list. An empty allow-list allows everybody.
func groupsAllowed(claims map[string]any, claimName string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	if claimName == "" {
		claimName = DefaultGroupsClaim
	}
	v, ok := claimValue(claims, claimName)
	if !ok {
		return false
	}
	have := claimStrings(v)
	for _, g := range have {
		for _, a := range allowed {
			if g == a {
				return true
			}
		}
	}
	return false
}

// sanitizeHeaderValue removes control characters so a claim can never break out of a header.
func sanitizeHeaderValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 && r != '\t' || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > 4096 {
		out = out[:4096]
	}
	return out
}

// applyHeaderMappings strips every mapped header from the request (so clients cannot inject them)
// and, when claims are available, sets them from the verified claims.
func applyHeaderMappings(r *http.Request, mappings []HeaderMapping, claims map[string]any) {
	for _, m := range mappings {
		r.Header.Del(m.Header)
	}
	for _, m := range mappings {
		v, ok := claimValue(claims, m.Claim)
		if !ok {
			continue
		}
		vals := claimStrings(v)
		if len(vals) == 0 {
			continue
		}
		r.Header.Set(m.Header, sanitizeHeaderValue(strings.Join(vals, ",")))
	}
}

// safeReturnPath reduces a request URI to a same-site relative path that is safe to redirect to.
// Anything that is not a plain absolute path (scheme-relative "//host", backslash tricks,
// absolute URLs, control characters) collapses to "/".
func safeReturnPath(uri string) string {
	if uri == "" || uri[0] != '/' {
		return "/"
	}
	if len(uri) > 1 && (uri[1] == '/' || uri[1] == '\\') {
		return "/"
	}
	for _, c := range uri {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	if strings.HasPrefix(uri, callbackPrefix) {
		return "/"
	}
	return uri
}
