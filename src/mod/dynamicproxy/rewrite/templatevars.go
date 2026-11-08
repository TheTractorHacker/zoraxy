package rewrite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

/*
	templatevars.go

	{{variable}} expansion for header values, redirect targets, static responses and
	error pages (upstream #370, #826, #877).

	Variables: {{host}} {{client_ip}} {{request_id}} {{rule_name}} {{external_ip}}
	Unknown names are left untouched. Every substituted value is sanitised: control
	characters (CR, LF, NUL ...) are removed and the value is capped, so a value taken from
	the request can never inject a header, split a response or smuggle a second Location.
	Only header VALUES are expanded, never header names.
*/

type ctxKey struct{}

// RequestVars is the per request context shared by all variable users
type RequestVars struct {
	RequestID string
	RuleName  string
	ClientIP  string
}

const maxVarLen = 256

// ExternalIPProvider returns the server's public IP (empty if unknown or the public IP check is disabled)
var externalIP atomic.Pointer[func() string]

// SetExternalIPProvider installs the {{external_ip}} source. nil removes it.
func SetExternalIPProvider(f func() string) {
	if f == nil {
		externalIP.Store(nil)
		return
	}
	externalIP.Store(&f)
}

// NewRequestID returns a random 16 hex character request identifier
func NewRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// SanitizeRequestID accepts a client supplied request id only if it is short and made of safe characters
func SanitizeRequestID(s string) string {
	if s == "" || len(s) > 64 {
		return ""
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return ""
		}
	}
	return s
}

// WithRequestVars returns a copy of r carrying v
func WithRequestVars(r *http.Request, v *RequestVars) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, v))
}

// GetRequestVars returns the request vars stored by WithRequestVars, or nil
func GetRequestVars(r *http.Request) *RequestVars {
	v, _ := r.Context().Value(ctxKey{}).(*RequestVars)
	return v
}

// SanitizeValue removes control characters and caps the length
func SanitizeValue(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c < 0x20 || c == 0x7f || c == 0x85 || c == 0x2028 || c == 0x2029 {
			continue
		}
		b.WriteRune(c)
		if b.Len() >= maxVarLen {
			break
		}
	}
	return b.String()
}

func varValue(r *http.Request, name string) (string, bool) {
	rv := GetRequestVars(r)
	switch name {
	case "host":
		return r.Host, true
	case "client_ip":
		if rv != nil && rv.ClientIP != "" {
			return rv.ClientIP, true
		}
		if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return h, true
		}
		return r.RemoteAddr, true
	case "request_id":
		if rv != nil && rv.RequestID != "" {
			return rv.RequestID, true
		}
		if id := SanitizeRequestID(r.Header.Get("X-Request-Id")); id != "" {
			return id, true
		}
		return NewRequestID(), true
	case "rule_name":
		if rv != nil {
			return rv.RuleName, true
		}
		return "", true
	case "external_ip":
		if p := externalIP.Load(); p != nil {
			return (*p)(), true
		}
		return "", true
	}
	return "", false
}

// ContainsTemplateVars is a cheap pre check
func ContainsTemplateVars(s string) bool {
	return strings.Contains(s, "{{")
}

// ExpandTemplateVars expands the {{variables}} of s using the request r
func ExpandTemplateVars(r *http.Request, s string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	var out strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			break
		}
		name := strings.TrimSpace(s[i+2 : i+j])
		out.WriteString(s[:i])
		if v, ok := varValue(r, name); ok {
			out.WriteString(SanitizeValue(v))
		} else {
			out.WriteString(s[i : i+j+2])
		}
		s = s[i+j+2:]
	}
	out.WriteString(s)
	return out.String()
}
