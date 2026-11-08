package pathmatch

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

/*
	pathmatch.go

	Shared request path matching for proxy path rules. Several rule types used to
	carry their own copy of this logic; they now share this one.
*/

// CleanRequestPath returns the decoded, lexically resolved path of a request
// target. The query string is dropped.
func CleanRequestPath(requestURI string) string {
	requestPath := requestURI
	if u, err := url.ParseRequestURI(requestURI); err == nil {
		requestPath = u.Path
	}
	return path.Clean("/" + requestPath)
}

func cleanPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return CleanRequestPath(prefix)
}

// RequestPathWithinPrefix reports whether requestURI falls within prefix, comparing resolved paths on segment boundaries. An empty or whitespace-only prefix never matches.
func RequestPathWithinPrefix(requestURI string, prefix string) bool {
	return requestPathWithinPrefix(requestURI, prefix, false)
}

// RequestPathWithinPrefixFold is RequestPathWithinPrefix with case-insensitive comparison.
func RequestPathWithinPrefixFold(requestURI string, prefix string) bool {
	return requestPathWithinPrefix(requestURI, prefix, true)
}

func requestPathWithinPrefix(requestURI string, prefix string, ignoreCase bool) bool {
	cleanedPrefix := cleanPrefix(prefix)
	if cleanedPrefix == "" {
		return false
	}
	requestPath := CleanRequestPath(requestURI)
	if ignoreCase {
		//Fold both sides so the segment boundary check below stays case-insensitive
		requestPath = strings.ToLower(requestPath)
		cleanedPrefix = strings.ToLower(cleanedPrefix)
	}
	return requestPath == cleanedPrefix || strings.HasPrefix(requestPath, cleanedPrefix+"/")
}

// PrefixIsRoot reports whether prefix resolves to the site root.
func PrefixIsRoot(prefix string) bool {
	return cleanPrefix(prefix) == "/"
}

// RequestTarget returns the raw request target for r.
func RequestTarget(r *http.Request) string {
	if r == nil {
		return "/"
	}
	if r.RequestURI != "" {
		return r.RequestURI
	}
	if r.URL != nil {
		return r.URL.RequestURI()
	}
	return "/"
}

// CanonicalPath returns the decoded and cleaned path of a request target if,
// and only if, the target is in canonical form. ok == false means "do not exempt".
func CanonicalPath(target string) (string, bool) {
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return "", false
	}
	p := u.Path
	if p == "" || p[0] != '/' {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x20 || c == 0x7f || c == '\\' || c == ';' || c == '%' {
			return "", false
		}
	}
	clean := path.Clean(p)
	trimmed := p
	if len(trimmed) > 1 {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	if clean != trimmed {
		//dot segments or duplicate slashes were present
		return "", false
	}
	return clean, true
}
