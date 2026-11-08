package forward

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}

	return "http"
}

func headerCookieRedact(r *http.Request, names []string, exclude bool) {
	if len(names) == 0 {
		return
	}

	original := r.Cookies()

	if len(original) == 0 {
		return
	}

	var cookies []string

	for _, cookie := range original {
		if exclude && stringInSlice(cookie.Name, names) {
			continue
		} else if !exclude && !stringInSlice(cookie.Name, names) {
			continue
		}

		cookies = append(cookies, cookie.String())
	}

	value := strings.Join(cookies, "; ")

	r.Header.Set(HeaderCookie, value)

	return
}

func headerCopyExcluded(original, destination http.Header, excludedHeaders []string) {
	for key, values := range original {
		// We should never copy the headers in the below list.
		if stringInSliceFold(key, doNotCopyHeaders) {
			continue
		}

		if stringInSliceFold(key, excludedHeaders) {
			continue
		}

		destination[key] = append(destination[key], values...)
	}
}

func headerCopyIncluded(original, destination http.Header, includedHeaders []string, allIfEmpty bool) {
	if allIfEmpty && len(includedHeaders) == 0 {
		headerCopyAll(original, destination)
	} else {
		headerCopyIncludedExact(original, destination, includedHeaders)
	}
}

func headerCopyAll(original, destination http.Header) {
	for key, values := range original {
		// We should never copy the headers in the below list, even if they're in the list provided by a user.
		if stringInSliceFold(key, doNotCopyHeaders) {
			continue
		}

		destination[key] = append(destination[key], values...)
	}
}

func headerCopyIncludedExact(original, destination http.Header, keys []string) {
	for key, values := range original {
		// We should never copy the headers in the below list, even if they're in the list provided by a user.
		if stringInSliceFold(key, doNotCopyHeaders) {
			continue
		}

		if !headerNameMatches(key, keys) {
			continue
		}

		destination[key] = append(destination[key], values...)
	}
}

// headerNameMatches reports whether name matches one of the keys. A key ending in "*" is a
// case-insensitive prefix match (e.g. "X-authentik-meta-*"); anything else is an exact
// case-insensitive match.
func headerNameMatches(name string, keys []string) bool {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.HasSuffix(k, "*") {
			if hasPrefixFold(name, strings.TrimSuffix(k, "*")) {
				return true
			}
			continue
		}
		if strings.EqualFold(name, k) {
			return true
		}
	}
	return false
}

func hasPrefixFold(name, prefix string) bool {
	return prefix != "" && len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix)
}

// headerReplaceIncluded replaces the listed headers on destination with the values from original.
// Client supplied values of the listed headers are always removed first, so a client can never
// inject an identity header that the auth server did not set. Keys ending in "*" act as prefixes.
func headerReplaceIncluded(original, destination http.Header, keys []string) {
	for _, key := range keys {
		key = strings.TrimSpace(key)

		if key == "" || stringInSliceFold(key, doNotCopyHeaders) {
			continue
		}

		if strings.HasSuffix(key, "*") {
			prefix := strings.TrimSuffix(key, "*")
			for name := range destination {
				if hasPrefixFold(name, prefix) {
					delete(destination, name)
				}
			}
			for name, values := range original {
				if hasPrefixFold(name, prefix) {
					for _, value := range values {
						destination.Add(name, value)
					}
				}
			}
			continue
		}

		destination.Del(key)

		for _, value := range original.Values(key) {
			destination.Add(key, value)
		}
	}
}

func stringInSlice(needle string, haystack []string) bool {
	if len(haystack) == 0 {
		return false
	}

	for _, v := range haystack {
		if needle == v {
			return true
		}
	}

	return false
}

func stringInSliceFold(needle string, haystack []string) bool {
	if len(haystack) == 0 {
		return false
	}

	for _, v := range haystack {
		if strings.EqualFold(needle, v) {
			return true
		}
	}

	return false
}

func rSetIPHeader(r, req *http.Request, headers ...string) {
	if len(headers) == 0 {
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// We should never leave a client supplied value in these headers when the address cannot be determined.
		for _, header := range headers {
			req.Header.Del(header)
		}

		return
	}

	for _, header := range headers {
		req.Header.Set(header, ip.String())
	}
}

// scrubForwardingHeaders removes every client supplied forwarding/original-URL header from the
// auth subrequest so that only values computed by Zoraxy reach the auth server.
func scrubForwardingHeaders(req *http.Request) {
	for _, h := range []string{HeaderXForwardedProto, HeaderXForwardedHost, HeaderXForwardedURI,
		HeaderXForwardedFor, HeaderXForwardedMethod, HeaderXOriginalURL, HeaderXOriginalIP, HeaderXOriginalMethod} {
		req.Header.Del(h)
	}
}

func rSetXForwardedHeaders(r, req *http.Request) {
	rSetIPHeader(r, req, HeaderXForwardedFor)
	req.Header.Set(HeaderXForwardedMethod, r.Method)
	req.Header.Set(HeaderXForwardedProto, scheme(r))
	req.Header.Set(HeaderXForwardedHost, r.Host)
	req.Header.Set(HeaderXForwardedURI, r.URL.RequestURI())
}

func rSetXOriginalHeaders(r, req *http.Request) {
	// The X-Forwarded-For header has larger support, so we include both.
	rSetIPHeader(r, req, HeaderXOriginalIP, HeaderXForwardedFor)

	original := &url.URL{
		Scheme:   scheme(r),
		Host:     r.Host,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}

	req.Header.Set(HeaderXOriginalMethod, r.Method)
	req.Header.Set(HeaderXOriginalURL, original.String())
}

func rCopyBody(req, freq *http.Request) (err error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}

	if len(body) == 0 {
		return nil
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	freq.Body = io.NopCloser(bytes.NewReader(body))

	return nil
}

func cleanSplit(s string) []string {
	if s == "" {
		return nil
	}

	return strings.Split(s, ",")
}
