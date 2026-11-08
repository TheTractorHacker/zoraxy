package forward

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/pathmatch"
)

/*
	outpost.go

	Authentik proxy outpost support for forward auth:
	  - reverse proxy of /outpost.goauthentik.io/ on the protected host to the outpost
	  - construction of the sign-in start URL (with a safe, server-built "rd" parameter)
*/

// validateHTTPURL checks that s is an absolute http(s) URL with a host.
func validateHTTPURL(s string) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("missing host")
	}
	return nil
}

// initOutpostProxy (re)builds the reverse proxy for the configured OutpostURL.
func (ar *AuthRouter) initOutpostProxy() {
	ar.outpostMu.Lock()
	defer ar.outpostMu.Unlock()
	ar.outpostProxy = nil
	ar.outpostBase = nil

	base := strings.TrimRight(strings.TrimSpace(ar.options.OutpostURL), "/")
	if base == "" || validateHTTPURL(base) != nil {
		return
	}
	u, _ := url.Parse(base)
	ar.outpostBase = u
	ar.outpostProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			inHost := pr.In.Host
			sch := scheme(pr.In)
			pr.Out.URL.Scheme = u.Scheme
			pr.Out.URL.Host = u.Host
			// Preserve any path prefix of the outpost base URL.
			pr.Out.URL.Path = strings.TrimRight(u.Path, "/") + path.Clean(pr.In.URL.Path)
			pr.Out.URL.RawPath = ""
			// Authentik selects the application by Host header, so the original host is kept.
			pr.Out.Host = inHost
			// Never trust client supplied forwarding headers towards the outpost.
			scrubForwardingHeaders(pr.Out)
			pr.Out.Header.Set(HeaderXForwardedHost, inHost)
			pr.Out.Header.Set(HeaderXForwardedProto, sch)
			pr.Out.Header.Set(HeaderXOriginalURL, sch+"://"+inHost+pr.In.URL.RequestURI())
			if host, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
				pr.Out.Header.Set(HeaderXForwardedFor, host)
			}
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: AuthRequestTimeout,
			IdleConnTimeout:       60 * time.Second,
			MaxIdleConns:          16,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if ar.options.Logger != nil {
				ar.options.Logger.PrintAndLog(LogTitle, "Outpost proxy error", err)
			}
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
	}
}

// handleOutpostPath proxies requests under /outpost.goauthentik.io to the outpost. It returns true
// when the request was handled (the response has been written).
func (ar *AuthRouter) handleOutpostPath(w http.ResponseWriter, r *http.Request) bool {
	ar.outpostMu.RLock()
	proxy := ar.outpostProxy
	ar.outpostMu.RUnlock()
	if proxy == nil {
		return false
	}
	// Hardened boundary / traversal aware match. A request like
	// /outpost.goauthentik.io/../admin resolves outside the prefix and is therefore authenticated.
	if !pathmatch.RequestPathWithinPrefix(r.RequestURI, OutpostPathPrefix) {
		return false
	}
	clean := path.Clean(r.URL.Path)
	if clean != OutpostPathPrefix && !strings.HasPrefix(clean, OutpostPathPrefix+"/") {
		return false
	}
	proxy.ServeHTTP(w, r)
	return true
}

// wantsHTMLNavigation reports whether the request looks like a browser page navigation, for which
// a sign-in redirect is appropriate. API/XHR callers get the plain 401.
func wantsHTMLNavigation(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// originalURL returns the externally visible URL of the request, built only from Zoraxy's own view
// of it (never from a client supplied header or query value).
func originalURL(r *http.Request) string {
	return scheme(r) + "://" + r.Host + r.URL.RequestURI()
}

// startURL builds the sign-in URL that the browser is redirected to. The "rd" value is the
// original URL computed by Zoraxy; no caller supplied redirect target is ever reflected.
func (ar *AuthRouter) startURL(r *http.Request) (string, bool) {
	ar.outpostMu.RLock()
	base := ar.outpostBase
	ar.outpostMu.RUnlock()
	if base == nil {
		return "", false
	}
	rd := url.QueryEscape(originalURL(r))
	switch ar.options.StartRedirect {
	case StartRedirectLocal:
		return OutpostPathPrefix + "/start?rd=" + rd, true
	case StartRedirectOutpost:
		return strings.TrimRight(base.String(), "/") + OutpostPathPrefix + "/start?rd=" + rd, true
	}
	return "", false
}
