package dynamicproxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/metrics"
)

/*
	Automatic abuse banning glue ("fail2ban built in", see mod/abuse).

	abuseBegin runs at the top of the per-endpoint request handling (TLS and
	non-TLS path, and the default site). It
	  1. rejects clients that are already banned (one atomic load when the
	     feature is off, one map lookup when on), and
	  2. wraps the response writer so the final status of the request (and any
	     explicit event noted by the chain: WAF block, exploit, rate limit,
	     captcha failure, bot block) is fed to the detectors.
	The client IP is always the trusted-proxy aware one (GetClientIPForEndpoint),
	so spoofed X-Forwarded-For headers from untrusted peers cannot frame others.
*/

type abuseCtxKey struct{}

// abuseNote carries an explicit event kind set by the chain; first one wins
type abuseNote struct {
	kind atomic.Pointer[abuse.Kind]
}

// abuseNoteKind records why the request is being rejected. No-op when the
// feature is off (no note in the context).
func abuseNoteKind(r *http.Request, kind abuse.Kind) {
	if n, ok := r.Context().Value(abuseCtxKey{}).(*abuseNote); ok {
		n.kind.CompareAndSwap(nil, &kind)
	}
}

type abuseRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *abuseRecorder) WriteHeader(code int) {
	if !w.wrote && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *abuseRecorder) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

func (w *abuseRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *abuseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := h.Hijack()
	if err == nil && !w.wrote {
		w.status, w.wrote = http.StatusSwitchingProtocols, true
	}
	return conn, rw, err
}

func (w *abuseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func abuseScope(sep *ProxyEndpoint) string {
	if sep == nil {
		return ""
	}
	return sep.RootOrMatchingDomain
}

// abuseBegin returns handled=true if the request was rejected because the
// client is banned. Otherwise the returned done must be deferred.
func (router *Router) abuseBegin(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) (http.ResponseWriter, *http.Request, func(), bool) {
	ab := router.Option.Abuse
	if !ab.Active() {
		return w, r, noopDone, false
	}
	clientIP := router.GetClientIPForEndpoint(r, sep)
	scope := abuseScope(sep)
	if ban, banned := ab.IsBanned(clientIP, scope); banned {
		router.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "auto-ban")
		detail := ban.Reason
		if ban.Source != "" {
			detail = strings.TrimSpace(ban.Source + ": " + ban.Reason)
		}
		if ab.DropConnection() {
			router.logRequestDetail(r, false, 444, "auto-ban-dropped", r.Host, "", sep, detail)
			dropConnection(w)
			return w, r, noopDone, true
		}
		router.logRequestDetail(r, false, http.StatusForbidden, "auto-ban", r.Host, "", sep, detail)
		router.writeForbiddenPage(w, r, http.StatusForbidden, localizedPage(r, page_forbidden), false)
		return w, r, noopDone, true
	}

	note := &abuseNote{}
	r = r.WithContext(context.WithValue(r.Context(), abuseCtxKey{}, note))
	rec := &abuseRecorder{ResponseWriter: w}
	return rec, r, func() {
		kind := abuse.Kind("")
		if k := note.kind.Load(); k != nil {
			kind = *k
		} else if rec.wrote {
			switch rec.status {
			case http.StatusUnauthorized:
				kind = abuse.KindUnauthorized
			case http.StatusForbidden:
				kind = abuse.KindForbidden
			case http.StatusNotFound:
				kind = abuse.KindNotFound
			case http.StatusTooManyRequests:
				kind = abuse.KindRateLimited
			}
		}
		if kind == "" {
			return
		}
		if b := ab.Report(clientIP, scope, kind, scope); b != nil {
			router.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "auto-ban-created")
		}
	}, false
}

func noopDone() {}

// dropConnection closes the client connection without any HTTP response.
// HTTP/1.x: hijack and close. HTTP/2 (cannot hijack): abort the handler, which
// makes net/http reset the stream (RST_STREAM) without logging a stack trace.
func dropConnection(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.SetLinger(0) //RST instead of FIN: nothing for a scanner to keep the socket in TIME_WAIT
			}
			conn.Close()
			return
		}
	}
	if rc := http.NewResponseController(w); rc != nil {
		if conn, _, err := rc.Hijack(); err == nil {
			conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

// captchaVerifiedOK reports whether a /verify answer issued the session cookie
func captchaVerifiedOK(w http.ResponseWriter) bool {
	for _, c := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, captcha.CookieName+"=") {
			return true
		}
	}
	return false
}
