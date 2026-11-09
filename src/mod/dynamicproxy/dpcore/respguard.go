package dpcore

import (
	"net/http"
	"strings"
)

/*
	respguard.go

	The single hook of response inspection (outbound leak detection) in the
	proxy core. The implementation lives in the waf package, glued in by the
	dynamicproxy package; dpcore only knows this interface. When no guard is
	set (the default, WAF or response protection off) ProxyHTTP pays one nil check.
*/

// ResponseGuard inspects an upstream response before anything is sent to the client.
type ResponseGuard interface {
	// GuardResponse may delete headers of res and replace res.Body by a reader yielding the same
	// bytes. It returns a non zero status if the response must be replaced by a generic error page;
	// it has then already closed res.Body.
	GuardResponse(req *http.Request, res *http.Response, streaming bool) (blockStatus int)
}

// applyResponseGuard runs the guard. handled is true when the response was replaced and written.
func (p *ReverseProxy) applyResponseGuard(rw http.ResponseWriter, req *http.Request, res *http.Response, g ResponseGuard) (status int, handled bool) {
	streaming := p.isBidirectionalStream(req, res) ||
		strings.HasPrefix(strings.ToLower(res.Header.Get("Content-Type")), "application/grpc")
	st := g.GuardResponse(req, res, streaming)
	if st == 0 {
		return 0, false
	}
	h := rw.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	rw.WriteHeader(st)
	rw.Write([]byte(http.StatusText(st) + "\n"))
	return st, true
}
