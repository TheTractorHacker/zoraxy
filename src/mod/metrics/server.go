package metrics

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"time"
)

// ContentType is the Prometheus text exposition content type
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Handler serves the exposition. It does no authentication itself: the admin
// API route is protected by the admin auth router; the separate listener
// wraps it with RequireBearer.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !r.Enabled() {
			http.Error(w, "metrics are disabled", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		if req.Method == http.MethodHead {
			return
		}
		r.Write(w)
	})
}

// RequireBearer rejects requests without "Authorization: Bearer <token>".
// An empty token disables the check (the caller decides whether that is
// acceptable, e.g. loopback only listener).
func RequireBearer(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := req.Header.Get("Authorization")
		const p = "Bearer "
		if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) &&
			subtle.ConstantTimeCompare([]byte(strings.TrimSpace(h[len(p):])), want) == 1 {
			next.ServeHTTP(w, req)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="zoraxy-metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// NewServer builds the separate metrics listener server: only GET /metrics,
// optional bearer token, short timeouts.
func (r *Registry) NewServer(addr, token string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", RequireBearer(token, r.Handler()))
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// Serve runs the server on ln (blocking)
func Serve(srv *http.Server, ln net.Listener) error { return srv.Serve(ln) }
