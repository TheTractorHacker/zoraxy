package cluster

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HealthPath is served by the proxy listeners before host routing.
const HealthPath = "/.zoraxy/health"

// HealthEndpoint answers load balancer / keepalived probes. It exposes no
// secrets: version, uptime, whether the proxy router is running and how many
// proxy endpoints are active.
type HealthEndpoint struct {
	Version string
	Started time.Time

	mu       sync.RWMutex
	allow    []*net.IPNet
	disabled bool
}

// NewHealthEndpoint creates an endpoint that allows everyone.
func NewHealthEndpoint(version string) *HealthEndpoint {
	return &HealthEndpoint{Version: version, Started: time.Now()}
}

// Configure sets the optional allow-list (IPs or CIDRs) and the kill switch.
// An empty list allows all clients.
func (h *HealthEndpoint) Configure(allow []string, disabled bool) error {
	nets, err := ParseAllowList(allow)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.allow = nets
	h.disabled = disabled
	h.mu.Unlock()
	return nil
}

// ParseAllowList parses IPs and CIDRs.
func ParseAllowList(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			ip := net.ParseIP(e)
			if ip == nil {
				return nil, &net.ParseError{Type: "IP address", Text: e}
			}
			if ip.To4() != nil {
				e += "/32"
			} else {
				e += "/128"
			}
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (h *HealthEndpoint) allowed(remoteAddr string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.allow) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range h.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsHealthRequest reports whether the request targets the health path.
func IsHealthRequest(r *http.Request) bool {
	return r.URL != nil && r.URL.Path == HealthPath
}

// Serve writes the health response. running and endpoints come from the
// proxy router. It returns false (and writes nothing) if the endpoint is
// disabled, so the request falls through to normal routing.
func (h *HealthEndpoint) Serve(w http.ResponseWriter, r *http.Request, running bool, endpoints int) bool {
	h.mu.RLock()
	disabled := h.disabled
	h.mu.RUnlock()
	if disabled {
		return false
	}
	if !h.allowed(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return true
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	status, code := "ok", http.StatusOK
	if !running {
		status, code = "unavailable", http.StatusServiceUnavailable
	}
	body, _ := json.Marshal(map[string]any{
		"status":          status,
		"version":         h.Version,
		"uptimeSeconds":   int64(time.Since(h.Started).Seconds()),
		"proxyRunning":    running,
		"activeEndpoints": endpoints,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
	return true
}
