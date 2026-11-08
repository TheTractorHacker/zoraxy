package dynamicproxy

import (
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"imuslab.com/zoraxy/mod/sablier"
)

/*
	sablier_gate.go

	Sablier (scale-to-zero) gate of a proxy rule (fork #120 / upstream #564), client logic in mod/sablier.
	Runs after authentication and the Lua stage, right before the upstream is contacted. Handler mode scripts never reach it
	(they replace the upstream), static responses and the health endpoint are answered earlier.
*/

type SablierConfig struct {
	sablier.Config
	rt atomic.Pointer[sablierRuntime] `json:"-"`
}

type sablierRuntime struct {
	gate *sablier.Gate
	err  error
}

func (c *SablierConfig) Validate() error {
	if c == nil {
		return nil
	}
	return c.Config.Validate()
}

func (c *SablierConfig) runtime() *sablierRuntime {
	if rt := c.rt.Load(); rt != nil {
		return rt
	}
	g, err := sablier.New(c.Config)
	rt := &sablierRuntime{gate: g, err: err}
	c.rt.Store(rt)
	return rt
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func wantsHTML(r *http.Request) bool {
	a := r.Header.Get("Accept")
	return a == "" || strings.Contains(a, "text/html") || strings.Contains(a, "*/*")
}

// handleSablier returns true when the request was answered (waiting page / error) instead of being proxied
func (h *ProxyHandler) handleSablier(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	sc := sep.Sablier
	if sc == nil || !sc.Enabled || sc.Bypass(r.URL.Path) {
		return false
	}
	rt := sc.runtime()
	id := ""
	if st := opsStateFrom(r); st != nil {
		id = st.id
	}
	unavailable := func(msg string, err error) bool {
		h.Parent.Option.Logger.PrintAndLog("proxy-sablier", "Sablier check for "+sep.RootOrMatchingDomain+" failed (request "+id+")", err)
		if sc.FailOpen {
			return false
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		http.Error(w, "503 - "+msg+" (request id "+id+")", http.StatusServiceUnavailable)
		h.Parent.logRequest(r, false, http.StatusServiceUnavailable, "sablier-error", r.Host, "", sep)
		return true
	}
	if rt.err != nil {
		return unavailable("Service start controller misconfigured", rt.err)
	}
	out, err := rt.gate.Check(r.Context())
	if err != nil {
		if r.Context().Err() != nil {
			return true //client went away
		}
		return unavailable("Service start controller unavailable", err)
	}
	if out.Ready {
		return false
	}
	//Not ready. WebSocket upgrades and non-browser clients get a plain 503 instead of the HTML waiting page: the request
	//has already woken the workload, they just have to retry.
	hd := w.Header()
	hd.Set("Cache-Control", "no-store")
	if isWebSocketUpgrade(r) || !wantsHTML(r) {
		hd.Set("Retry-After", "5")
		http.Error(w, "503 - Service is starting", http.StatusServiceUnavailable)
		h.Parent.logRequest(r, false, http.StatusServiceUnavailable, "sablier-waiting", r.Host, "", sep)
		return true
	}
	hd.Set("Content-Type", out.Type)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Length", strconv.Itoa(len(out.Body)))
	if out.Status == http.StatusServiceUnavailable || out.Status == http.StatusTooManyRequests {
		hd.Set("Retry-After", "5")
	}
	w.WriteHeader(out.Status)
	if r.Method != http.MethodHead {
		w.Write(out.Body)
	}
	h.Parent.logRequest(r, out.Status < 400, out.Status, "sablier-waiting", r.Host, "", sep)
	return true
}
