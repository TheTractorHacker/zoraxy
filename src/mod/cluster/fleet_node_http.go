package cluster

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// HandleFleetNodeInfo returns the fleet state of this node for the UI
// (the "managed by hub" badge, the join dialog and the hub's own pin).
func (m *Manager) HandleFleetNodeInfo(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"role":   m.Role(),
		"nodeId": m.opt.NodeID,
		"fleet":  m.FleetInfo(),
		"legacy": m.Role() == RolePrimary || m.Role() == RoleFollower,
	}
	if m.opt.HubFingerprint != nil {
		out["tlsFingerprint"] = m.opt.HubFingerprint() //this node's own admin certificate (shown on the hub for pin comparison)
	}
	writeJSON(w, out)
}

// HandleFleetProbe fetches the hub's certificate fingerprint for confirmation.
func (m *Manager) HandleFleetProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := ProbeHub(ctx, strings.TrimSpace(r.PostFormValue("hubUrl")))
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	writeJSON(w, res)
}

// HandleFleetJoin enrolls this node with a join token.
func (m *Manager) HandleFleetJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := m.Join(ctx, JoinRequest{
		HubURL:      r.PostFormValue("hubUrl"),
		Token:       r.PostFormValue("token"),
		Fingerprint: r.PostFormValue("fingerprint"),
		AllowHTTP:   r.PostFormValue("allowHttp") == "true",
	})
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	writeJSON(w, "ok")
}

// HandleFleetLeave detaches this node from its hub.
func (m *Manager) HandleFleetLeave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	if err := m.Leave(); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeJSON(w, "ok")
}

// HandleFleetNodeSync fetches the bundle now.
func (m *Manager) HandleFleetNodeSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := m.FleetSyncOnce(ctx, r.PostFormValue("force") == "true"); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeJSON(w, m.FleetInfo())
}
