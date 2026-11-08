package cluster

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FleetHandler serves the token authenticated hub endpoints. Mount it on
// the three Fleet paths outside the admin session and CSRF layers. A node
// that is not a hub answers 404 to all of them.
func (m *Manager) FleetHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(FleetJoinPath, m.hub.handleJoin)
	mux.HandleFunc(FleetConfigPath, m.hub.handleConfig)
	mux.HandleFunc(FleetHeartbeatPath, m.hub.handleHeartbeat)
	return mux
}

func (h *Hub) gate(w http.ResponseWriter, r *http.Request, method string, lim *RateLimiter) bool {
	if !h.active() {
		http.NotFound(w, r)
		return false
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !lim.Allow(clientIP(r), h.now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return false
	}
	return true
}

func (h *Hub) handleJoin(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r, http.MethodPost, h.joinLimiter) {
		return
	}
	var req struct {
		Token   string `json:"token"`
		NodeID  string `json:"nodeId"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if err != nil || json.Unmarshal(body, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, err := h.Join(req.Token, req.NodeID, req.Name, req.Version, clientIP(r))
	if err != nil {
		status := http.StatusUnauthorized
		msg := "invalid or expired join token"
		if err != ErrJoinInvalid {
			status, msg = http.StatusBadRequest, err.Error()
		}
		http.Error(w, msg, status)
		return
	}
	writeJSON(w, res)
}

func (h *Hub) handleConfig(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r, http.MethodGet, h.syncLimiter) {
		return
	}
	now := h.now()
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	n, usedKey, err := h.authNode(tok, r.Method, r.URL.Path, now)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.touch(n.ID, r, now)
	b, cur, err := h.bundleFor(n.ID)
	if err != nil || cur == nil {
		http.Error(w, "config unavailable", http.StatusInternalServerError)
		return
	}
	meta := b.meta
	if cur.NextKey != "" && usedKey == cur.Key {
		meta.Rotate = cur.NextKey
	}
	if have := r.URL.Query().Get("have"); have == meta.Hash && meta.Rotate == "" {
		w.Header().Set("X-Zoraxy-Fleet-Hash", meta.Hash)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	p := &Payload{Roots: rootsOf(b.files), IncludesCerts: hasCerts(b.files), Files: b.files, ContentHash: HashFiles(b.files), Fleet: &meta}
	raw, err := Seal(usedKey, meta.Version, now.Unix(), meta.HubID, p)
	if err != nil {
		http.Error(w, "config unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Zoraxy-Fleet-Hash", meta.Hash)
	w.Write(raw)
}

func rootsOf(files []FileEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		root := strings.SplitN(f.Path, "/", 2)[0]
		if !seen[root] {
			seen[root] = true
			out = append(out, root)
		}
	}
	sort.Strings(out)
	return out
}

func hasCerts(files []FileEntry) bool {
	for _, f := range files {
		if strings.HasPrefix(f.Path, certRoot+"/") {
			return true
		}
	}
	return false
}

func (h *Hub) touch(id string, r *http.Request, now time.Time) {
	h.mu.Lock()
	rt := h.rtFor(id)
	rt.LastSeen = now.Unix()
	rt.Addr = clientIP(r)
	h.mu.Unlock()
}

func (h *Hub) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !h.gate(w, r, http.MethodPost, h.syncLimiter) {
		return
	}
	now := h.now()
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	n, _, err := h.authNode(tok, r.Method, r.URL.Path, now)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var hb fleetHeartbeat
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFleetHBBody))
	if err != nil || json.Unmarshal(body, &hb) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h.touch(n.ID, r, now)
	reply := h.recordHeartbeat(n.ID, hb, now)
	h.Tick(now)
	writeJSON(w, reply)
}

// recordHeartbeat stores a node report and derives the per minute rates.
func (h *Hub) recordHeartbeat(id string, hb fleetHeartbeat, now time.Time) fleetHeartbeatReply {
	hb.Name, hb.Version = trimTo(hb.Name, 64), trimTo(hb.Version, 32)
	hb.LastError = trimTo(hb.LastError, 300)
	hb.LastResult = trimTo(hb.LastResult, 16)
	hb.AppliedHash, hb.AttemptHash = trimTo(hb.AppliedHash, 64), trimTo(hb.AttemptHash, 64)
	hb.Stats.WAFMode = trimTo(hb.Stats.WAFMode, 16)
	hb.Stats.Health = trimTo(hb.Stats.Health, 16)
	if len(hb.Conflicts) > 20 {
		hb.Conflicts = hb.Conflicts[:20]
	}
	for i := range hb.Conflicts {
		hb.Conflicts[i].Key = trimTo(hb.Conflicts[i].Key, 96)
		hb.Conflicts[i].Scope = trimTo(hb.Conflicts[i].Scope, 24)
	}
	h.mu.Lock()
	n := h.st.Nodes[id]
	if n == nil {
		h.mu.Unlock()
		return fleetHeartbeatReply{}
	}
	rt := h.rtFor(id)
	if rt.PrevAt > 0 {
		dt := float64(now.Unix() - rt.PrevAt)
		if dt >= 5 {
			rate := func(cur, prev uint64) float64 {
				d := cur
				if cur >= prev {
					d = cur - prev //a smaller value means the node restarted
				}
				return float64(d) / dt * 60
			}
			rt.ReqPerMin = rate(hb.Stats.Requests, rt.PrevStats.Requests)
			rt.ErrPerMin = rate(hb.Stats.Errors, rt.PrevStats.Errors)
			rt.WAFPerMin = rate(hb.Stats.WAFEvents, rt.PrevStats.WAFEvents)
			rt.PrevStats, rt.PrevAt = hb.Stats, now.Unix()
		}
	} else {
		rt.PrevStats, rt.PrevAt = hb.Stats, now.Unix()
	}
	rt.HB, rt.Version = hb, hb.Version
	sig := hb.AppliedHash + "|" + hb.AttemptHash + "|" + hb.LastResult
	if sig != rt.lastHistHash {
		rt.lastHistHash = sig
		if hb.LastResult != "" {
			rt.History = append(rt.History, HistoryEntry{At: now.Unix(), Version: hb.AppliedVer, Result: hb.LastResult, Error: hb.LastError})
			if len(rt.History) > 20 {
				rt.History = rt.History[1:]
			}
		}
	}
	if hb.LastError != "" && (len(rt.Errors) == 0 || rt.Errors[len(rt.Errors)-1].Error != hb.LastError) {
		rt.Errors = append(rt.Errors, HistoryEntry{At: now.Unix(), Version: hb.AppliedVer, Result: "error", Error: hb.LastError})
		if len(rt.Errors) > 10 {
			rt.Errors = rt.Errors[1:]
		}
	}
	sync := rt.SyncRequest
	rt.SyncRequest = false
	secs := h.st.Settings.HeartbeatSecs
	h.mu.Unlock()
	_, hash := h.DesiredHash(id)
	return fleetHeartbeatReply{SyncNow: sync, DesiredHash: hash, HeartbeatS: secs}
}

// ---------------------------------------------------------------------
// dashboard view

// NodeView is one row of the Fleet table plus the drawer details.
type NodeView struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Group          string            `json:"group"`
	Version        string            `json:"version"`
	Status         string            `json:"status"`
	LastSeen       int64             `json:"lastSeen"`
	Addr           string            `json:"addr"`
	Uptime         int64             `json:"uptime"`
	Health         string            `json:"health"`
	Endpoints      int               `json:"endpoints"`
	CertExpiry     int64             `json:"certExpiry"`
	WAFMode        string            `json:"wafMode"`
	ReqPerMin      float64           `json:"reqPerMin"`
	ErrPerMin      float64           `json:"errPerMin"`
	WAFPerMin      float64           `json:"wafPerMin"`
	AppliedVersion int64             `json:"appliedVersion"`
	DesiredVersion int64             `json:"desiredVersion"`
	Drift          bool              `json:"drift"`
	DriftReason    string            `json:"driftReason,omitempty"`
	LastResult     string            `json:"lastResult"`
	LastError      string            `json:"lastError"`
	Conflicts      []Conflict        `json:"conflicts,omitempty"`
	ManagedCount   int               `json:"managedCount"`
	KeyRotating    bool              `json:"keyRotating"`
	Vars           map[string]string `json:"vars"`
	Override       *ScopeSel         `json:"override"`
	History        []HistoryEntry    `json:"history"`
	Errors         []HistoryEntry    `json:"errors"`
}

// Aggregate is computed from bounded heartbeat stats only.
type Aggregate struct {
	Nodes      map[string]int `json:"nodes"`
	Drifting   int            `json:"drifting"`
	Endpoints  int            `json:"endpoints"`
	ReqPerMin  float64        `json:"reqPerMin"`
	ErrPerMin  float64        `json:"errPerMin"`
	ErrorRate  float64        `json:"errorRate"`
	WAFPerMin  float64        `json:"wafPerMin"`
	WAFByMode  map[string]int `json:"wafByMode"`
	SoonestCrt int64          `json:"soonestCertExpiry"`
}

func (h *Hub) statusLocked(n *FleetNode, rt *nodeRuntime, now time.Time) string {
	if n.Revoked {
		return StatusRevoked
	}
	if rt == nil || rt.LastSeen == 0 {
		return StatusNever
	}
	age := now.Sub(time.Unix(rt.LastSeen, 0))
	switch {
	case age > offlineAfter:
		return StatusOffline
	case age > onlineWithin:
		return StatusDegraded
	case rt.HB.Stats.Health != "" && rt.HB.Stats.Health != "ok", rt.HB.LastResult == "error":
		return StatusDegraded
	}
	return StatusOnline
}

// Overview builds everything the Fleet page shows.
func (h *Hub) Overview() map[string]any {
	now := h.now()
	h.mu.Lock()
	ids := make([]string, 0, len(h.st.Nodes))
	for id := range h.st.Nodes {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	sort.Strings(ids)
	type dh struct {
		ver  int64
		hash string
	}
	desired := map[string]dh{}
	for _, id := range ids {
		v, hs := h.DesiredHash(id)
		desired[id] = dh{v, hs}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	agg := Aggregate{Nodes: map[string]int{}, WAFByMode: map[string]int{}}
	nodes := []NodeView{}
	for _, id := range ids {
		n := h.st.Nodes[id]
		if n == nil {
			continue
		}
		rt := h.rt[id]
		v := NodeView{ID: id, Name: n.Name, Group: n.Group, Vars: n.Vars, Override: n.Override, KeyRotating: n.NextKey != "",
			Status: h.statusLocked(n, rt, now), DesiredVersion: desired[id].ver, History: []HistoryEntry{}, Errors: []HistoryEntry{}}
		if rt != nil {
			hb := rt.HB
			v.Version, v.LastSeen, v.Addr = rt.Version, rt.LastSeen, rt.Addr
			v.Uptime, v.Health, v.Endpoints = hb.Stats.UptimeSeconds, hb.Stats.Health, hb.Stats.Endpoints
			v.CertExpiry, v.WAFMode = hb.Stats.CertExpiry, hb.Stats.WAFMode
			v.ReqPerMin, v.ErrPerMin, v.WAFPerMin = rt.ReqPerMin, rt.ErrPerMin, rt.WAFPerMin
			v.AppliedVersion, v.LastResult, v.LastError = hb.AppliedVer, hb.LastResult, hb.LastError
			v.Conflicts, v.ManagedCount = hb.Conflicts, hb.ManagedCount
			if rt.History != nil {
				v.History = rt.History
			}
			if rt.Errors != nil {
				v.Errors = rt.Errors
			}
			if rt.LastSeen > 0 && v.Status != StatusRevoked && desired[id].ver != 0 {
				if hb.AppliedHash != desired[id].hash {
					v.Drift, v.DriftReason = true, "applied configuration differs from the desired version"
				} else if hb.LocalDrift {
					v.Drift, v.DriftReason = true, "managed files were edited on the node"
				}
			}
		}
		agg.Nodes[v.Status]++
		if v.Drift {
			agg.Drifting++
		}
		if v.Status == StatusOnline || v.Status == StatusDegraded {
			agg.Endpoints += v.Endpoints
			agg.ReqPerMin += v.ReqPerMin
			agg.ErrPerMin += v.ErrPerMin
			agg.WAFPerMin += v.WAFPerMin
			if v.WAFMode != "" {
				agg.WAFByMode[v.WAFMode]++
			}
			if v.CertExpiry > 0 && (agg.SoonestCrt == 0 || v.CertExpiry < agg.SoonestCrt) {
				agg.SoonestCrt = v.CertExpiry
			}
		}
		nodes = append(nodes, v)
	}
	if agg.ReqPerMin > 0 {
		agg.ErrorRate = agg.ErrPerMin / agg.ReqPerMin
	}
	groups := []FleetGroup{}
	for _, g := range h.st.Groups {
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	type tokView struct {
		ID        string `json:"id"`
		CreatedBy string `json:"createdBy"`
		ExpiresAt int64  `json:"expiresAt"`
		NodeName  string `json:"nodeName"`
		Group     string `json:"group"`
		State     string `json:"state"`
		UsedBy    string `json:"usedBy"`
	}
	toks := []tokView{}
	for _, t := range h.st.Tokens {
		st := "open"
		switch {
		case t.UsedAt != 0:
			st = "used"
		case t.Revoked:
			st = "revoked"
		case now.Unix() > t.ExpiresAt:
			st = "expired"
		}
		toks = append(toks, tokView{t.ID, t.CreatedBy, t.ExpiresAt, t.NodeName, t.Group, st, t.UsedBy})
	}
	vers := append([]VersionMeta{}, h.st.Versions...)
	for i := range vers {
		vers[i].Files = nil //index stays on the hub
	}
	return map[string]any{
		"hubId": h.st.HubID, "now": now.Unix(), "nodes": nodes, "groups": groups, "tokens": toks,
		"versions": vers, "aggregate": agg, "settings": h.st.Settings, "scopes": ScopeList(),
		"variableNames": ReservedVars,
	}
}

// ---------------------------------------------------------------------
// admin API (admin session + CSRF protected by the Zoraxy auth layer)

// FleetAPIPrefix is the admin API prefix; register it as a subtree.
const FleetAPIPrefix = "/api/fleet/hub/"

func (m *Manager) actor(r *http.Request) string {
	if m.opt.Actor != nil {
		if a := m.opt.Actor(r); a != "" {
			return a
		}
	}
	return "admin"
}

func formList(r *http.Request, key string) []string {
	var out []string
	for _, e := range strings.FieldsFunc(r.PostFormValue(key), func(c rune) bool { return c == ',' || c == '\n' || c == ' ' }) {
		out = append(out, e)
	}
	return out
}

func formVars(r *http.Request, key string) (map[string]string, error) {
	v := map[string]string{}
	raw := strings.TrimSpace(r.PostFormValue(key))
	if raw == "" {
		return v, nil
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, err
	}
	return v, nil
}

// HandleFleetHub is the single admin entry point of the hub: /api/fleet/hub/<action>.
func (m *Manager) HandleFleetHub(w http.ResponseWriter, r *http.Request) {
	h := m.hub
	action := strings.TrimPrefix(r.URL.Path, FleetAPIPrefix)
	if action == "overview" || action == "audit" || action == "diff" || action == "joinInfo" {
		if m.Role() != RoleHub {
			writeErr(w, "this node is not a fleet hub")
			return
		}
		switch action {
		case "overview":
			writeJSON(w, h.Overview())
		case "audit":
			writeJSON(w, h.AuditLog(200))
		case "joinInfo":
			writeJSON(w, map[string]any{"hubId": h.HubID()})
		case "diff":
			a, _ := strconv.ParseInt(r.URL.Query().Get("a"), 10, 64)
			b, _ := strconv.ParseInt(r.URL.Query().Get("b"), 10, 64)
			d, err := h.Diff(a, b)
			if err != nil {
				writeErr(w, err.Error())
				return
			}
			writeJSON(w, d)
		}
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, "POST required")
		return
	}
	if m.Role() != RoleHub {
		writeErr(w, "this node is not a fleet hub")
		return
	}
	r.ParseForm()
	by := m.actor(r)
	fail := func(err error) {
		if err != nil {
			writeErr(w, err.Error())
		} else {
			writeJSON(w, "ok")
		}
	}
	id := r.PostFormValue("id")
	switch action {
	case "tokenCreate":
		mins, _ := strconv.Atoi(r.PostFormValue("minutes"))
		tok, t, err := h.CreateJoinToken(by, time.Duration(mins)*time.Minute, strings.TrimSpace(r.PostFormValue("name")), strings.TrimSpace(r.PostFormValue("group")))
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, map[string]any{"token": tok, "id": t.ID, "expiresAt": t.ExpiresAt})
	case "tokenRevoke":
		fail(h.RevokeJoinToken(by, id))
	case "nodeRevoke":
		fail(h.RevokeNode(by, id))
	case "nodeRotate":
		fail(h.RotateNode(by, id))
	case "nodeRemove":
		fail(h.RemoveNode(by, id))
	case "nodeSync":
		fail(h.SyncNow(by, id))
	case "nodeGroup":
		fail(h.SetNodeGroup(by, id, strings.TrimSpace(r.PostFormValue("group"))))
	case "nodeVars":
		v, err := formVars(r, "vars")
		if err != nil {
			fail(err)
			return
		}
		fail(h.SetNodeVars(by, id, v))
	case "nodeScopes":
		if r.PostFormValue("inherit") == "true" {
			fail(h.SetNodeScopes(by, id, nil))
			return
		}
		fail(h.SetNodeScopes(by, id, &ScopeSel{Scopes: formList(r, "scopes"), ProxyTags: formList(r, "tags")}))
	case "groupSet":
		v, err := formVars(r, "vars")
		if err != nil {
			fail(err)
			return
		}
		fail(h.SetGroup(by, strings.TrimSpace(r.PostFormValue("name")), ScopeSel{Scopes: formList(r, "scopes"), ProxyTags: formList(r, "tags")}, v))
	case "groupDelete":
		fail(h.DeleteGroup(by, strings.TrimSpace(r.PostFormValue("name"))))
	case "capture":
		v, created, err := h.Capture(by, r.PostFormValue("note"))
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, map[string]any{"version": v.ID, "created": created})
	case "publish":
		ver, _ := strconv.ParseInt(r.PostFormValue("version"), 10, 64)
		hs, _ := strconv.Atoi(r.PostFormValue("healthySeconds"))
		ts, _ := strconv.Atoi(r.PostFormValue("timeoutSeconds"))
		ro, err := h.Publish(by, PublishRequest{Group: r.PostFormValue("group"), Version: ver, Note: r.PostFormValue("note"),
			Strategy: r.PostFormValue("strategy"), CanaryNode: r.PostFormValue("canaryNode"), HealthySeconds: hs,
			HoldForApproval: r.PostFormValue("hold") == "true", TimeoutSeconds: ts})
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, ro)
	case "approve":
		fail(h.Approve(by, r.PostFormValue("group")))
	case "abort":
		fail(h.Abort(by, r.PostFormValue("group")))
	case "rollback":
		to, _ := strconv.ParseInt(r.PostFormValue("version"), 10, 64)
		ro, err := h.Rollback(by, r.PostFormValue("group"), to, r.PostFormValue("strategy"))
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		writeJSON(w, ro)
	case "settings":
		keep, _ := strconv.Atoi(r.PostFormValue("keepVersions"))
		hbs, _ := strconv.Atoi(r.PostFormValue("heartbeatSecs"))
		gr, _ := strconv.Atoi(r.PostFormValue("healthGraceSec"))
		fail(h.SetSettings(by, HubSettings{KeepVersions: keep, HeartbeatSecs: hbs, HealthGraceSec: gr, CaptureCerts: r.PostFormValue("captureCerts") == "true"}))
	default:
		writeErr(w, "unknown action")
	}
}
