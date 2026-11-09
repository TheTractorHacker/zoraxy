package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

/*
	Staged rollout

	immediate  every node of the group is pointed at the new version at once
	manual     nothing changes until an admin approves (then immediate)
	canary     one node gets the version first. It must apply it and stay
	           healthy (health reported in its heartbeat) for HealthySeconds.
	           Then the rest follow, or, with HoldForApproval, an admin
	           approves the promotion. A failed apply, an unhealthy canary or
	           a canary that does not apply in time halts the rollout and the
	           canary goes back to the group's stable version.

	Nodes always apply atomically with a local rollback (the same code as the
	legacy follower), so a bad version can never leave a node half applied.
*/

// PublishRequest describes a publish to one group.
type PublishRequest struct {
	Group           string `json:"group"`
	Version         int64  `json:"version"` //0 = capture the hub's current configuration
	Note            string `json:"note"`
	Strategy        string `json:"strategy"`
	CanaryNode      string `json:"canaryNode"`
	HealthySeconds  int    `json:"healthySeconds"`
	HoldForApproval bool   `json:"holdForApproval"`
	TimeoutSeconds  int    `json:"timeoutSeconds"`
}

func activeState(s string) bool {
	return s == RolloutPendingApproval || s == RolloutCanary || s == RolloutAwaitPromotion
}

// Preflight checks that every node of the group can apply the version: the
// scopes exist in it, all variables are defined and the resolved content
// still validates. A publish that fails here changes nothing.
func (h *Hub) Preflight(group string, ver int64) error {
	h.mu.Lock()
	vm, ok := h.versionMeta(ver)
	var nodes []FleetNode
	type eff struct {
		sel  ScopeSel
		vars map[string]string
	}
	effs := map[string]eff{}
	for _, n := range h.st.Nodes {
		if n.Group == group && !n.Revoked {
			nodes = append(nodes, *n)
			s, v := h.effectiveLocked(n)
			effs[n.ID] = eff{s, v}
		}
	}
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("version %d does not exist", ver)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	have := map[string]bool{}
	for _, s := range vm.Scopes {
		have[s] = true
	}
	for _, n := range nodes {
		e := effs[n.ID]
		for _, s := range e.sel.Scopes {
			if !have[s] {
				return fmt.Errorf("node %s manages scope %q, which version %d does not contain (capture again after enabling it, e.g. certificates)", n.Name, s, ver)
			}
		}
		vars := map[string]string{}
		for k, v := range e.vars {
			vars[k] = v
		}
		for k, v := range builtinVars(&n) {
			vars[k] = v
		}
		b, err := h.buildBundle(n, e.sel, vars, ver)
		if err != nil {
			return fmt.Errorf("node %s: %w", n.Name, err)
		}
		all := append(append([]FileEntry{}, b.files...), b.meta.Extra...)
		if miss, err := MissingVars(all, vars); err != nil {
			return fmt.Errorf("node %s: %w", n.Name, err)
		} else if len(miss) > 0 {
			return fmt.Errorf("node %s lacks variable(s) %s used by version %d", n.Name, strings.Join(miss, ", "), ver)
		}
		res, err := ResolveFiles(all, vars)
		if err != nil {
			return fmt.Errorf("node %s: %w", n.Name, err)
		}
		for sc, its := range groupItems(res, nil) {
			if s, ok := GetScope(sc); ok {
				if err := s.Validate(its); err != nil {
					return fmt.Errorf("node %s: %w", n.Name, err)
				}
			}
		}
	}
	return nil
}

// Publish starts a rollout of a version to a group.
func (h *Hub) Publish(by string, req PublishRequest) (*Rollout, error) {
	if !h.active() {
		return nil, errors.New("this node is not a fleet hub")
	}
	switch req.Strategy {
	case "":
		req.Strategy = StrategyImmediate
	case StrategyImmediate, StrategyCanary, StrategyManual:
	default:
		return nil, errors.New("strategy must be immediate, canary or manual")
	}
	if req.HealthySeconds <= 0 {
		req.HealthySeconds = 60
	}
	if req.HealthySeconds > 3600 {
		return nil, errors.New("healthySeconds must be at most 3600")
	}
	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 300
	}
	if req.TimeoutSeconds > 3600 {
		return nil, errors.New("timeoutSeconds must be at most 3600")
	}
	h.mu.Lock()
	g := h.st.Groups[req.Group]
	if g == nil {
		h.mu.Unlock()
		return nil, errors.New("no such group")
	}
	if g.Rollout != nil && activeState(g.Rollout.State) {
		h.mu.Unlock()
		return nil, errors.New("a rollout is already in progress for this group; approve or abort it first")
	}
	h.mu.Unlock()

	ver := req.Version
	if ver == 0 {
		vm, _, err := h.Capture(by, req.Note)
		if err != nil {
			return nil, err
		}
		ver = vm.ID
	}
	if err := h.Preflight(req.Group, ver); err != nil {
		return nil, err
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	g = h.st.Groups[req.Group]
	if g == nil {
		return nil, errors.New("no such group")
	}
	if g.Rollout != nil && activeState(g.Rollout.State) {
		return nil, errors.New("a rollout is already in progress for this group")
	}
	now := h.now().Unix()
	prevRollout, prevDesired := g.Rollout, g.Desired
	r := &Rollout{ID: randHex(4), Group: g.Name, Version: ver, PrevVersion: g.Desired, Strategy: req.Strategy,
		HealthySeconds: req.HealthySeconds, HoldForApproval: req.HoldForApproval, TimeoutSeconds: req.TimeoutSeconds,
		StartedAt: now, StateAt: now, By: trimTo(by, 64)}
	switch req.Strategy {
	case StrategyImmediate:
		r.State, r.Reason = RolloutComplete, "published to all nodes"
		g.Desired = ver
	case StrategyManual:
		r.State = RolloutPendingApproval
	case StrategyCanary:
		c, err := h.pickCanaryLocked(g.Name, req.CanaryNode)
		if err != nil {
			return nil, err
		}
		r.CanaryNode, r.State = c, RolloutCanary
		h.rtFor(c).SyncRequest = true
	}
	g.Rollout = r
	if err := h.saveLocked(); err != nil {
		g.Rollout, g.Desired = prevRollout, prevDesired
		return nil, err
	}
	h.pruneVersionsLocked()
	h.auditLocked(AuditEntry{At: now, Actor: by, Action: "rollout.start", Target: g.Name,
		Detail: fmt.Sprintf("v%d %s canary=%s prev=v%d", ver, r.Strategy, r.CanaryNode, r.PrevVersion)})
	cp := *r
	return &cp, nil
}

func (h *Hub) pickCanaryLocked(group, want string) (string, error) {
	if want != "" {
		n := h.st.Nodes[want]
		if n == nil || n.Group != group || n.Revoked || n.Paused {
			return "", errors.New("canary node is not an active, synced member of the group")
		}
		return want, nil
	}
	now := h.now().Unix()
	var ids []string
	for id, n := range h.st.Nodes {
		if n.Group == group && !n.Revoked && !n.Paused {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if rt := h.rt[id]; rt != nil && now-rt.LastSeen <= int64(onlineWithin/time.Second) {
			return id, nil
		}
	}
	if len(ids) > 0 {
		return "", errors.New("no node of the group is online to act as canary")
	}
	return "", errors.New("the group has no nodes")
}

func (h *Hub) rollout(group string) (*FleetGroup, *Rollout, error) {
	g := h.st.Groups[group]
	if g == nil {
		return nil, nil, errors.New("no such group")
	}
	if g.Rollout == nil || !activeState(g.Rollout.State) {
		return nil, nil, errors.New("no rollout is waiting in this group")
	}
	return g, g.Rollout, nil
}

// Approve releases a manual rollout, or promotes a canary that is waiting.
func (h *Hub) Approve(by, group string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	g, r, err := h.rollout(group)
	if err != nil {
		return err
	}
	switch r.State {
	case RolloutPendingApproval, RolloutAwaitPromotion:
	default:
		return errors.New("the rollout is not waiting for approval")
	}
	h.completeLocked(g, r, "approved by "+by)
	h.auditLocked(AuditEntry{At: h.now().Unix(), Actor: by, Action: "rollout.approve", Target: group, Detail: "v" + strconv.FormatInt(r.Version, 10)})
	return h.saveLocked()
}

// Abort stops an active rollout. Nodes return to the group's stable version.
func (h *Hub) Abort(by, group string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, r, err := h.rollout(group)
	if err != nil {
		return err
	}
	r.State, r.StateAt, r.Reason = RolloutAborted, h.now().Unix(), "aborted by "+by
	if r.CanaryNode != "" {
		h.rtFor(r.CanaryNode).SyncRequest = true
	}
	h.auditLocked(AuditEntry{At: r.StateAt, Actor: by, Action: "rollout.abort", Target: group})
	return h.saveLocked()
}

// Rollback publishes an earlier version again (default: the version the
// group ran before its latest rollout).
func (h *Hub) Rollback(by, group string, to int64, strategy string) (*Rollout, error) {
	if to == 0 {
		h.mu.Lock()
		g := h.st.Groups[group]
		if g != nil && g.Rollout != nil {
			to = g.Rollout.PrevVersion
			if g.Rollout.State == RolloutHalted || g.Rollout.State == RolloutAborted {
				to = g.Desired
			}
		}
		h.mu.Unlock()
	}
	if to == 0 {
		return nil, errors.New("there is no earlier version to roll back to")
	}
	h.mu.Lock()
	g := h.st.Groups[group]
	if g != nil && g.Rollout != nil && activeState(g.Rollout.State) {
		g.Rollout.State, g.Rollout.StateAt, g.Rollout.Reason = RolloutAborted, h.now().Unix(), "superseded by rollback by "+by
	}
	h.mu.Unlock()
	h.Audit(by, "rollback", group, "to v"+strconv.FormatInt(to, 10))
	return h.Publish(by, PublishRequest{Group: group, Version: to, Strategy: strategy, Note: "rollback"})
}

func (h *Hub) completeLocked(g *FleetGroup, r *Rollout, why string) {
	g.Desired = r.Version
	r.State, r.StateAt, r.Reason = RolloutComplete, h.now().Unix(), why
}

func (h *Hub) haltLocked(g *FleetGroup, r *Rollout, why string) {
	r.State, r.StateAt = RolloutHalted, h.now().Unix()
	r.Reason = why
	if r.PrevVersion == 0 {
		r.Reason += " (no earlier version existed to return the canary to; check it manually)"
	}
	h.rtFor(r.CanaryNode).SyncRequest = true
	h.auditLocked(AuditEntry{At: r.StateAt, Actor: "system", Action: "rollout.halt", Target: g.Name, Detail: trimTo(r.Reason, 280)})
	h.saveLocked()
}

// Tick advances canary rollouts. It is called on a timer and after each
// heartbeat; now is injectable for tests.
func (h *Hub) Tick(now time.Time) {
	type job struct {
		group, id, node string
	}
	var jobs []job
	h.mu.Lock()
	for _, g := range h.st.Groups {
		if r := g.Rollout; r != nil && (r.State == RolloutCanary) {
			jobs = append(jobs, job{g.Name, r.ID, r.CanaryNode})
		}
	}
	h.mu.Unlock()
	for _, j := range jobs {
		_, hash := h.DesiredHash(j.node)
		h.mu.Lock()
		g := h.st.Groups[j.group]
		if g != nil && g.Rollout != nil && g.Rollout.ID == j.id && g.Rollout.State == RolloutCanary {
			h.evalCanaryLocked(g, g.Rollout, hash, now)
		}
		h.mu.Unlock()
	}
}

func (h *Hub) evalCanaryLocked(g *FleetGroup, r *Rollout, hash string, now time.Time) {
	n := h.st.Nodes[r.CanaryNode]
	if n == nil || n.Revoked {
		h.haltLocked(g, r, "canary node was removed or revoked")
		return
	}
	elapsed := now.Unix() - r.StateAt
	timedOut := elapsed > int64(r.TimeoutSeconds)
	rt := h.rt[r.CanaryNode]
	if rt == nil || rt.LastSeen == 0 {
		if timedOut {
			h.haltLocked(g, r, "canary node never reported in")
		}
		return
	}
	hb := rt.HB
	if hash != "" && hb.AttemptHash == hash && hb.LastResult == "error" && hb.AppliedHash != hash {
		h.haltLocked(g, r, "apply failed on canary "+n.Name+": "+hb.LastError)
		return
	}
	if hb.AppliedHash != hash {
		if timedOut {
			h.haltLocked(g, r, fmt.Sprintf("canary %s did not apply the version within %ds", n.Name, r.TimeoutSeconds))
		}
		return
	}
	age := now.Unix() - rt.LastSeen
	switch {
	case age > int64(offlineAfter/time.Second):
		h.haltLocked(g, r, "canary "+n.Name+" went offline after applying")
	case age > int64(onlineWithin/time.Second):
		r.HealthySince = 0 //restart in progress or late: the healthy period starts over
	case hb.Stats.Health != "ok":
		r.HealthySince = 0
		if r.UnhealthySince == 0 {
			r.UnhealthySince = now.Unix()
		}
		if now.Unix()-r.UnhealthySince >= int64(h.st.Settings.HealthGraceSec) {
			h.haltLocked(g, r, "canary "+n.Name+" is unhealthy after the new configuration")
		}
	default:
		r.UnhealthySince = 0
		if r.HealthySince == 0 {
			r.HealthySince = now.Unix()
		}
		if now.Unix()-r.HealthySince >= int64(r.HealthySeconds) {
			if r.HoldForApproval {
				r.State, r.StateAt = RolloutAwaitPromotion, now.Unix()
				r.Reason = "canary healthy, waiting for approval"
				h.saveLocked()
				return
			}
			h.completeLocked(g, r, fmt.Sprintf("canary healthy for %ds, promoted to the group", r.HealthySeconds))
			h.auditLocked(AuditEntry{At: now.Unix(), Actor: "system", Action: "rollout.promote", Target: g.Name, Detail: "v" + strconv.FormatInt(r.Version, 10)})
			h.saveLocked()
		}
	}
}
