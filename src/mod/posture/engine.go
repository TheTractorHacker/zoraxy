package posture

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Journal remembers what each action changed, so it can be undone
type Journal interface {
	Load() (map[string][]Change, error)
	Save(map[string][]Change) error
}

// MemoryJournal is a Journal that lives in memory (tests)
type MemoryJournal struct {
	mu sync.Mutex
	m  map[string][]Change
}

// Load returns a copy of the journal
func (j *MemoryJournal) Load() (map[string][]Change, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := map[string][]Change{}
	for k, v := range j.m {
		out[k] = append([]Change(nil), v...)
	}
	return out, nil
}

// Save replaces the journal
func (j *MemoryJournal) Save(m map[string][]Change) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.m = map[string][]Change{}
	for k, v := range m {
		j.m[k] = append([]Change(nil), v...)
	}
	return nil
}

// Engine ties checks, actions, the fact collector and the backend together
type Engine struct {
	Checks  *Registry
	Actions *ActionRegistry
	Collect func() *Facts
	Backend Backend
	Journal Journal
	// Audit records an administrator action in the audit log: who, event, target, detail (never secrets)
	Audit func(who Actor, event, target, detail string)
	Now   func() time.Time

	applyMu sync.Mutex
	cacheMu sync.Mutex
	cached  *Overview
	cacheAt time.Time
}

// CacheTTL bounds how long Overview(false) reuses an evaluation
const CacheTTL = 10 * time.Second

// NewEngine returns an engine over the default registries
func NewEngine(collect func() *Facts, b Backend) *Engine {
	return &Engine{Checks: Default, Actions: DefaultActions, Collect: collect, Backend: b, Journal: &MemoryJournal{}, Now: time.Now}
}

// Actor is the administrator on whose behalf an action runs
type Actor struct{ Name, IP string }

// Overview is the answer of GET /api/security/posture
type Overview struct {
	Report
	Actions    []ActionInfo `json:"actions"`
	Managed    string       `json:"managed,omitempty"` // non-empty: fixes are disabled, with the reason
	Disclaimer string       `json:"disclaimer"`
}

// Disclaimer is shown with every score
const Disclaimer = "This score reflects Zoraxy's configuration. It is not a penetration test and does not look inside your applications."

// plan runs an action's plan against fresh facts and normalises it
func (e *Engine) plan(a Action, f *Facts) Plan {
	p := a.Plan(f, e.Backend)
	for i := range p.Changes {
		if p.Changes[i].Prev == "" && p.Changes[i].From != "-" {
			p.Changes[i].Prev = p.Changes[i].From
		}
	}
	if p.Refusal != "" {
		p.Changes = nil
	}
	return p
}

// texts are the title and description to show for an action: the plan's own when it has some and
// there is something to do, else the static ones of the action
func (p Plan) texts(a Action) (title, desc string) {
	title, desc = a.Title, a.Description
	if len(p.Changes) > 0 {
		if p.Title != "" {
			title = p.Title
		}
		if p.Description != "" {
			desc = p.Description
		}
	}
	return
}

func (e *Engine) facts() *Facts {
	f := e.Collect()
	if f == nil {
		f = &Facts{}
	}
	if f.Now.IsZero() {
		f.Now = e.Now()
	}
	return f
}

// Overview evaluates the checks. Unless refresh is set a result younger than CacheTTL is reused.
func (e *Engine) Overview(refresh bool) Overview {
	e.cacheMu.Lock()
	if !refresh && e.cached != nil && e.Now().Sub(e.cacheAt) < CacheTTL {
		o := *e.cached
		e.cacheMu.Unlock()
		return o
	}
	e.cacheMu.Unlock()

	f := e.facts()
	o := Overview{Report: e.Checks.Evaluate(f), Disclaimer: Disclaimer}
	o.Managed = e.Backend.Managed()
	journal, _ := e.Journal.Load()
	for _, a := range e.Actions.All() {
		p := e.plan(a, f)
		title, desc := p.texts(a)
		info := ActionInfo{ID: a.ID, Title: title, Description: desc, Covers: a.Covers, Preselected: a.Preselected,
			MayBlock: a.MayBlock, Sticky: a.Sticky, Reversible: a.Reversible(), Changes: len(p.Changes), State: "available"}
		switch {
		case o.Managed != "":
			info.State, info.Reason = "refused", o.Managed
		case p.Refusal != "":
			info.State, info.Reason = "refused", p.Refusal
		case len(p.Changes) == 0:
			info.State, info.Reason = "done", "already in place"
		}
		info.Undoable = a.Reversible() && len(journal[a.ID]) > 0
		o.Actions = append(o.Actions, info)
	}
	e.cacheMu.Lock()
	e.cached, e.cacheAt = &o, e.Now()
	e.cacheMu.Unlock()
	return o
}

func (e *Engine) invalidate() {
	e.cacheMu.Lock()
	e.cached = nil
	e.cacheMu.Unlock()
}

// Preview returns what each named action would change right now. Unknown ids are an error.
func (e *Engine) Preview(ids []string) ([]Preview, error) {
	f := e.facts()
	managed := e.Backend.Managed()
	var out []Preview
	for _, id := range ids {
		a, ok := e.Actions.Get(id)
		if !ok {
			return nil, fmt.Errorf("unknown action %q", id)
		}
		p := e.plan(a, f)
		if managed != "" && p.Refusal == "" {
			p.Refusal, p.Changes = managed, nil
		}
		title, desc := p.texts(a)
		out = append(out, Preview{ID: a.ID, Title: title, Hash: p.Hash(), Changes: nz(p.Changes), Refusal: p.Refusal, Notes: p.Notes,
			NoOp: p.Refusal == "" && len(p.Changes) == 0, MayBlock: a.MayBlock, Sticky: a.Sticky, Reversible: a.Reversible(), Description: desc})
	}
	return out, nil
}

func nz(c []Change) []Change {
	if c == nil {
		return []Change{}
	}
	return c
}

// ApplyRequest names an action together with the hash of the preview the user confirmed
type ApplyRequest struct {
	ID   string `json:"id"`
	Hash string `json:"hash"`
}

// ErrNoConfirmation is returned when a request lacks the preview hash
var ErrNoConfirmation = errors.New("an action can only be applied together with the hash of its preview")

// Apply executes the named actions in registry order. Each action is all-or-nothing: if one of its changes fails
// the earlier changes of that action are rolled back. Actions are independent: one failing does not stop the others.
func (e *Engine) Apply(reqs []ApplyRequest, actor Actor) ([]ActionResult, error) {
	for _, r := range reqs {
		if _, ok := e.Actions.Get(r.ID); !ok {
			return nil, fmt.Errorf("unknown action %q", r.ID)
		}
		if r.Hash == "" {
			return nil, ErrNoConfirmation
		}
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	defer e.invalidate()

	want := map[string]string{}
	for _, r := range reqs {
		want[r.ID] = r.Hash
	}
	var results []ActionResult
	journal, _ := e.Journal.Load()
	for _, a := range e.Actions.All() {
		hash, ok := want[a.ID]
		if !ok {
			continue
		}
		res := ActionResult{ID: a.ID, Title: a.Title}
		f := e.facts() // fresh for every action: an earlier action may have changed the state
		p := e.plan(a, f)
		switch {
		case e.Backend.Managed() != "":
			res.Status, res.Error = "refused", e.Backend.Managed()
		case p.Refusal != "":
			res.Status, res.Error = "refused", p.Refusal
		case hash != p.Hash():
			res.Status, res.Error = "changed", "The settings changed since the preview. Preview again before applying."
		case len(p.Changes) == 0:
			res.Status = "nothing-to-do"
		default:
			var done []Change
			var failure error
			for _, c := range p.Changes {
				if err := e.Backend.Set(c.Key, c.To); err != nil {
					failure = fmt.Errorf("%s (%s): %w", c.Label, c.Target, err)
					break
				}
				done = append(done, c)
			}
			if failure != nil {
				res.Status, res.Error = "failed", failure.Error()
				for i := len(done) - 1; i >= 0; i-- {
					if err := e.Backend.Set(done[i].Key, done[i].Prev); err != nil {
						res.Error += "; rollback of " + done[i].Label + " failed: " + err.Error()
					} else {
						res.RolledBack = true
					}
				}
			} else {
				res.Status, res.Applied = "applied", done
				if a.Reversible() {
					journal[a.ID] = append(journal[a.ID], done...)
				}
			}
		}
		e.audit(actor, res)
		results = append(results, res)
	}
	e.Journal.Save(journal)
	return results, nil
}

func (e *Engine) audit(actor Actor, res ActionResult) {
	if e.Audit == nil {
		return
	}
	switch res.Status {
	case "applied":
		e.Audit(actor, "posture.apply", res.ID, describe(res.Applied))
	case "undone":
		e.Audit(actor, "posture.undo", res.ID, describe(res.Applied))
	case "nothing-to-do":
	default:
		e.Audit(actor, "posture.apply."+res.Status, res.ID, res.Error)
	}
}

// Undo restores the values an action replaced, but only those that still hold the value the action set.
// Settings changed by someone else since are left alone and reported as skipped.
func (e *Engine) Undo(id string, actor Actor) (ActionResult, error) {
	a, ok := e.Actions.Get(id)
	if !ok {
		return ActionResult{}, fmt.Errorf("unknown action %q", id)
	}
	if !a.Reversible() {
		return ActionResult{}, fmt.Errorf("%s cannot be undone: browsers keep what they learned", a.Title)
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	defer e.invalidate()
	res := ActionResult{ID: a.ID, Title: a.Title}
	if m := e.Backend.Managed(); m != "" {
		res.Status, res.Error = "refused", m
		return res, nil
	}
	journal, _ := e.Journal.Load()
	changes := journal[id]
	if len(changes) == 0 {
		res.Status = "nothing-to-do"
		return res, nil
	}
	for i := len(changes) - 1; i >= 0; i-- {
		c := changes[i]
		if cur, _ := e.Backend.Get(c.Key); cur != c.To {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%s) was changed since: now %q", c.Label, c.Target, cur))
			continue
		}
		if err := e.Backend.Set(c.Key, c.Prev); err != nil {
			res.Status, res.Error = "failed", fmt.Sprintf("%s (%s): %v", c.Label, c.Target, err)
			e.audit(actor, res)
			return res, nil
		}
		res.Applied = append(res.Applied, Change{Key: c.Key, Label: c.Label, Target: c.Target, From: c.To, To: c.From, Prev: c.To})
	}
	res.Status = "undone"
	delete(journal, id)
	e.Journal.Save(journal)
	e.audit(actor, res)
	return res, nil
}
