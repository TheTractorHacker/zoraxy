package ruleset

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/*
	engine.go

	The rule engine: the stored rule sets (global + one per proxy rule), the compiled snapshot the request
	path reads, per rule counters and the management operations behind the API.

	Concurrency: the request path does one atomic pointer load and only reads the immutable snapshot.
	Every change builds a complete new snapshot (all expressions are compiled again, which costs
	microseconds per rule), writes the affected file atomically and swaps the pointer, so a request never
	sees a half applied change and an invalid change is rejected before anything is written.
*/

const (
	MaxRulesPerSet = 500
	MaxRulesTotal  = 5000
	MaxSites       = 1000
	MaxNameLen     = 80
	MaxDescLen     = 500

	// DefaultSiteKey is the key the default site (root endpoint) uses in the API and in file names
	DefaultSiteKey = "_default_site"
)

// Rule is one WHEN expression THEN action
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	DryRun      bool   `json:"dry_run"` // log-only: matches are counted and recorded, the action is never performed
	Expression  string `json:"expression"`
	Action      Action `json:"action"`
	Created     int64  `json:"created"`
	Updated     int64  `json:"updated"`
}

// RuleInput is what the API accepts to create or replace a rule
type RuleInput struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     *bool     `json:"enabled"`
	DryRun      *bool     `json:"dry_run"`
	Expression  string    `json:"expression"`
	Tree        *TreeNode `json:"tree"`
	Action      Action    `json:"action"`
}

type state struct {
	global []Rule
	sites  map[string][]Rule
	lists  []*List
}

func (s *state) clone() *state {
	c := &state{global: append([]Rule(nil), s.global...), sites: map[string][]Rule{}, lists: append([]*List(nil), s.lists...)}
	for k, v := range s.sites {
		c.sites[k] = append([]Rule(nil), v...)
	}
	return c
}

func (s *state) put(site string, rules []Rule) {
	if site == "" {
		s.global = rules
		return
	}
	if len(rules) == 0 {
		delete(s.sites, site)
		return
	}
	s.sites[site] = rules
}

func (s *state) get(site string) []Rule {
	if site == "" {
		return s.global
	}
	return s.sites[site]
}

// compiledRule is a rule ready to run
type compiledRule struct {
	Rule
	site   string // "" = global
	expr   *Expr
	stats  *ruleStats
	err    string // why the rule is not active (invalid after a list change, bad file ...)
	warns  []string
	fields []string
}

type compiledSet struct{ rules []*compiledRule }

type snapshot struct {
	global       *compiledSet
	sites        map[string]*compiledSet
	lists        map[string]*List
	byKey        map[string]*compiledRule // site + "\x00" + id, every rule including disabled / broken
	active       int                      // enabled and valid rules
	hasChallenge bool
	challengeTTL int // minutes, the longest ttl_minutes of an enabled challenge rule
}

// Engine holds the rule sets
type Engine struct {
	dir string

	mu    sync.Mutex // serialises changes
	st    *state
	snap  atomic.Pointer[snapshot]
	stats sync.Map // key -> *ruleStats
	recnt *recentRing

	// Country resolves an address to an ISO country code (set by the proxy; nil = unknown)
	Country func(ip string) string

	ruleBudget, reqBudget int // tests lower these
	LoadErrors            []string
}

// NewMemory creates an engine that keeps everything in memory (tests)
func NewMemory() *Engine { return newEngine("") }

func newEngine(dir string) *Engine {
	e := &Engine{dir: dir, st: &state{sites: map[string][]Rule{}}, recnt: &recentRing{}, ruleBudget: RuleBudget, reqBudget: RequestBudget}
	e.snap.Store(e.build(e.st))
	return e
}

// Active is the whole cost of the feature on the request path when no rule exists: one atomic load
func (e *Engine) Active() bool {
	if e == nil {
		return false
	}
	s := e.snap.Load()
	return s != nil && s.active > 0
}

// NeedsChallengeEndpoints reports whether an enabled rule can serve a challenge (so the CAPTCHA
// verification paths have to be answered before the rules run)
func (e *Engine) NeedsChallengeEndpoints() bool {
	s := e.snap.Load()
	return s != nil && s.hasChallenge
}

// ChallengeTTLMinutes is how long a solved challenge is remembered (the longest ttl of the challenge rules)
func (e *Engine) ChallengeTTLMinutes() int {
	if s := e.snap.Load(); s != nil && s.challengeTTL > 0 {
		return s.challengeTTL
	}
	return 30
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "r_" + hex.EncodeToString(b)
}

func statKey(site, id string) string { return site + "\x00" + id }

func (e *Engine) statsFor(site, id string) *ruleStats {
	k := statKey(site, id)
	if v, ok := e.stats.Load(k); ok {
		return v.(*ruleStats)
	}
	v, _ := e.stats.LoadOrStore(k, &ruleStats{})
	return v.(*ruleStats)
}

// compileRule parses, links and analyses one rule
func compileRule(r Rule, lists map[string]*List) (*Expr, *Error, error) {
	if err := r.Action.Validate(); err != nil {
		return nil, nil, err
	}
	x, perr := Parse(r.Expression)
	if perr != nil {
		return nil, perr, nil
	}
	if perr := x.Link(lists); perr != nil {
		return nil, perr, nil
	}
	return x, nil, nil
}

// build compiles a state into a snapshot. Rules that fail to compile stay in the state (so the admin can
// fix them) but are inactive and carry the error.
func (e *Engine) build(st *state) *snapshot {
	s := &snapshot{sites: map[string]*compiledSet{}, lists: map[string]*List{}, byKey: map[string]*compiledRule{}}
	for _, l := range st.lists {
		s.lists[l.Name] = l
	}
	keep := map[string]bool{}
	comp := func(site string, rules []Rule) *compiledSet {
		cs := &compiledSet{}
		for _, r := range rules {
			c := &compiledRule{Rule: r, site: site, stats: e.statsFor(site, r.ID)}
			keep[statKey(site, r.ID)] = true
			x, perr, aerr := compileRule(r, s.lists)
			switch {
			case aerr != nil:
				c.err = aerr.Error()
			case perr != nil:
				c.err = perr.Error()
			default:
				c.expr, c.warns, c.fields = x, x.Warnings, x.Fields
			}
			s.byKey[statKey(site, r.ID)] = c
			if r.Enabled && c.err == "" {
				cs.rules = append(cs.rules, c)
				s.active++
				if r.Action.Type == ActChallenge {
					s.hasChallenge = true
					ttl := r.Action.TTLMinutes
					if ttl == 0 {
						ttl = 30
					}
					if ttl > s.challengeTTL {
						s.challengeTTL = ttl
					}
				}
			}
		}
		return cs
	}
	s.global = comp("", st.global)
	for site, rules := range st.sites {
		s.sites[site] = comp(site, rules)
	}
	e.stats.Range(func(k, _ any) bool {
		if !keep[k.(string)] {
			e.stats.Delete(k)
		}
		return true
	})
	return s
}

// ---------------------------------------------------------------------
// request path

// Matched is a rule whose expression matched
type Matched struct {
	Rule
	Site string
}

// Run is one request's walk through the rules
type Run struct {
	e       *Engine
	env     *Env
	sets    [2]*compiledSet
	si, ri  int
	reqLeft int
	stopped bool
}

// Begin starts evaluating the global rules and then those of site. It returns nil when there is nothing to
// evaluate for this site.
func (e *Engine) Begin(env *Env, site string) *Run {
	s := e.snap.Load()
	if s == nil || s.active == 0 {
		return nil
	}
	r := &Run{e: e, env: env, reqLeft: e.reqBudget}
	n := 0
	if len(s.global.rules) > 0 {
		r.sets[n] = s.global
		n++
	}
	if cs := s.sites[site]; cs != nil && len(cs.rules) > 0 {
		r.sets[n] = cs
		n++
	}
	if n == 0 {
		return nil
	}
	return r
}

// Stop ends the evaluation: no later rule runs (allow, skip rules)
func (r *Run) Stop() { r.stopped = true }

// Next returns the next rule that matches, or nil. The hit is counted. Rules that fail or run out of budget
// do not match.
func (r *Run) Next() *Matched {
	for !r.stopped && r.si < len(r.sets) && r.sets[r.si] != nil {
		cs := r.sets[r.si]
		if r.ri >= len(cs.rules) {
			r.si++
			r.ri = 0
			continue
		}
		c := cs.rules[r.ri]
		r.ri++
		b := budget{left: r.e.ruleBudget}
		if b.left > r.reqLeft {
			b.left = r.reqLeft
		}
		start := b.left
		ok := evalExpr(c.expr.Root, r.env, &b, nil)
		r.reqLeft -= start - b.left
		if b.exceeded {
			c.stats.errs.Add(1)
			if r.reqLeft <= 0 {
				r.stopped = true
			}
			continue
		}
		if r.reqLeft <= 0 {
			r.stopped = true
		}
		if !ok {
			continue
		}
		now := time.Now()
		c.stats.hit(c.DryRun, now.Unix())
		r.e.recnt.add(RecentHit{Time: now.Unix(), Site: c.site, RuleID: c.ID, Rule: c.Name, Action: c.Action.Describe(), DryRun: c.DryRun, IP: r.env.ClientIP, Method: r.env.R.Method, Path: clip(r.env.normPath())})
		return &Matched{Rule: c.Rule, Site: c.site}
	}
	return nil
}

// ---------------------------------------------------------------------
// counters

type ruleStats struct {
	total, dry, errs atomic.Uint64
	last             atomic.Int64
	hours            [24]atomic.Uint64 // hour number << 32 | count
}

func (s *ruleStats) hit(dry bool, now int64) {
	if dry {
		s.dry.Add(1)
	} else {
		s.total.Add(1)
	}
	s.last.Store(now)
	h := uint64(now / 3600)
	slot := &s.hours[h%24]
	for {
		old := slot.Load()
		var nv uint64
		if old>>32 == h {
			if old&0xffffffff == 0xffffffff {
				return
			}
			nv = old + 1
		} else {
			nv = h<<32 | 1
		}
		if slot.CompareAndSwap(old, nv) {
			return
		}
	}
}

// Stats are the counters of one rule (since the proxy started)
type Stats struct {
	Hits    uint64     `json:"hits"`     // matches that acted
	DryRun  uint64     `json:"dry_run"`  // matches of the rule while it was log-only
	Errors  uint64     `json:"errors"`   // evaluations aborted by the budget
	LastHit int64      `json:"last_hit"` // unix seconds, 0 = never
	Last24h uint64     `json:"last_24h"`
	Hourly  [24]uint32 `json:"hourly"` // oldest first, the last entry is the current hour
}

func (s *ruleStats) view(now int64) Stats {
	v := Stats{Hits: s.total.Load(), DryRun: s.dry.Load(), Errors: s.errs.Load(), LastHit: s.last.Load()}
	h := uint64(now / 3600)
	for i := 0; i < 24; i++ {
		hr := h - uint64(23-i)
		w := s.hours[hr%24].Load()
		if w>>32 == hr {
			v.Hourly[i] = uint32(w & 0xffffffff)
			v.Last24h += w & 0xffffffff
		}
	}
	return v
}

// RecentHit is one entry of the bounded list of recent matches
type RecentHit struct {
	Time   int64  `json:"t"`
	Site   string `json:"site,omitempty"`
	RuleID string `json:"rule_id"`
	Rule   string `json:"rule"`
	Action string `json:"action"`
	DryRun bool   `json:"dry_run"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

const recentCap = 100

type recentRing struct {
	mu   sync.Mutex
	buf  [recentCap]RecentHit
	next int
	n    int
}

func (r *recentRing) add(h RecentHit) {
	r.mu.Lock()
	r.buf[r.next] = h
	r.next = (r.next + 1) % recentCap
	if r.n < recentCap {
		r.n++
	}
	r.mu.Unlock()
}

func (r *recentRing) list() []RecentHit {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RecentHit, 0, r.n)
	for i := 0; i < r.n; i++ {
		out = append(out, r.buf[(r.next-1-i+2*recentCap)%recentCap])
	}
	return out
}

// RecentHits returns the latest matches, newest first (memory only, bounded)
func (e *Engine) RecentHits() []RecentHit { return e.recnt.list() }

// ---------------------------------------------------------------------
// management

// RuleInfo is a rule with everything the UI shows
type RuleInfo struct {
	Rule
	Tree     *TreeNode `json:"tree,omitempty"`
	Fields   []string  `json:"fields,omitempty"`
	Warnings []string  `json:"warnings,omitempty"`
	Error    string    `json:"error,omitempty"` // set when the rule cannot run
	Stats    Stats     `json:"stats"`
	Position int       `json:"position"`
}

func (e *Engine) info(c *compiledRule, pos int) RuleInfo {
	ri := RuleInfo{Rule: c.Rule, Fields: c.fields, Warnings: c.warns, Error: c.err, Stats: c.stats.view(time.Now().Unix()), Position: pos}
	if c.expr != nil {
		ri.Tree = c.expr.Tree()
		ri.Expression = c.expr.Text()
	}
	return ri
}

// Sites lists the sites that have rules
func (e *Engine) Sites() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for k := range e.st.sites {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Rules lists one rule set in order
func (e *Engine) Rules(site string) []RuleInfo {
	e.mu.Lock()
	s := e.snap.Load()
	rules := append([]Rule(nil), e.st.get(site)...)
	e.mu.Unlock()
	out := make([]RuleInfo, 0, len(rules))
	for i, r := range rules {
		if c := s.byKey[statKey(site, r.ID)]; c != nil {
			out = append(out, e.info(c, i))
		}
	}
	return out
}

// Get returns one rule
func (e *Engine) Get(site, id string) (RuleInfo, bool) {
	for _, ri := range e.Rules(site) {
		if ri.ID == id {
			return ri, true
		}
	}
	return RuleInfo{}, false
}

// ErrNotFound is returned for an unknown rule / list
type ErrNotFound struct{ What string }

func (e ErrNotFound) Error() string { return e.What + " not found" }

// ValidationError is a rejected change (bad input), as opposed to a storage failure
type ValidationError struct {
	Msg string
	Err *Error
}

func (v ValidationError) Error() string { return v.Msg }

func badf(format string, a ...any) error { return ValidationError{Msg: fmt.Sprintf(format, a...)} }

func validSiteKey(site string) error {
	if len(site) > 253 || strings.ContainsAny(site, "\x00\r\n") {
		return badf("invalid site")
	}
	return nil
}

// ruleFromInput normalises and validates input into a Rule (without ID / times)
func (e *Engine) ruleFromInput(in RuleInput, lists map[string]*List) (Rule, error) {
	r := Rule{Name: strings.TrimSpace(in.Name), Description: strings.TrimSpace(in.Description), Action: in.Action}
	if r.Name == "" || len(r.Name) > MaxNameLen || strings.ContainsAny(r.Name, "\x00\r\n") {
		return r, badf("the rule needs a name of 1-%d characters", MaxNameLen)
	}
	if len(r.Description) > MaxDescLen || strings.ContainsRune(r.Description, 0) {
		return r, badf("the description is limited to %d characters", MaxDescLen)
	}
	if err := r.Action.Validate(); err != nil {
		return r, ValidationError{Msg: "action: " + err.Error()}
	}
	var x *Expr
	var perr *Error
	switch {
	case in.Expression != "" && in.Tree != nil:
		return r, badf("give either expression or tree, not both")
	case in.Expression != "":
		x, perr = Parse(in.Expression)
	case in.Tree != nil:
		x, perr = FromTree(in.Tree)
	default:
		return r, badf("the rule needs an expression or a tree")
	}
	if perr == nil {
		perr = x.Link(lists)
	}
	if perr != nil {
		return r, ValidationError{Msg: "expression: " + perr.Error(), Err: perr}
	}
	r.Expression = x.Text()
	return r, nil
}

func listMap(ls []*List) map[string]*List {
	m := map[string]*List{}
	for _, l := range ls {
		m[l.Name] = l
	}
	return m
}

func (e *Engine) totalRules(st *state) int {
	n := len(st.global)
	for _, v := range st.sites {
		n += len(v)
	}
	return n
}

// commit builds the snapshot for st, persists the changed scopes and swaps. Nothing changes on failure.
func (e *Engine) commit(st *state, scopes ...string) error {
	snap := e.build(st)
	if e.dir != "" {
		if err := e.save(st, scopes); err != nil {
			return err
		}
	}
	e.st = st
	e.snap.Store(snap)
	return nil
}

// Create adds a rule at pos (negative or beyond the end = last). Rules start log-only unless dry_run is
// explicitly false, so a new rule can be observed before it acts.
func (e *Engine) Create(site string, in RuleInput, pos int) (RuleInfo, error) {
	if err := validSiteKey(site); err != nil {
		return RuleInfo{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.st.clone()
	rules := st.get(site)
	if len(rules) >= MaxRulesPerSet {
		return RuleInfo{}, badf("a rule set holds at most %d rules", MaxRulesPerSet)
	}
	if e.totalRules(st) >= MaxRulesTotal {
		return RuleInfo{}, badf("at most %d rules in total", MaxRulesTotal)
	}
	if site != "" && st.sites[site] == nil && len(st.sites) >= MaxSites {
		return RuleInfo{}, badf("rules for at most %d sites", MaxSites)
	}
	r, err := e.ruleFromInput(in, listMap(st.lists))
	if err != nil {
		return RuleInfo{}, err
	}
	r.ID = newID()
	r.Created = time.Now().Unix()
	r.Updated = r.Created
	r.Enabled = in.Enabled == nil || *in.Enabled
	r.DryRun = in.DryRun == nil || *in.DryRun
	if pos < 0 || pos > len(rules) {
		pos = len(rules)
	}
	rules = append(rules[:pos:pos], append([]Rule{r}, rules[pos:]...)...)
	st.put(site, rules)
	if err := e.commit(st, scopeOf(site)); err != nil {
		return RuleInfo{}, err
	}
	return e.infoLocked(site, r.ID), nil
}

func (e *Engine) infoLocked(site, id string) RuleInfo {
	s := e.snap.Load()
	for i, r := range e.st.get(site) {
		if r.ID == id {
			return e.info(s.byKey[statKey(site, id)], i)
		}
	}
	return RuleInfo{}
}

func scopeOf(site string) string {
	if site == "" {
		return "global"
	}
	return "site:" + site
}

func indexOf(rules []Rule, id string) int {
	for i, r := range rules {
		if r.ID == id {
			return i
		}
	}
	return -1
}

// Update replaces a rule (the id and creation time stay). Omitted enabled / dry_run keep their value.
func (e *Engine) Update(site, id string, in RuleInput) (RuleInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.st.clone()
	rules := st.get(site)
	i := indexOf(rules, id)
	if i < 0 {
		return RuleInfo{}, ErrNotFound{"rule"}
	}
	r, err := e.ruleFromInput(in, listMap(st.lists))
	if err != nil {
		return RuleInfo{}, err
	}
	old := rules[i]
	r.ID, r.Created, r.Updated = old.ID, old.Created, time.Now().Unix()
	r.Enabled, r.DryRun = old.Enabled, old.DryRun
	if in.Enabled != nil {
		r.Enabled = *in.Enabled
	}
	if in.DryRun != nil {
		r.DryRun = *in.DryRun
	}
	rules[i] = r
	st.put(site, rules)
	if err := e.commit(st, scopeOf(site)); err != nil {
		return RuleInfo{}, err
	}
	return e.infoLocked(site, id), nil
}

// Delete removes a rule
func (e *Engine) Delete(site, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.st.clone()
	rules := st.get(site)
	i := indexOf(rules, id)
	if i < 0 {
		return ErrNotFound{"rule"}
	}
	rules = append(rules[:i:i], rules[i+1:]...)
	st.put(site, rules)
	return e.commit(st, scopeOf(site))
}

// SetEnabled switches a rule on or off
func (e *Engine) SetEnabled(site, id string, on bool) (RuleInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.st.clone()
	rules := st.get(site)
	i := indexOf(rules, id)
	if i < 0 {
		return RuleInfo{}, ErrNotFound{"rule"}
	}
	rules[i].Enabled = on
	rules[i].Updated = time.Now().Unix()
	st.put(site, rules)
	if err := e.commit(st, scopeOf(site)); err != nil {
		return RuleInfo{}, err
	}
	return e.infoLocked(site, id), nil
}

// SetDryRun switches a rule between log-only and acting
func (e *Engine) SetDryRun(site, id string, dry bool) (RuleInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.st.clone()
	rules := st.get(site)
	i := indexOf(rules, id)
	if i < 0 {
		return RuleInfo{}, ErrNotFound{"rule"}
	}
	rules[i].DryRun = dry
	rules[i].Updated = time.Now().Unix()
	st.put(site, rules)
	if err := e.commit(st, scopeOf(site)); err != nil {
		return RuleInfo{}, err
	}
	return e.infoLocked(site, id), nil
}

// Reorder sets the order; ids must be exactly the ids of the set
func (e *Engine) Reorder(site string, ids []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.st.clone()
	rules := st.get(site)
	if len(ids) != len(rules) {
		return badf("the order must list every rule of the set exactly once")
	}
	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	out := make([]Rule, 0, len(ids))
	for _, id := range ids {
		r, ok := byID[id]
		if !ok {
			return badf("the order lists %q twice or it is not in the set", id)
		}
		delete(byID, id)
		out = append(out, r)
	}
	st.put(site, out)
	return e.commit(st, scopeOf(site))
}

// ---------------------------------------------------------------------
// lists

// Lists returns the named lists
func (e *Engine) Lists() []*List {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*List(nil), e.st.lists...)
}

// ListUsers returns "site:rule name" strings for the rules that reference a list
func (e *Engine) ListUsers(name string) []string {
	s := e.snap.Load()
	var out []string
	for _, c := range s.byKey {
		if c.expr == nil {
			// broken rules are reported through their text
			if strings.Contains(c.Expression, "$"+name) {
				out = append(out, scopeLabel(c.site)+": "+c.Name)
			}
			continue
		}
		for _, l := range c.expr.Lists {
			if l == name {
				out = append(out, scopeLabel(c.site)+": "+c.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

func scopeLabel(site string) string {
	if site == "" {
		return "global"
	}
	return site
}

// SaveList creates or replaces a list
func (e *Engine) SaveList(l List) (*List, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	l.Items = append([]string{}, l.Items...)
	for i := range l.Items {
		l.Items[i] = strings.TrimSpace(l.Items[i])
	}
	if err := l.Validate(); err != nil {
		return nil, ValidationError{Msg: err.Error()}
	}
	st := e.st.clone()
	replaced := false
	for i, o := range st.lists {
		if o.Name == l.Name {
			st.lists[i] = &l
			replaced = true
		}
	}
	if !replaced {
		if len(st.lists) >= MaxLists {
			return nil, badf("at most %d lists", MaxLists)
		}
		st.lists = append(st.lists, &l)
		sort.Slice(st.lists, func(i, j int) bool { return st.lists[i].Name < st.lists[j].Name })
	}
	if replaced {
		// a changed type must not break the rules that use the list
		snap := e.build(st)
		for _, c := range snap.byKey {
			if c.err != "" && c.Enabled && strings.Contains(c.Expression, "$"+l.Name) {
				return nil, badf("rule %q would stop working: %s", c.Name, c.err)
			}
		}
	}
	if err := e.commit(st, "lists"); err != nil {
		return nil, err
	}
	return &l, nil
}

// DeleteList removes a list that no rule uses
func (e *Engine) DeleteList(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.st.clone()
	idx := -1
	for i, l := range st.lists {
		if l.Name == name {
			idx = i
		}
	}
	if idx < 0 {
		return ErrNotFound{"list"}
	}
	if users := e.ListUsers(name); len(users) > 0 {
		return badf("the list is used by: %s", strings.Join(users, ", "))
	}
	st.lists = append(st.lists[:idx:idx], st.lists[idx+1:]...)
	return e.commit(st, "lists")
}

// ---------------------------------------------------------------------
// overview

// Overview is the data behind the rules page header
type Overview struct {
	Active      int `json:"active_rules"`
	Total       int `json:"total_rules"`
	DryRunRules int `json:"dry_run_rules"`
	Lists       int `json:"lists"`
	Sites       int `json:"sites_with_rules"`
}

// Overview counts the rules
func (e *Engine) Overview() Overview {
	s := e.snap.Load()
	o := Overview{Active: s.active, Lists: len(s.lists), Sites: len(s.sites)}
	for _, c := range s.byKey {
		o.Total++
		if c.Enabled && c.DryRun {
			o.DryRunRules++
		}
	}
	return o
}
