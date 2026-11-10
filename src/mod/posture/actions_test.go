package posture

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

/* ---- fakes ---- */

type fakeBackend struct {
	mu      sync.Mutex
	state   map[string]string
	sets    []string // "key=value" in order
	failKey string
	managed string
}

func newFake() *fakeBackend {
	return &fakeBackend{state: map[string]string{
		"waf.enabled": "off", "waf.mode": "detection_only", "waf.paranoia": "0", "waf.threshold": "0", "waf.cookies": "off",
		"autoban.enabled": "off", "autoban.detector.waf_block": "off", "autoban.detector.exploit_block": "off",
		"autoban.detector.bot_block": "off", "autoban.detector.login_fail": "off", "autoban.detector.not_found": "off",
		"https.redirect":       "off",
		"uptime.a.example.com": "off", "uptime.b.example.com": "off",
		"hsts.a.example.com": "0", "hsts.b.example.com": "0",
	}}
}

func (b *fakeBackend) Get(key string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.state[key]
	return v, ok
}
func (b *fakeBackend) Set(key, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if key == b.failKey {
		return errors.New("disk full")
	}
	if _, ok := b.state[key]; !ok {
		return fmt.Errorf("unknown setting %s", key)
	}
	b.state[key] = value
	b.sets = append(b.sets, key+"="+value)
	return nil
}
func (b *fakeBackend) Managed() string { return b.managed }

type auditLine struct {
	who                   Actor
	event, target, detail string
}

type env struct {
	b     *fakeBackend
	e     *Engine
	f     *Facts
	audit []auditLine
}

func newEnv() *env {
	v := &env{b: newFake(), f: healthy()}
	// a fresh instance: TLS with valid certs, no redirect, nothing else on
	v.f.Proxy.ForceHTTPSRedirect = false
	v.f.WAF = &WAFFacts{DefaultMode: "detection_only"}
	v.f.Abuse = &AbuseFacts{TotalDetectors: 9}
	e := NewEngine(func() *Facts { c := *v.f; return &c }, v.b)
	e.Now = func() time.Time { return t0 }
	e.Audit = func(who Actor, event, target, detail string) {
		v.audit = append(v.audit, auditLine{who, event, target, detail})
	}
	v.e = e
	return v
}

var admin = Actor{Name: "root", IP: "192.0.2.10"}

func previewHash(t *testing.T, v *env, id string) Preview {
	t.Helper()
	ps, err := v.e.Preview([]string{id})
	if err != nil || len(ps) != 1 {
		t.Fatal(err, ps)
	}
	return ps[0]
}

func applyOne(t *testing.T, v *env, id string) ActionResult {
	t.Helper()
	p := previewHash(t, v, id)
	rs, err := v.e.Apply([]ApplyRequest{{ID: id, Hash: p.Hash}}, admin)
	if err != nil || len(rs) != 1 {
		t.Fatal(err, rs)
	}
	return rs[0]
}

/* ---- tests ---- */

func TestWAFBaselineIsDetectionOnly(t *testing.T) {
	v := newEnv()
	p := previewHash(t, v, "waf.baseline")
	if p.Refusal != "" || len(p.Changes) != 3 {
		t.Fatalf("%+v", p)
	}
	r := applyOne(t, v, "waf.baseline")
	if r.Status != "applied" {
		t.Fatalf("%+v", r)
	}
	s := v.b.state
	if s["waf.enabled"] != "on" || s["waf.mode"] != "detection_only" || s["waf.paranoia"] != "1" || s["waf.threshold"] != "5" {
		t.Fatalf("state: %v", s)
	}
}

// Whatever the stored policy looks like, no action may leave the WAF able to reject requests that it could not reject before.
func TestWAFBaselineNeverSwitchesBlockingOn(t *testing.T) {
	for _, enabled := range []string{"on", "off"} {
		for _, mode := range []string{"off", "detection_only", "block"} {
			t.Run(enabled+"/"+mode, func(t *testing.T) {
				v := newEnv()
				v.b.state["waf.enabled"], v.b.state["waf.mode"] = enabled, mode
				wasBlocking := enabled == "on" && mode == "block"
				for _, id := range []string{"waf.baseline", "waf.cookies"} {
					applyOne(t, v, id)
				}
				nowBlocking := v.b.state["waf.enabled"] == "on" && v.b.state["waf.mode"] == "block"
				if nowBlocking && !wasBlocking {
					t.Fatalf("started blocking: %v", v.b.state)
				}
				if wasBlocking && v.b.state["waf.mode"] != "block" {
					t.Fatalf("an explicit block setting was weakened: %v", v.b.state)
				}
				if v.b.state["waf.enabled"] != "on" {
					t.Fatal("the WAF is not on after the baseline")
				}
			})
		}
	}
	// the stored block mode is explained in the preview
	v := newEnv()
	v.b.state["waf.mode"] = "block"
	if p := previewHash(t, v, "waf.baseline"); len(p.Notes) == 0 || !strings.Contains(p.Notes[0], "detection-only") {
		t.Fatalf("no explanation: %+v", p)
	}
}

func TestWAFBaselineLeavesOtherSettingsAlone(t *testing.T) {
	v := newEnv()
	v.b.state["waf.paranoia"], v.b.state["waf.threshold"] = "3", "9"
	applyOne(t, v, "waf.baseline")
	if v.b.state["waf.paranoia"] != "3" || v.b.state["waf.threshold"] != "9" {
		t.Fatalf("an administrator's values were overwritten: %v", v.b.state)
	}
	// rules that are off on purpose are reported and untouched
	v = newEnv()
	v.f.Proxy.Rules[0].WAFMode, v.f.Proxy.Rules[0].WAFOrigin = "off", "off"
	p := previewHash(t, v, "waf.baseline")
	found := false
	for _, n := range p.Notes {
		found = found || strings.Contains(n, "stay off")
	}
	if !found {
		t.Fatalf("%+v", p.Notes)
	}
	for _, c := range p.Changes {
		if strings.HasPrefix(c.Key, "rule.") {
			t.Fatal("the baseline touches single rules")
		}
	}
}

// What the preview shows is exactly what the apply changes, for every action and a spread of starting states.
func TestPreviewPredictsApplyExactly(t *testing.T) {
	for _, a := range DefaultActions.All() {
		v := newEnv()
		p := previewHash(t, v, a.ID)
		if p.Refusal != "" || p.NoOp {
			t.Fatalf("%s: preview refuses in the standard fixture: %+v", a.ID, p)
		}
		before := map[string]string{}
		for k, val := range v.b.state {
			before[k] = val
		}
		r := applyOne(t, v, a.ID)
		if r.Status != "applied" {
			t.Fatalf("%s: %+v", a.ID, r)
		}
		if !reflect.DeepEqual(p.Changes, r.Applied) {
			t.Fatalf("%s: preview\n%+v\napplied\n%+v", a.ID, p.Changes, r.Applied)
		}
		// nothing outside the previewed keys changed, and every previewed key has the previewed value
		want := map[string]string{}
		for k, val := range before {
			want[k] = val
		}
		for _, c := range p.Changes {
			if before[c.Key] != c.Prev && c.Prev != "" && c.Key != "waf.paranoia" && c.Key != "waf.threshold" {
				t.Errorf("%s: preview says %s was %q but it was %q", a.ID, c.Key, c.Prev, before[c.Key])
			}
			want[c.Key] = c.To
		}
		if !reflect.DeepEqual(want, v.b.state) {
			t.Fatalf("%s: state differs from the preview:\nwant %v\ngot  %v", a.ID, want, v.b.state)
		}
	}
}

func TestApplyTwiceChangesNothing(t *testing.T) {
	for _, a := range DefaultActions.All() {
		v := newEnv()
		applyOne(t, v, a.ID)
		n := len(v.b.sets)
		state := fmt.Sprint(v.b.state)
		r := applyOne(t, v, a.ID)
		if r.Status != "nothing-to-do" || len(r.Applied) != 0 {
			t.Fatalf("%s second apply: %+v", a.ID, r)
		}
		if len(v.b.sets) != n || fmt.Sprint(v.b.state) != state {
			t.Fatalf("%s: the second apply wrote settings", a.ID)
		}
		if p := previewHash(t, v, a.ID); !p.NoOp {
			t.Fatalf("%s: preview after apply should be a no-op: %+v", a.ID, p)
		}
	}
}

func TestApplyNeedsThePreviewHash(t *testing.T) {
	v := newEnv()
	if _, err := v.e.Apply([]ApplyRequest{{ID: "waf.baseline"}}, admin); !errors.Is(err, ErrNoConfirmation) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.e.Apply([]ApplyRequest{{ID: "nope", Hash: "x"}}, admin); err == nil {
		t.Fatal("unknown action accepted")
	}
	if len(v.b.sets) != 0 {
		t.Fatal("something was written")
	}
	// the state changes after the preview: the apply is refused, nothing is written
	p := previewHash(t, v, "waf.baseline")
	v.b.state["waf.paranoia"] = "2"
	rs, _ := v.e.Apply([]ApplyRequest{{ID: "waf.baseline", Hash: p.Hash}}, admin)
	if rs[0].Status != "changed" || len(v.b.sets) != 0 {
		t.Fatalf("%+v sets=%v", rs[0], v.b.sets)
	}
}

func TestUndoRestoresPreviousState(t *testing.T) {
	v := newEnv()
	orig := map[string]string{}
	for k, val := range v.b.state {
		orig[k] = val
	}
	for _, id := range []string{"waf.baseline", "waf.cookies", "uptime.enable", "https.redirect", "autoban.enable"} {
		applyOne(t, v, id)
	}
	if reflect.DeepEqual(orig, v.b.state) {
		t.Fatal("nothing was applied")
	}
	for _, id := range []string{"autoban.enable", "https.redirect", "uptime.enable", "waf.cookies", "waf.baseline"} {
		r, err := v.e.Undo(id, admin)
		if err != nil || r.Status != "undone" {
			t.Fatalf("undo %s: %+v %v", id, r, err)
		}
	}
	if !reflect.DeepEqual(orig, v.b.state) {
		t.Fatalf("not restored:\nwant %v\ngot  %v", orig, v.b.state)
	}
	if r, _ := v.e.Undo("waf.baseline", admin); r.Status != "nothing-to-do" {
		t.Fatalf("a second undo: %+v", r)
	}
}

func TestUndoLeavesLaterChangesAlone(t *testing.T) {
	v := newEnv()
	applyOne(t, v, "waf.baseline")
	v.b.state["waf.paranoia"] = "3" // the administrator raised it afterwards
	r, _ := v.e.Undo("waf.baseline", admin)
	if v.b.state["waf.paranoia"] != "3" || len(r.Skipped) != 1 || v.b.state["waf.enabled"] != "off" {
		t.Fatalf("%+v %v", r, v.b.state)
	}
}

func TestHSTSCannotBeUndone(t *testing.T) {
	v := newEnv()
	applyOne(t, v, "hsts.enable")
	if _, err := v.e.Undo("hsts.enable", admin); err == nil {
		t.Fatal("HSTS undo was offered")
	}
	for _, a := range v.e.Overview(true).Actions {
		if a.ID == "hsts.enable" && (a.Reversible || a.Undoable || !a.Sticky) {
			t.Fatalf("%+v", a)
		}
	}
}

func TestRefusalsWhenPreconditionsFail(t *testing.T) {
	type tc struct {
		name, action string
		mutate       func(f *Facts)
		reason       string
	}
	cases := []tc{
		{"redirect: no certificates", "https.redirect", func(f *Facts) { f.Certs.Hosts = nil }, "no host names"},
		{"redirect: a host without certificate", "https.redirect", func(f *Facts) { f.Certs.Hosts[1].State = "fallback" }, "b.example.com (fallback)"},
		{"redirect: self-signed", "https.redirect", func(f *Facts) { f.Certs.Hosts[0].State = "selfsigned" }, "a.example.com (selfsigned)"},
		{"redirect: expired", "https.redirect", func(f *Facts) { f.Certs.Hosts[0].State = "expired" }, "expired"},
		{"redirect: wildcard host", "https.redirect", func(f *Facts) { f.Certs.Skipped = 1 }, "cannot be verified"},
		{"redirect: no tls", "https.redirect", func(f *Facts) { f.Proxy.UseTLS = false }, "does not serve TLS"},
		{"redirect: no port 80", "https.redirect", func(f *Facts) { f.Proxy.ListenOnPort80 = false }, "nothing to redirect"},
		{"redirect: certs unreadable", "https.redirect", func(f *Facts) { f.Certs = nil }, "could not be read"},
		{"hsts: no certificates", "hsts.enable", func(f *Facts) { f.Certs.Hosts = nil }, "no proxy rule qualifies"},
		{"hsts: expiring certificate", "hsts.enable", func(f *Facts) { f.Certs.Hosts[0].DaysLeft = 10; f.Certs.Hosts[1].DaysLeft = 10 }, "no proxy rule qualifies"},
		{"hsts: no tls", "hsts.enable", func(f *Facts) { f.Proxy.UseTLS = false }, "does not serve TLS"},
		{"waf: policy unreadable", "waf.baseline", func(f *Facts) { f.WAF = nil }, "could not be read"},
		{"autoban: unreadable", "autoban.enable", func(f *Facts) { f.Abuse = nil }, "could not be read"},
		{"uptime: rules unreadable", "uptime.enable", func(f *Facts) { f.Proxy = nil }, "could not be read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv()
			c.mutate(v.f)
			p := previewHash(t, v, c.action)
			if p.Refusal == "" || !strings.Contains(p.Refusal, c.reason) || len(p.Changes) != 0 {
				t.Fatalf("preview: %+v", p)
			}
			rs, err := v.e.Apply([]ApplyRequest{{ID: c.action, Hash: p.Hash}}, admin)
			if err != nil || rs[0].Status != "refused" || len(v.b.sets) != 0 {
				t.Fatalf("%+v %v sets=%v", rs, err, v.b.sets)
			}
			if len(v.audit) != 1 || v.audit[0].event != "posture.apply.refused" {
				t.Fatalf("a refusal must be audited: %+v", v.audit)
			}
		})
	}
}

func TestHSTSOnlyForQualifyingRules(t *testing.T) {
	v := newEnv()
	v.f.Certs.Hosts[1].DaysLeft = 12 // b is about to expire
	p := previewHash(t, v, "hsts.enable")
	if len(p.Changes) != 1 || p.Changes[0].Target != "a.example.com" || p.Changes[0].To != "31536000" {
		t.Fatalf("%+v", p)
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "b.example.com") {
		t.Fatalf("the skipped rule is not explained: %v", p.Notes)
	}
	if !p.Sticky || p.Reversible {
		t.Fatal("HSTS must be marked sticky")
	}
}

func TestRedirectOnlyWithValidCertificatesForEveryHost(t *testing.T) {
	v := newEnv()
	p := previewHash(t, v, "https.redirect")
	if len(p.Changes) != 1 || p.Changes[0].Key != "https.redirect" || p.Changes[0].To != "on" {
		t.Fatalf("%+v", p)
	}
}

func TestFailureRollsTheActionBack(t *testing.T) {
	v := newEnv()
	v.b.failKey = "waf.threshold" // third change of waf.baseline
	p := previewHash(t, v, "waf.baseline")
	rs, _ := v.e.Apply([]ApplyRequest{{ID: "waf.baseline", Hash: p.Hash}}, admin)
	r := rs[0]
	if r.Status != "failed" || !r.RolledBack || !strings.Contains(r.Error, "disk full") {
		t.Fatalf("%+v", r)
	}
	if v.b.state["waf.enabled"] != "off" || v.b.state["waf.paranoia"] != "0" {
		t.Fatalf("the earlier changes were not rolled back: %v", v.b.state)
	}
	if len(v.audit) != 1 || v.audit[0].event != "posture.apply.failed" {
		t.Fatalf("%+v", v.audit)
	}
	// a failing action does not stop the others
	v = newEnv()
	v.b.failKey = "waf.enabled"
	ps, _ := v.e.Preview([]string{"waf.baseline", "uptime.enable"})
	rs, _ = v.e.Apply([]ApplyRequest{{ID: "waf.baseline", Hash: ps[0].Hash}, {ID: "uptime.enable", Hash: ps[1].Hash}}, admin)
	if rs[0].Status != "failed" || rs[1].Status != "applied" {
		t.Fatalf("%+v", rs)
	}
}

func TestAuditEntries(t *testing.T) {
	v := newEnv()
	applyOne(t, v, "waf.baseline")
	applyOne(t, v, "waf.baseline") // nothing to do: not audited
	if len(v.audit) != 1 {
		t.Fatalf("%+v", v.audit)
	}
	a := v.audit[0]
	if a.event != "posture.apply" || a.target != "waf.baseline" || a.who != admin || !strings.Contains(a.detail, "WAF master switch") || !strings.Contains(a.detail, "off -> on") {
		t.Fatalf("%+v", a)
	}
	if _, err := v.e.Undo("waf.baseline", admin); err != nil {
		t.Fatal(err)
	}
	if last := v.audit[len(v.audit)-1]; last.event != "posture.undo" || last.target != "waf.baseline" {
		t.Fatalf("%+v", last)
	}
	// previews are not audited
	n := len(v.audit)
	previewHash(t, v, "uptime.enable")
	v.e.Overview(true)
	if len(v.audit) != n {
		t.Fatal("a read was audited")
	}
}

func TestManagedNodeRefusesEverything(t *testing.T) {
	v := newEnv()
	v.b.managed = "This node is a cluster follower"
	for _, a := range DefaultActions.All() {
		p := previewHash(t, v, a.ID)
		if p.Refusal == "" {
			t.Fatalf("%s: previewed as available on a managed node", a.ID)
		}
		rs, _ := v.e.Apply([]ApplyRequest{{ID: a.ID, Hash: p.Hash}}, admin)
		if rs[0].Status != "refused" {
			t.Fatalf("%+v", rs[0])
		}
	}
	if len(v.b.sets) != 0 {
		t.Fatal("a managed node was changed")
	}
	o := v.e.Overview(true)
	if o.Managed == "" {
		t.Fatal("overview does not say fixes are disabled")
	}
	for _, a := range o.Actions {
		if a.State != "refused" {
			t.Fatalf("%+v", a)
		}
	}
}

func TestReadsNeverWrite(t *testing.T) {
	v := newEnv()
	v.e.Overview(true)
	v.e.Overview(false)
	for _, a := range DefaultActions.All() {
		previewHash(t, v, a.ID)
	}
	if len(v.b.sets) != 0 || len(v.audit) != 0 {
		t.Fatalf("a read changed something: %v %v", v.b.sets, v.audit)
	}
}

func TestOverviewActionStates(t *testing.T) {
	v := newEnv()
	states := func() map[string]ActionInfo {
		m := map[string]ActionInfo{}
		for _, a := range v.e.Overview(true).Actions {
			m[a.ID] = a
		}
		return m
	}
	s := states()
	for id, a := range s {
		if a.State != "available" || a.Changes == 0 {
			t.Errorf("%s: %+v", id, a)
		}
	}
	applyOne(t, v, "waf.baseline")
	s = states()
	if s["waf.baseline"].State != "done" || !s["waf.baseline"].Undoable || s["waf.cookies"].State != "available" {
		t.Fatalf("%+v", s["waf.baseline"])
	}
	v.f.Certs.Hosts = nil
	if s = states(); s["https.redirect"].State != "refused" || s["https.redirect"].Reason == "" {
		t.Fatalf("%+v", s["https.redirect"])
	}
}

func TestOverviewIsCachedBriefly(t *testing.T) {
	v := newEnv()
	calls := 0
	v.e.Collect = func() *Facts { calls++; return healthy() }
	now := t0
	v.e.Now = func() time.Time { return now }
	v.e.Overview(false)
	v.e.Overview(false)
	if calls != 1 {
		t.Fatalf("collected %d times", calls)
	}
	v.e.Overview(true)
	now = now.Add(CacheTTL + time.Second)
	v.e.Overview(false)
	if calls != 3 {
		t.Fatalf("collected %d times", calls)
	}
}

func TestRecommendedSelectionIsSafe(t *testing.T) {
	for _, a := range DefaultActions.All() {
		if a.Preselected && (a.MayBlock || a.Sticky) {
			t.Errorf("%s is preselected but can block traffic or is sticky", a.ID)
		}
	}
	ab, _ := DefaultActions.Get("autoban.enable")
	hs, _ := DefaultActions.Get("hsts.enable")
	if !ab.MayBlock || ab.Preselected || !hs.Sticky || hs.Preselected {
		t.Fatal("auto-ban and HSTS must be opt-in")
	}
	r := NewActionRegistry()
	plan := func(f *Facts, b Backend) Plan { return Plan{} }
	if r.Register(Action{ID: "x", Title: "x", Plan: plan, Preselected: true, MayBlock: true}) == nil {
		t.Fatal("a preselected blocking action was accepted")
	}
	if r.Register(Action{ID: "y", Title: "y", Plan: plan}) != nil || r.Register(Action{ID: "y", Title: "y", Plan: plan}) == nil {
		t.Fatal("registry duplicate handling")
	}
}

func TestAutobanLeavesNoisyDetectorsOff(t *testing.T) {
	v := newEnv()
	applyOne(t, v, "autoban.enable")
	if v.b.state["autoban.enabled"] != "on" || v.b.state["autoban.detector.waf_block"] != "on" || v.b.state["autoban.detector.login_fail"] != "on" {
		t.Fatalf("%v", v.b.state)
	}
	if v.b.state["autoban.detector.not_found"] != "off" {
		t.Fatal("the 404 detector must stay off")
	}
}

func TestUptimeOnlyChangesRulesThatLackIt(t *testing.T) {
	v := newEnv()
	v.b.state["uptime.b.example.com"] = "on"
	p := previewHash(t, v, "uptime.enable")
	if len(p.Changes) != 1 || p.Changes[0].Target != "a.example.com" {
		t.Fatalf("%+v", p)
	}
}

/* ---- monitor ---- */

type memBaseline struct {
	b  Baseline
	ok bool
}

func (m *memBaseline) Load() (Baseline, bool) { return m.b, m.ok }
func (m *memBaseline) Save(b Baseline)        { m.b, m.ok = b, true }

func report(score int, failing ...string) Report {
	r := Report{Score: Score{Value: score, Label: "Fair"}}
	for _, id := range failing {
		r.Checks = append(r.Checks, CheckResult{ID: id, Title: "title " + id, Status: StatusFail})
	}
	return r
}

func TestMonitorNotifiesOnDropOrNewFailure(t *testing.T) {
	st := &memBaseline{}
	now := t0
	var sent []string
	m := &Monitor{Store: st, Now: func() time.Time { return now }, Emit: func(s, d string) { sent = append(sent, s+" / "+d) }}

	if m.Observe(report(80, "a")) || len(sent) != 0 || !st.ok {
		t.Fatal("the first observation only records the baseline")
	}
	if m.Observe(report(75, "a")) {
		t.Fatal("a small decline notified")
	}
	if !m.Observe(report(60, "a")) || len(sent) != 1 || !strings.Contains(sent[0], "fell from 80 to 60") {
		t.Fatalf("a 20 point drop did not notify: %v", sent)
	}
	now = now.Add(time.Hour)
	if m.Observe(report(40, "a", "b")) || len(sent) != 1 {
		t.Fatal("the rate limit was ignored")
	}
	now = now.Add(MinGap)
	if !m.Observe(report(60, "a", "b")) || !strings.Contains(sent[1], "newly failing: title b") {
		t.Fatalf("a new failure after the gap did not notify: %v", sent)
	}
	// improvement moves the baseline up, so a later fall is measured from the best state
	now = now.Add(MinGap)
	m.Observe(report(95))
	if st.b.Score != 95 || len(st.b.Failing) != 0 {
		t.Fatalf("%+v", st.b)
	}
	now = now.Add(MinGap)
	if !m.Observe(report(80)) {
		t.Fatal("95 -> 80 should notify")
	}
}

func TestMonitorSlowSlideAddsUp(t *testing.T) {
	st := &memBaseline{}
	now := t0
	n := 0
	m := &Monitor{Store: st, Now: func() time.Time { return now }, Emit: func(string, string) { n++ }}
	m.Observe(report(90))
	for _, s := range []int{86, 83, 80} {
		now = now.Add(time.Hour)
		m.Observe(report(s))
	}
	if n != 1 {
		t.Fatalf("notifications: %d", n)
	}
}
