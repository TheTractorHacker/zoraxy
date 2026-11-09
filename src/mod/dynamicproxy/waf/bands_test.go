package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// probeRules add a deterministic anomaly score to requests carrying ?probe=N (phase 1, so they run before the
// blocking evaluation of the CRS in phase 2).
const probeRules = `
SecRule ARGS:probe "@streq 2" "id:1000101,phase:1,pass,log,msg:'band probe 2',severity:'NOTICE',setvar:'tx.inbound_anomaly_score_pl1=+2'"
SecRule ARGS:probe "@streq 3" "id:1000102,phase:1,pass,log,msg:'band probe 3',severity:'WARNING',setvar:'tx.inbound_anomaly_score_pl1=+3'"
SecRule ARGS:probe "@streq 4" "id:1000103,phase:1,pass,log,msg:'band probe 4',severity:'ERROR',setvar:'tx.inbound_anomaly_score_pl1=+4'"
`

type bandHarness struct {
	m          *Manager
	in         *Instance
	challenges int
	valid      bool
	provider   bool // OnChallenge wired (a CAPTCHA provider exists)
	upstream   int
}

func newBandHarness(t *testing.T, cfg Config) *bandHarness {
	t.Helper()
	cfg.CustomRules = probeRules
	m := NewManager()
	in, err := m.Get(&cfg)
	if err != nil {
		t.Fatalf("build waf: %v", err)
	}
	return &bandHarness{m: m, in: in, provider: true}
}

func (h *bandHarness) serve(method, target, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	info := RequestInfo{Endpoint: "test", ClientIP: "203.0.113.7",
		ChallengeValid: func(*http.Request) bool { return h.valid }}
	if h.provider {
		info.OnChallenge = func(w http.ResponseWriter, r *http.Request, txID string) {
			h.challenges++
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("challenge-page"))
		}
	}
	if !h.in.Inspect(rec, req, info) {
		h.upstream++
		rec.WriteHeader(200)
	}
	return rec
}

func (h *bandHarness) lastEvent(t *testing.T) Event {
	t.Helper()
	evs := h.m.RecentEvents(1, "")
	if len(evs) != 1 {
		t.Fatalf("expected an event, got %d", len(evs))
	}
	return evs[0]
}

const html = "text/html,application/xhtml+xml"

func TestBandBelowChallengePasses(t *testing.T) {
	h := newBandHarness(t, Config{Mode: ModeBlock, ChallengeThreshold: 3})
	if rec := h.serve("GET", "/?probe=2", html); rec.Code != 200 || h.challenges != 0 {
		t.Fatalf("score 2 must pass untouched, code=%d challenges=%d", rec.Code, h.challenges)
	}
	ev := h.lastEvent(t)
	if ev.Action != "detected" || ev.Score != 2 || ev.Band != "" {
		t.Errorf("event = %+v", ev)
	}
}

func TestBandChallengeAndBlock(t *testing.T) {
	h := newBandHarness(t, Config{Mode: ModeBlock, ChallengeThreshold: 3})

	// in the band: challenge page, 403 (the CAPTCHA page convention), never reaches the upstream
	rec := h.serve("GET", "/?probe=3", html)
	if rec.Code != 403 || rec.Body.String() != "challenge-page" || h.upstream != 0 {
		t.Fatalf("band request: code=%d body=%q upstream=%d", rec.Code, rec.Body.String(), h.upstream)
	}
	ev := h.lastEvent(t)
	if ev.Action != ActionChallenged || ev.Score != 3 || ev.Band != "challenge" || ev.WouldBlock {
		t.Errorf("challenged event = %+v", ev)
	}
	// score 4 is still the challenge band with the default block threshold of 5
	if rec := h.serve("GET", "/?probe=4", html); rec.Body.String() != "challenge-page" {
		t.Errorf("score 4 should be challenged, got %d", rec.Code)
	}

	// at the block threshold: plain 403 from the block path, not the challenge
	before := h.challenges
	rec = h.serve("GET", "/item?id=1%27%20OR%20%271%27%3D%271", html)
	if rec.Code != 403 || h.challenges != before {
		t.Fatalf("block band: code=%d challenges=%d->%d", rec.Code, before, h.challenges)
	}
	if ev := h.lastEvent(t); ev.Action != "blocked" || ev.Score < 5 {
		t.Errorf("blocked event = %+v", ev)
	}
}

func TestBandSolvedChallengePassesBandButNotBlock(t *testing.T) {
	h := newBandHarness(t, Config{Mode: ModeBlock, ChallengeThreshold: 3})
	h.valid = true
	if rec := h.serve("GET", "/?probe=3", html); rec.Code != 200 || h.challenges != 0 {
		t.Fatalf("valid cookie must pass the band: code=%d", rec.Code)
	}
	if ev := h.lastEvent(t); ev.Action != ActionChallengePassed || ev.Band != "challenge" {
		t.Errorf("event = %+v", ev)
	}
	// cookie or not, the block band stays blocked
	if rec := h.serve("GET", "/item?id=1%27%20OR%20%271%27%3D%271", html); rec.Code != 403 {
		t.Fatalf("a valid challenge cookie must not open the block band, got %d", rec.Code)
	}
	st := h.m.Stats()
	if st.Passed != 1 || st.Blocked != 1 || st.Challenged != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestBandFallsBackToBlock(t *testing.T) {
	// no CAPTCHA provider: fail closed
	h := newBandHarness(t, Config{Mode: ModeBlock, ChallengeThreshold: 3})
	h.provider = false
	if rec := h.serve("GET", "/?probe=3", html); rec.Code != 403 {
		t.Fatalf("no provider must block, got %d", rec.Code)
	}
	if ev := h.lastEvent(t); ev.Action != "blocked" || ev.Band != "challenge" {
		t.Errorf("event = %+v", ev)
	}

	// clients that cannot render a page are not challenged: block band logic
	h = newBandHarness(t, Config{Mode: ModeBlock, ChallengeThreshold: 3})
	for name, c := range map[string]struct{ method, accept string }{
		"json api":  {"GET", "application/json"},
		"no accept": {"GET", ""},
		"any":       {"GET", "*/*"},
		"post":      {"POST", html},
		"head":      {"HEAD", html},
	} {
		if rec := h.serve(c.method, "/?probe=3", c.accept); rec.Code != 403 || rec.Body.String() == "challenge-page" {
			t.Errorf("%s: must be blocked without a challenge, code=%d body=%q", name, rec.Code, rec.Body.String())
		}
	}
	if h.challenges != 0 {
		t.Errorf("non navigation clients were challenged %d times", h.challenges)
	}
	// fetch() from a page
	req := httptest.NewRequest("GET", "/?probe=3", nil)
	req.Header.Set("Accept", html)
	req.Header.Set("Sec-Fetch-Mode", "cors")
	if CanChallenge(req) {
		t.Error("fetch / XHR must not be challenged")
	}
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	if !CanChallenge(req) {
		t.Error("navigation must be challengeable")
	}
}

func TestBandDisabledBehavesAsBefore(t *testing.T) {
	h := newBandHarness(t, Config{Mode: ModeBlock})
	for _, probe := range []string{"2", "3", "4"} {
		if rec := h.serve("GET", "/?probe="+probe, html); rec.Code != 200 || h.challenges != 0 {
			t.Fatalf("probe %s with challenge off: code=%d", probe, rec.Code)
		}
		if ev := h.lastEvent(t); ev.Action != "detected" || ev.Band != "" {
			t.Errorf("event = %+v", ev)
		}
	}
	if rec := h.serve("GET", "/item?id=1%27%20OR%20%271%27%3D%271", html); rec.Code != 403 {
		t.Errorf("block threshold unchanged, got %d", rec.Code)
	}
}

func TestBandDetectionOnlyNeverActs(t *testing.T) {
	h := newBandHarness(t, Config{Mode: ModeDetectionOnly, ChallengeThreshold: 3})
	for _, target := range []string{"/?probe=3", "/item?id=1%27%20OR%20%271%27%3D%271"} {
		if rec := h.serve("GET", target, html); rec.Code != 200 || h.challenges != 0 {
			t.Fatalf("detection_only %s: code=%d challenges=%d", target, rec.Code, h.challenges)
		}
		if ev := h.lastEvent(t); ev.Action != "detected" || ev.Band != "" {
			t.Errorf("event = %+v", ev)
		}
	}
}

func TestBandConfigValidation(t *testing.T) {
	bad := []Config{
		{Mode: ModeBlock, ChallengeThreshold: 5},                          // == default block threshold
		{Mode: ModeBlock, ChallengeThreshold: 9, InboundThreshold: 8},     // above
		{Mode: ModeBlock, ChallengeThreshold: 8, InboundThreshold: 8},     // equal
		{Mode: ModeBlock, ChallengeThreshold: -1},                         // negative
		{Mode: ModeBlock, ChallengeThreshold: 3, ChallengeTTLMinutes: -5}, // negative ttl
		{Mode: ModeBlock, ChallengeThreshold: 3, ChallengeTTLMinutes: 1441},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("config %d (%+v) should be rejected", i, c)
		}
	}
	for _, c := range []Config{
		{Mode: ModeBlock},
		{Mode: ModeBlock, ChallengeThreshold: 4},
		{Mode: ModeBlock, ChallengeThreshold: 7, InboundThreshold: 8, ChallengeTTLMinutes: 1440},
		{Mode: ModeBlock, ChallengeThreshold: 1, ChallengeTTLMinutes: 1},
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("config %+v should be valid: %v", c, err)
		}
	}
	c := Config{Mode: ModeBlock, ChallengeThreshold: 3}
	if got := c.Normalize().ChallengeTTLMinutes; got != DefaultChallengeTTLMinutes {
		t.Errorf("default ttl = %d", got)
	}
	if _, err := NewManager().Get(&Config{Mode: ModeBlock, ChallengeThreshold: 6}); err == nil {
		t.Error("manager must refuse challenge >= block")
	}
}

func TestBandPolicyProfileOverrideMerge(t *testing.T) {
	pol := Policy{Enabled: true, DefaultMode: ModeBlock, InboundThreshold: 8, ChallengeThreshold: 4, ChallengeTTLMinutes: 30, AllowEndpointOverride: true}
	st, err := NewState(pol, []Profile{
		{Name: "inherit", Mode: ModeBlock},
		{Name: "own", Mode: ModeBlock, ChallengeThreshold: 6, ChallengeTTLMinutes: 120},
	})
	if err != nil {
		t.Fatal(err)
	}
	get := func(set Setting) Config {
		r := st.Resolve(set)
		if r.Config == nil {
			t.Fatalf("no config for %+v", set)
		}
		return *r.Config
	}
	if c := get(Setting{Source: SourceInherit}); c.ChallengeThreshold != 4 || c.ChallengeTTLMinutes != 30 {
		t.Errorf("inherit = %d/%d", c.ChallengeThreshold, c.ChallengeTTLMinutes)
	}
	if c := get(Setting{Source: SourceProfile, Profile: "inherit"}); c.ChallengeThreshold != 4 || c.ChallengeTTLMinutes != 30 {
		t.Errorf("profile 0 must inherit, got %d/%d", c.ChallengeThreshold, c.ChallengeTTLMinutes)
	}
	if c := get(Setting{Source: SourceProfile, Profile: "own"}); c.ChallengeThreshold != 6 || c.ChallengeTTLMinutes != 120 {
		t.Errorf("profile own = %d/%d", c.ChallengeThreshold, c.ChallengeTTLMinutes)
	}
	// endpoint override wins over the profile; 0 keeps the profile value
	c := get(Setting{Source: SourceProfile, Profile: "own", Extra: &Overrides{ChallengeThreshold: 3}})
	if c.ChallengeThreshold != 3 || c.ChallengeTTLMinutes != 120 {
		t.Errorf("override = %d/%d", c.ChallengeThreshold, c.ChallengeTTLMinutes)
	}
	// the endpoint override is not honoured without AllowEndpointOverride, same as paranoia level / threshold
	pol.AllowEndpointOverride = false
	st2, _ := NewState(pol, nil)
	set := Setting{Source: SourceInherit, Extra: &Overrides{ChallengeThreshold: 2, ChallengeTTLMinutes: 10}}
	if err := st2.ValidateSetting(set); err == nil {
		t.Error("override must be refused when the policy does not allow it")
	}
	r := st2.Resolve(set)
	if r.Config.ChallengeThreshold != 4 || r.Config.ChallengeTTLMinutes != 30 || !strings.Contains(r.Warning, "challenge override ignored") {
		t.Errorf("ignored override: %+v warning=%q", r.Config, r.Warning)
	}
	// an override that is not below the block threshold is refused on save and degrades (band off) at runtime
	bad := Setting{Source: SourceInherit, Extra: &Overrides{ChallengeThreshold: 8}}
	if err := st.ValidateSetting(bad); err == nil {
		t.Error("override >= block threshold must be refused")
	}
	if r := st.Resolve(bad); r.Config.ChallengeThreshold != 0 || r.Warning == "" {
		t.Errorf("degrade: %+v %q", r.Config, r.Warning)
	}
	if err := st.ValidateSetting(Setting{Source: SourceInherit, Extra: &Overrides{ChallengeThreshold: -1}}); err == nil {
		t.Error("negative override accepted")
	}
	// the merged Config is valid and compiles
	if err := NewManager().Validate(&c); err != nil {
		t.Errorf("merged config does not compile: %v", err)
	}
}

func TestBandPolicyAndProfileValidation(t *testing.T) {
	for i, p := range []Policy{
		{DefaultMode: ModeBlock, ChallengeThreshold: 5},
		{DefaultMode: ModeBlock, ChallengeThreshold: -2},
		{DefaultMode: ModeBlock, ChallengeThreshold: 2, ChallengeTTLMinutes: 5000},
		{DefaultMode: ModeBlock, InboundThreshold: 10, ChallengeThreshold: 10},
	} {
		if _, err := NewState(p, nil); err == nil {
			t.Errorf("policy %d should be rejected", i)
		}
	}
	pol := Policy{DefaultMode: ModeBlock, InboundThreshold: 10, ChallengeThreshold: 6}
	if _, err := NewState(pol, []Profile{{Name: "x", Mode: ModeBlock, ChallengeThreshold: -1}}); err == nil {
		t.Error("negative profile value accepted")
	}
	// profile that lowers the block threshold under the inherited challenge threshold
	if _, err := NewState(pol, []Profile{{Name: "x", Mode: ModeBlock, InboundThreshold: 5}}); err == nil {
		t.Error("profile with block 5 and inherited challenge 6 must be refused")
	}
	if _, err := NewState(pol, []Profile{{Name: "x", Mode: ModeBlock, InboundThreshold: 5, ChallengeThreshold: 3}}); err != nil {
		t.Errorf("consistent profile refused: %v", err)
	}
}

func TestBandEventFilterAndSummary(t *testing.T) {
	h := newBandHarness(t, Config{Mode: ModeBlock, ChallengeThreshold: 3})
	h.serve("GET", "/?probe=3", html)
	h.valid = true
	h.serve("GET", "/?probe=3", html)
	h.valid = false
	h.serve("GET", "/?probe=2", html)
	h.serve("GET", "/item?id=1%27%20OR%20%271%27%3D%271", html)
	for action, want := range map[string]int{ActionChallenged: 1, ActionChallengePassed: 1, "detected": 1, "blocked": 1} {
		if got := len(h.m.QueryEvents(EventFilter{Action: action})); got != want {
			t.Errorf("filter %s: %d events, want %d", action, got, want)
		}
	}
	sum := h.m.Summary(time.Time{}, 5)
	if sum.Blocked != 1 || sum.Challenged != 1 || sum.Passed != 1 || sum.Detected != 1 {
		t.Errorf("summary = %+v", sum)
	}
	st := h.m.Stats()
	if st.Total != 4 || st.Blocked != 1 || st.Challenged != 1 || st.Passed != 1 {
		t.Errorf("stats = %+v", st)
	}
}
