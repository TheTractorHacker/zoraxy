package waf

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStateValidation(t *testing.T) {
	bad := []Policy{
		{DefaultMode: "sometimes"},
		{DefaultMode: ModeBlock, TrustedPaths: []TrustedPath{{Path: "nope"}}},
		{DefaultMode: ModeBlock, TrustedPaths: []TrustedPath{{Path: "/a%2e"}}},
		{DefaultMode: ModeBlock, AllowedIPs: []string{"300.1.1.1"}},
		{DefaultMode: ModeBlock, AllowedIPs: []string{"10.0.0.0/99"}},
		{DefaultMode: ModeBlock, ExcludedRuleIDs: []string{"abc"}},
		{DefaultMode: ModeBlock, ParanoiaLevel: 9},
		{DefaultMode: ModeBlock, CustomRules: "Include /etc/passwd"},
	}
	for i, p := range bad {
		if _, err := NewState(p, nil); err == nil {
			t.Errorf("policy %d should be rejected", i)
		}
	}
	for _, pr := range []Profile{
		{Name: ""}, {Name: "../x"}, {Name: "wordpress"}, {Name: "ok", Mode: "weird"}, {Name: "ok", CustomRules: "SecRuleEngine Off"},
	} {
		if _, err := NewState(DefaultPolicy(), []Profile{pr}); err == nil {
			t.Errorf("profile %+v should be rejected", pr)
		}
	}
	if _, err := NewState(DefaultPolicy(), []Profile{{Name: "a"}, {Name: "A"}}); err == nil {
		t.Error("duplicate profile names (case insensitive) accepted")
	}
}

func TestBuiltinProfiles(t *testing.T) {
	st := EmptyState()
	names := map[string]bool{}
	for _, p := range st.Profiles() {
		if !p.BuiltIn {
			t.Errorf("%s should be built-in", p.Name)
		}
		names[p.Name] = true
		cfg := st.Resolve(Setting{Source: SourceProfile, Profile: p.Name}).Config
		if cfg == nil {
			t.Fatalf("profile %s resolved to off", p.Name)
		}
		if err := Default.Validate(cfg); err != nil {
			t.Errorf("built-in profile %s does not compile: %v", p.Name, err)
		}
	}
	for _, want := range []string{"WordPress", "API-only", "Strict", "Learning"} {
		if !names[want] {
			t.Errorf("missing built-in profile %s", want)
		}
	}
	if _, ok := st.Profile("wordpress"); !ok {
		t.Error("profile lookup must be case insensitive")
	}
}

func TestResolveMissingProfileDegrades(t *testing.T) {
	st, _ := NewState(Policy{Enabled: true, DefaultMode: ModeBlock}, nil)
	res := st.Resolve(Setting{Source: SourceProfile, Profile: "gone"})
	if res.Warning == "" || res.Mode != ModeBlock || res.Source != SourceInherit {
		t.Fatalf("missing profile must fall back to the global default: %+v", res)
	}
	if err := st.ValidateSetting(Setting{Source: SourceProfile, Profile: "gone"}); err == nil {
		t.Fatal("saving a setting that names a missing profile must fail")
	}
	if err := st.ValidateSetting(Setting{Source: "bogus"}); err == nil {
		t.Fatal("unknown source must fail validation")
	}
}

func TestResolveProfileLayering(t *testing.T) {
	st, _ := NewState(
		Policy{Enabled: true, DefaultMode: ModeDetectionOnly, ParanoiaLevel: 2, InboundThreshold: 7, ExcludedRuleIDs: []string{"1"}, AllowEndpointOverride: true},
		[]Profile{{Name: "P", Mode: ModeBlock, InboundThreshold: 3, ExcludedRuleIDs: []string{"2"}}})
	res := st.Resolve(Setting{Source: SourceProfile, Profile: "P", Extra: &Overrides{ExcludedRuleIDs: []string{"3"}, ParanoiaLevel: 3}})
	c := res.Config
	if c.Mode != ModeBlock || c.InboundThreshold != 3 || c.ParanoiaLevel != 3 || strings.Join(c.ExcludedRuleIDs, ",") != "1,2,3" {
		t.Fatalf("unexpected layering: %+v", c)
	}
	again := st.Resolve(Setting{Source: SourceProfile, Profile: "P", Extra: &Overrides{ExcludedRuleIDs: []string{"3"}, ParanoiaLevel: 3}})
	if c.Hash() != again.Config.Hash() {
		t.Fatal("hash must be stable")
	}
	other := st.Resolve(Setting{Source: SourceProfile, Profile: "P"})
	if c.Hash() == other.Config.Hash() {
		t.Fatal("different effective configs must hash differently")
	}
}

func TestBypassReasonUnits(t *testing.T) {
	st, _ := NewState(Policy{TrustedPaths: []TrustedPath{{Host: "*.example.com", Path: "/ok/"}}, AllowedIPs: []string{"10.1.2.3", "2001:db8::/32"}}, nil)
	req := func(method, host, target string) string {
		r := httptest.NewRequest(method, "http://"+host+target, nil)
		return st.BypassReason(r, "198.51.100.1:1")
	}
	if req("GET", "a.example.com", "/ok/x") != "trusted-path" {
		t.Error("wildcard host should match")
	}
	if req("GET", "example.com", "/ok/x") != "" || req("GET", "evil.com", "/ok/x") != "" {
		t.Error("wildcard host must not match the apex or other domains")
	}
	if req("GET", "a.example.com", "/ok") != "" {
		t.Error("prefix /ok/ must not match /ok")
	}
	r := httptest.NewRequest("GET", "http://x.test/", nil)
	for ip, want := range map[string]string{"10.1.2.3:99": "allowed-ip", "10.1.2.3": "allowed-ip", "[2001:db8::5]:80": "allowed-ip", "10.1.2.4:1": "", "garbage": ""} {
		if got := st.BypassReason(r, ip); got != want {
			t.Errorf("ip %q: got %q want %q", ip, got, want)
		}
	}
	if (*State)(nil).BypassReason(r, "1.1.1.1") != "" {
		t.Error("nil state must not bypass")
	}
}

func TestRuleReference(t *testing.T) {
	ref := RuleReference()
	if len(ref) < 100 {
		t.Fatalf("expected a few hundred CRS rules, got %d", len(ref))
	}
	info, ok := LookupRule(942100)
	if !ok || info.Message == "" || !strings.Contains(strings.ToLower(info.Category), "sql") {
		t.Fatalf("rule 942100 not described: %+v", info)
	}
	for i := 1; i < len(ref); i++ {
		if ref[i].ID <= ref[i-1].ID {
			t.Fatal("reference must be sorted and unique")
		}
	}
}

func TestEventFilterSummaryAndHourly(t *testing.T) {
	s := newEventStore()
	now := time.Now()
	add := func(ep, ip, action string, age time.Duration, rule int) {
		s.add(Event{Time: now.Add(-age), Endpoint: ep, ClientIP: ip, Action: action, Rules: []RuleHit{{ID: rule}}})
	}
	add("a", "1.1.1.1", "blocked", time.Minute, 942100)
	add("a", "1.1.1.1", "detected", 2*time.Minute, 941100)
	add("b", "2.2.2.2", "blocked", 3*time.Hour, 942100)
	if got := s.query(EventFilter{Endpoint: "a"}); len(got) != 2 || got[0].Action != "detected" && got[0].Action != "blocked" {
		t.Errorf("endpoint filter wrong: %+v", got)
	}
	if len(s.query(EventFilter{RuleID: 942100})) != 2 || len(s.query(EventFilter{Action: "detected"})) != 1 || len(s.query(EventFilter{ClientIP: "2.2.2.2"})) != 1 {
		t.Error("filters wrong")
	}
	if len(s.query(EventFilter{Since: now.Add(-time.Hour)})) != 2 {
		t.Error("since filter wrong")
	}
	sum := s.summary(now.Add(-24*time.Hour), 5)
	if sum.Events != 3 || sum.Blocked != 2 || sum.TopRules[0].Key != "942100" || sum.TopClientIPs[0].Key != "1.1.1.1" {
		t.Errorf("summary wrong: %+v", sum)
	}
	var total uint64
	for _, h := range s.stats().PerHour {
		total += h.Total
	}
	if total != 3 {
		t.Errorf("hourly buckets lost events: %d", total)
	}
	for i := 0; i < maxHourBuckets+50; i++ {
		s.add(Event{Time: now.Add(-time.Duration(i+5) * time.Hour), Endpoint: "c", Action: "detected"})
	}
	if n := len(s.stats().PerHour); n > maxHourBuckets {
		t.Errorf("hour buckets unbounded: %d", n)
	}
}
