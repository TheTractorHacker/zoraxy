package waf

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAPILimitsDefaultsAndUnlimited(t *testing.T) {
	d := DefaultAPILimits()
	if d.MaxBodyBytes != 1<<20 || d.JSONMaxDepth != 20 || d.XMLMaxDepth != 20 || d.QueryMaxParams != 100 || d.URLMaxLen != 8192 || d.HeaderMaxCount != 100 {
		t.Fatalf("defaults %+v", d)
	}
	l := &APILimits{JSONMaxDepth: -1, JSONMaxKeys: 7, MaxBodyBytes: -1}
	e := l.Effective()
	if e.JSONMaxDepth != 0 || e.JSONMaxKeys != 7 || e.MaxBodyBytes != MaxAPIBodyBytes {
		t.Fatalf("effective %+v", e)
	}
	var nilLimits *APILimits
	if nilLimits.Effective().JSONMaxDepth != 20 {
		t.Fatal("nil limits")
	}
}

func TestAPIConfigValidate(t *testing.T) {
	bad := map[string]*APIConfig{
		"mode":             {Mode: "enforce"},
		"neg limit":        {Mode: "block", Limits: &APILimits{JSONMaxDepth: -2}},
		"huge depth":       {Mode: "block", Limits: &APILimits{JSONMaxDepth: 100000}},
		"huge body":        {Mode: "block", Limits: &APILimits{MaxBodyBytes: MaxAPIBodyBytes + 1}},
		"neg body":         {Mode: "block", Limits: &APILimits{MaxBodyBytes: -5}},
		"allow no slash":   {AllowList: []APIAllowRule{{Path: "api"}}},
		"allow space":      {AllowList: []APIAllowRule{{Path: "/a b"}}},
		"allow percent":    {AllowList: []APIAllowRule{{Path: "/a%2fb"}}},
		"allow quote":      {AllowList: []APIAllowRule{{Path: `/a"b`}}},
		"allow method":     {AllowList: []APIAllowRule{{Path: "/a", Methods: []string{"GE T"}}}},
		"allow method /":   {AllowList: []APIAllowRule{{Path: "/a", Methods: []string{"a/b"}}}},
		"allow type":       {AllowList: []APIAllowRule{{Path: "/a", ContentTypes: []string{"json"}}}},
		"allow type slash": {AllowList: []APIAllowRule{{Path: "/a", ContentTypes: []string{"a/b/c"}}}},
		"too many rules":   {AllowList: make([]APIAllowRule, MaxAPIAllowRules+1)},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	good := []*APIConfig{
		nil, {}, {Mode: "block"}, {Mode: "LOG"}, {Mode: "off"},
		{Mode: "block", Limits: &APILimits{JSONMaxDepth: 1000, MaxBodyBytes: MaxAPIBodyBytes, URLMaxLen: -1}},
		{AllowList: []APIAllowRule{{Path: "/api", Methods: []string{"GET", "post"}, ContentTypes: []string{"application/json", "text/*"}}, {Path: "/x*"}, {Path: "/"}}},
	}
	for i, c := range good {
		if err := c.Validate(); err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
	}
	// NewGuard rejects an invalid stored config as well
	if _, err := NewManager().NewGuard(&APIConfig{Mode: "block", Limits: &APILimits{JSONMaxDepth: -9}}); err == nil {
		t.Error("NewGuard accepted invalid limits")
	}
}

func TestMergeAPI(t *testing.T) {
	pol := &APIConfig{Mode: "log", Limits: &APILimits{JSONMaxDepth: 5}, AllowList: []APIAllowRule{{Path: "/a", Methods: []string{"GET"}}},
		OpenAPI: &OpenAPIConfig{Spec: "policy"}}
	prof := &APIConfig{Mode: "block", AllowList: []APIAllowRule{{Path: "/b"}}}
	ep := &APIConfig{Limits: &APILimits{JSONMaxDepth: 9}, AllowList: []APIAllowRule{{Path: "/a", Methods: []string{"POST"}}}}

	m := MergeAPI(pol, prof, ep)
	if m == nil || m.Mode != "block" {
		t.Fatalf("mode: %+v", m)
	}
	if m.Limits.JSONMaxDepth != 9 {
		t.Errorf("limits: %+v", m.Limits)
	}
	if len(m.AllowList) != 3 || m.AllowList[0].Path != "/a" || m.AllowList[2].Methods[0] != "POST" {
		t.Errorf("allow list: %+v", m.AllowList)
	}
	if m.OpenAPI == nil || m.OpenAPI.Spec != "policy" {
		t.Errorf("openapi: %+v", m.OpenAPI)
	}
	// the inputs are not modified or aliased
	m.Limits.JSONMaxDepth = 1
	m.OpenAPI.Spec = "changed"
	m.AllowList[0].Methods[0] = "X"
	if pol.Limits.JSONMaxDepth != 5 || ep.Limits.JSONMaxDepth != 9 || pol.OpenAPI.Spec != "policy" || pol.AllowList[0].Methods[0] != "GET" {
		t.Error("MergeAPI aliases its inputs")
	}
	// endpoint turns it off
	if MergeAPI(pol, prof, &APIConfig{Mode: "off"}) != nil {
		t.Error("off layer did not disable")
	}
	// nothing set
	if MergeAPI(nil, &APIConfig{}, nil) != nil || MergeAPI() != nil {
		t.Error("empty merge should be off")
	}
	// endpoint mode inherits when empty
	if m := MergeAPI(pol, nil, ep); m == nil || m.Mode != "log" {
		t.Errorf("inherit: %+v", m)
	}
	// own spec replaces the inherited one
	if m := MergeAPI(pol, &APIConfig{OpenAPI: &OpenAPIConfig{Spec: "own"}}); m.OpenAPI.Spec != "own" {
		t.Error("own spec")
	}
}

func TestResolveAPIBySource(t *testing.T) {
	polAPI := &APIConfig{Mode: "log", Limits: &APILimits{JSONMaxDepth: 5}}
	profAPI := &APIConfig{Mode: "block"}
	epAPI := &APIConfig{Limits: &APILimits{JSONMaxDepth: 8}}
	mk := func(enabled bool) *State {
		st, err := NewState(Policy{Enabled: enabled, DefaultMode: ModeBlock, API: polAPI},
			[]Profile{{Name: "Mine", Mode: ModeBlock, API: profAPI}})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	on, off := mk(true), mk(false)
	type c struct {
		name string
		st   *State
		set  Setting
		mode string // "" = nil
		dep  int
	}
	cases := []c{
		{"inherit, policy on", on, Setting{Source: SourceInherit}, "log", 5},
		{"inherit, policy off", off, Setting{Source: SourceInherit}, "", 0},
		{"inherit, policy off, own api", off, Setting{Source: SourceInherit, API: &APIConfig{Mode: "block"}}, "block", 0},
		{"inherit with endpoint layer", on, Setting{Source: SourceInherit, API: epAPI}, "log", 8},
		{"fixed mode", off, Setting{Source: ModeBlock}, "log", 5},
		{"profile", on, Setting{Source: SourceProfile, Profile: "mine"}, "block", 5},
		{"profile + endpoint", on, Setting{Source: SourceProfile, Profile: "Mine", API: epAPI}, "block", 8},
		{"missing profile degrades", on, Setting{Source: SourceProfile, Profile: "gone"}, "log", 5},
		{"source off", on, Setting{Source: SourceOff, API: &APIConfig{Mode: "block"}}, "", 0},
		{"custom ignores policy", on, Setting{Source: SourceCustom, Custom: &Config{Mode: ModeBlock}}, "", 0},
		{"custom with own api", on, Setting{Source: SourceCustom, Custom: &Config{Mode: ModeBlock}, API: &APIConfig{Mode: "block", Limits: epAPI.Limits}}, "block", 8},
		{"legacy custom", on, Setting{Custom: &Config{Mode: ModeBlock}}, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.st.ResolveAPI(tc.set)
			if tc.mode == "" {
				if got != nil {
					t.Fatalf("want nil, got %+v", got)
				}
				return
			}
			if got == nil || got.Mode != tc.mode {
				t.Fatalf("got %+v want mode %s", got, tc.mode)
			}
			if tc.dep != 0 && got.Limits.JSONMaxDepth != tc.dep {
				t.Fatalf("depth %d want %d", got.Limits.JSONMaxDepth, tc.dep)
			}
		})
	}
}

func TestAPIConfigDoesNotChangeWAFConfigHash(t *testing.T) {
	// API protection lives outside waf.Config, so a different API setup never recompiles the CRS.
	st1, _ := NewState(Policy{Enabled: true, DefaultMode: ModeBlock}, nil)
	st2, _ := NewState(Policy{Enabled: true, DefaultMode: ModeBlock, API: &APIConfig{Mode: "block"}}, nil)
	a := st1.Resolve(Setting{Source: SourceInherit}).Config
	b := st2.Resolve(Setting{Source: SourceInherit, API: &APIConfig{Mode: "log"}}).Config
	if a.Hash() != b.Hash() {
		t.Fatal("API settings changed the WAF config hash")
	}
}

func TestStateValidatesAPI(t *testing.T) {
	if _, err := NewState(Policy{DefaultMode: ModeBlock, API: &APIConfig{Mode: "nope"}}, nil); err == nil {
		t.Error("policy with bad API accepted")
	}
	if _, err := NewState(Policy{DefaultMode: ModeBlock}, []Profile{{Name: "X", API: &APIConfig{Limits: &APILimits{JSONMaxDepth: -4}}}}); err == nil {
		t.Error("profile with bad API accepted")
	}
	st := EmptyState()
	if err := st.ValidateSetting(Setting{Source: SourceInherit, API: &APIConfig{Mode: "bogus"}}); err == nil {
		t.Error("setting with bad API accepted")
	}
	if err := st.ValidateSetting(Setting{Source: SourceInherit, API: &APIConfig{Mode: "block"}}); err != nil {
		t.Error(err)
	}
}

func TestAPIConfigJSONBackwardCompatible(t *testing.T) {
	// A policy / profile saved before this feature has no API field and still loads
	var p Policy
	if err := json.Unmarshal([]byte(`{"Enabled":true,"DefaultMode":"block"}`), &p); err != nil || p.API != nil {
		t.Fatal(err, p.API)
	}
	js, _ := json.Marshal(Policy{DefaultMode: "block"})
	if strings.Contains(string(js), "API") {
		t.Errorf("empty API serialised: %s", js)
	}
	var s Setting
	in := Setting{API: &APIConfig{Mode: "block", AllowList: []APIAllowRule{{Path: "/a", Methods: []string{"GET"}}}, OpenAPI: &OpenAPIConfig{Spec: "x", BlockUnknown: true}}}
	js, _ = json.Marshal(in)
	if err := json.Unmarshal(js, &s); err != nil || s.API.OpenAPI.Spec != "x" || !s.API.OpenAPI.BlockUnknown || s.API.AllowList[0].Path != "/a" {
		t.Fatal(err, string(js))
	}
}

func TestNewGuardOffReturnsNil(t *testing.T) {
	m := NewManager()
	for _, c := range []*APIConfig{nil, {}, {Mode: "off"}, {Mode: "block"}} {
		g, err := m.NewGuard(c)
		if err != nil {
			t.Fatal(err)
		}
		if (c != nil && c.Mode == "block") != (g != nil) {
			t.Errorf("%+v -> %v", c, g)
		}
	}
	var nilGuard *Guard
	if nilGuard.Inspect(nil, nil, RequestInfo{}) {
		t.Error("nil guard blocked")
	}
}
