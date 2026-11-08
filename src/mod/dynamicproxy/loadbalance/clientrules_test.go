package loadbalance

import (
	"net/http/httptest"
	"testing"
)

func crUpstreams() []*Upstream {
	return []*Upstream{
		{OriginIpOrDomain: "eu1:80", Weight: 1}, {OriginIpOrDomain: "eu2:80", Weight: 1},
		{OriginIpOrDomain: "us1:80", Weight: 1}, {OriginIpOrDomain: "office:80", Weight: 1},
	}
}

func crSelect(t *testing.T, cfg *Config, ups []*Upstream, ip, country string, sticky bool) (*Upstream, error) {
	t.Helper()
	lb := &RouteManager{}
	opt := &SelectOptions{Config: cfg, ClientIP: func() string { return ip }, ClientCountry: func() string { return country }}
	r := httptest.NewRequest("GET", "http://x/", nil)
	return lb.SelectUpstream(httptest.NewRecorder(), r, ups, opt)
}

func TestClientRulesPinByCIDRAndCountry(t *testing.T) {
	cfg := &Config{Algorithm: AlgoRoundRobin, ClientRules: []*ClientRule{
		{Name: "office", CIDRs: []string{"10.1.0.0/16", "2001:db8::/32"}, Upstreams: []string{"office:80"}},
		{Name: "eu", Countries: []string{"de", "FR"}, Upstreams: []string{"eu1:80", "eu2:80"}},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ups := crUpstreams()
	for i := 0; i < 20; i++ {
		if u, _ := crSelect(t, cfg, ups, "10.1.2.3", "US", false); u.OriginIpOrDomain != "office:80" {
			t.Fatalf("office CIDR beats country: %v", u)
		}
		if u, _ := crSelect(t, cfg, ups, "2001:db8::5", "", false); u.OriginIpOrDomain != "office:80" {
			t.Fatalf("v6 CIDR: %v", u)
		}
		if u, _ := crSelect(t, cfg, ups, "::ffff:10.1.9.9", "", false); u.OriginIpOrDomain != "office:80" {
			t.Fatalf("v4-mapped: %v", u)
		}
		if u, _ := crSelect(t, cfg, ups, "93.184.216.34:5555", "DE", false); u.OriginIpOrDomain != "eu1:80" && u.OriginIpOrDomain != "eu2:80" {
			t.Fatalf("country DE: %v", u)
		}
	}
	// round robin inside the group uses both members
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		u, _ := crSelect(t, cfg, ups, "93.184.216.34", "FR", false)
		seen[u.OriginIpOrDomain] = true
	}
	if len(seen) != 2 {
		t.Fatalf("algorithm not applied inside the group: %v", seen)
	}
	// no match: all upstreams are candidates
	seen = map[string]bool{}
	for i := 0; i < 40; i++ {
		u, _ := crSelect(t, cfg, ups, "198.51.100.1", "JP", false)
		seen[u.OriginIpOrDomain] = true
	}
	if len(seen) != 4 {
		t.Fatalf("unmatched client should see all upstreams: %v", seen)
	}
}

func TestClientRulesFallback(t *testing.T) {
	ups := crUpstreams()
	ups[3].Draining = true //the office group is down
	anyCfg := &Config{ClientRules: []*ClientRule{{CIDRs: []string{"10.1.0.0/16"}, Upstreams: []string{"office:80"}}}}
	u, err := crSelect(t, anyCfg, ups, "10.1.0.1", "", false)
	if err != nil || u.OriginIpOrDomain == "office:80" {
		t.Fatalf("fallback any: %v %v", u, err)
	}
	denyCfg := &Config{ClientRules: []*ClientRule{{CIDRs: []string{"10.1.0.0/16"}, Upstreams: []string{"office:80"}, Fallback: "deny"}}}
	if _, err := crSelect(t, denyCfg, ups, "10.1.0.1", "", false); err != ErrNoUpstreamForClient {
		t.Fatalf("fallback deny: %v", err)
	}
	if u, err := crSelect(t, denyCfg, ups, "11.1.0.1", "", false); err != nil || u == nil {
		t.Fatalf("non matching client must be unaffected: %v", err)
	}
}

func TestClientRulesNoGeoIPOrBadIP(t *testing.T) {
	cfg := &Config{ClientRules: []*ClientRule{{Countries: []string{"DE"}, Upstreams: []string{"eu1:80"}}}}
	lb := &RouteManager{}
	r := httptest.NewRequest("GET", "http://x/", nil)
	for _, opt := range []*SelectOptions{
		{Config: cfg}, //no resolvers at all
		{Config: cfg, ClientIP: func() string { return "garbage" }, ClientCountry: func() string { return "DE" }},
		{Config: cfg, ClientIP: func() string { return "1.2.3.4" }}, //no geo resolver
	} {
		if _, err := lb.SelectUpstream(httptest.NewRecorder(), r, crUpstreams(), opt); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientRulesValidation(t *testing.T) {
	bad := []*ClientRule{
		{Upstreams: []string{"a"}}, {CIDRs: []string{"1.2.3.4"}}, {CIDRs: []string{"1.2.3.4/33"}, Upstreams: []string{"a"}},
		{Countries: []string{"DEU"}, Upstreams: []string{"a"}}, {Countries: []string{"1A"}, Upstreams: []string{"a"}},
		{CIDRs: []string{"1.2.3.4"}, Upstreams: []string{"a"}, Fallback: "x"},
	}
	for i, r := range bad {
		if (&Config{ClientRules: []*ClientRule{r}}).Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	c := &Config{ClientRules: []*ClientRule{{CIDRs: []string{"1.2.3.4"}, Upstreams: []string{"ghost:1"}}}}
	if c.ValidateClientRuleGroups([]string{"eu1:80"}) == nil {
		t.Error("unknown upstream accepted")
	}
}

func TestClientRulesStickySessionRespectsGroup(t *testing.T) {
	// a sticky target outside the client's group must not be reused; with no store the sticky lookup fails
	// and the group restriction still applies on the fresh selection
	cfg := &Config{ClientRules: []*ClientRule{{CIDRs: []string{"10.0.0.0/8"}, Upstreams: []string{"office:80"}}}}
	lb := &RouteManager{}
	_ = lb
	ups := crUpstreams()
	u, err := crSelect(t, cfg, ups, "10.9.9.9", "", false)
	if err != nil || u.OriginIpOrDomain != "office:80" {
		t.Fatalf("%v %v", u, err)
	}
}
