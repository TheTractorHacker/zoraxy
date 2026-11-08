package loadbalance

import "testing"

// Upstream #896: a rule with a single upstream must keep using it when the
// uptime monitor marks it offline (e.g. while the container is restarting),
// otherwise every request gets a 521 until the next monitor tick.
func TestFilterOfflineOriginsKeepsOnlyUpstream(t *testing.T) {
	m := &RouteManager{}
	only := []*Upstream{{OriginIpOrDomain: "10.0.0.1:80"}}
	m.NotifyHostOnlineState("10.0.0.1:80", false)
	if got := m.FilterOfflineOrigins(only, len(only), false); len(got) != 1 {
		t.Fatalf("single offline upstream was filtered out: %d", len(got))
	}

	two := []*Upstream{{OriginIpOrDomain: "10.0.0.1:80"}, {OriginIpOrDomain: "10.0.0.2:80"}}
	got := m.FilterOfflineOrigins(two, len(two), false)
	if len(got) != 1 || got[0].OriginIpOrDomain != "10.0.0.2:80" {
		t.Fatalf("offline upstream must still be filtered with multiple upstreams: %+v", got)
	}
	if got := m.FilterOfflineOrigins(two, len(two), true); len(got) != 2 {
		t.Fatalf("DisableAutoFallback must keep all upstreams: %d", len(got))
	}
}
