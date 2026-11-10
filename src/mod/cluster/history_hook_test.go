package cluster

import "testing"

func TestHubManagedReason(t *testing.T) {
	m := &Manager{}
	m.cfg.Role = RoleNode
	m.status.FleetScopes = []string{"proxy", "redirect"}
	m.status.Managed = map[string][]string{"proxy": {"proxy/hub.example.com.config"}}
	if m.HubManagedReason("proxy/hub.example.com.config") == "" {
		t.Fatal("hub published proxy file must be managed")
	}
	if m.HubManagedReason("proxy/local.example.com.config") != "" {
		t.Fatal("node local proxy file must not be managed")
	}
	if m.HubManagedReason("redirect/x.json") == "" {
		t.Fatal("whole-root scope must be managed")
	}
	if m.HubManagedReason("access/default.json") != "" {
		t.Fatal("unmanaged scope must not be managed")
	}
	m.cfg.Role = RoleStandalone
	if m.HubManagedReason("redirect/x.json") != "" {
		t.Fatal("standalone node manages nothing")
	}
	m.cfg.Role = RoleFollower
	if m.HubManagedReason("access/default.json") == "" {
		t.Fatal("follower synced root must be managed")
	}
	if m.HubManagedReason("botrules.json") != "" {
		t.Fatal("non synced file stays local")
	}
}
