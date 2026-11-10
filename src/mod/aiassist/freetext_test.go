package aiassist

import (
	"strings"
	"testing"
)

func TestFreeTextMasksHostsWhenPolicySet(t *testing.T) {
	in := "Rules: secret.corp.example.com, *.internal.example.org and v1.2 (default site shop.example.net)"
	out := testRedactor(Policy{MaskHosts: true}).FreeText(in, 300)
	for _, h := range []string{"secret.corp.example.com", "internal.example.org", "shop.example.net"} {
		if strings.Contains(out, h) {
			t.Fatalf("host %q leaked with MaskHosts: %s", h, out)
		}
	}
	if !strings.Contains(out, "host-") || !strings.Contains(out, "v1.2") {
		t.Fatalf("unexpected output: %s", out)
	}
	if o := testRedactor(Policy{}).FreeText(in, 300); !strings.Contains(o, "secret.corp.example.com") {
		t.Fatalf("hosts should stay when not masked: %s", o)
	}
}

func TestAuditPayloadMasksPostureHosts(t *testing.T) {
	s := newTestService(t, nil, nil)
	s.deps.Posture = FakePosture{List: []PostureItem{{ID: "x", Title: "Check secret.corp.example.com", Status: "warn", Severity: "low", Detail: "hosts: secret.corp.example.com"}}}
	o, _, err := s.auditOutbound(Settings{MaskHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(o.User, "secret.corp.example.com") {
		t.Fatalf("audit payload leaked host: %s", o.User)
	}
}
