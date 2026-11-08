package access

import "testing"

// The access UI documents which ranges "Enable LAN and Loopback" covers (upstream #1087). Pin that list:
// 100.64.0.0/10 (CarrierNAT, Tailscale) is deliberately NOT part of it; if this changes, update the help
// text in web/components/access.html and docs/guides/real-client-ip-cloudflare.md.
func TestIsPrivateIPRangeMatchesDocumentedList(t *testing.T) {
	c := &Controller{}
	for _, ip := range []string{"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.1.1", "127.0.0.1", "::1", "fd00::1", "fe80::1"} {
		if !c.IsPrivateIPRange(ip) {
			t.Errorf("%s must count as LAN", ip)
		}
	}
	for _, ip := range []string{"100.64.0.1", "100.67.181.105", "100.127.255.255", "8.8.8.8", "172.32.0.1", "2a00:20::1"} {
		if c.IsPrivateIPRange(ip) {
			t.Errorf("%s must not count as LAN", ip)
		}
	}
}
