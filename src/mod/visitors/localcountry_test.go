package visitors

import "testing"

func TestNormalizeCountry(t *testing.T) {
	for in, want := range map[string]string{"": "", "us": "US", "AU": "AU", "Private": "LAN", "CarrierNAT": "LAN", "Loopback": "LAN", "LinkLocal": "LAN", "UniqueLocal": "LAN"} {
		if got := normalizeCountry(in); got != want {
			t.Errorf("normalizeCountry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsNonPublicIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"192.168.1.5": true, "10.1.0.25": true, "172.16.0.1": true, "127.0.0.1": true, "::1": true, "100.64.1.1": true,
		"169.254.1.1": true, "fe80::1%eth0": true, "fd00::1": true, "::ffff:192.168.1.5": true,
		"8.8.8.8": false, "3.224.220.101": false, "2a01:4f9:3070:124a::1": false, "::ffff:8.8.8.8": false, "not-an-ip": false,
	} {
		if got := isNonPublicIP(ip); got != want {
			t.Errorf("isNonPublicIP(%q) = %v, want %v", ip, got, want)
		}
	}
}
