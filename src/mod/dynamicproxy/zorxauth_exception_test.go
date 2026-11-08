package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Upstream #1165: bypass ZorxAuth for requests from a LAN subnet.
func TestZorxAuthExceptionByCIDR(t *testing.T) {
	rules := []*ZorxAuthExceptionRule{
		{RuleType: AuthExceptionType_CIDR, CIDR: "192.168.0.0/16"},
		{RuleType: AuthExceptionType_CIDR, CIDR: "fd00::/8"},
	}
	req := func(remote string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/dash", nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"LAN IPv4", req("192.168.1.20:5555", nil), true},
		{"LAN IPv6", req("[fd12::1]:5555", nil), true},
		{"public IPv4", req("203.0.113.9:5555", nil), false},
		{"public peer spoofing client IP headers", req("203.0.113.9:5555", map[string]string{"X-Forwarded-For": "192.168.1.20", "X-Real-Ip": "192.168.1.20", "CF-Connecting-IP": "192.168.1.20"}), false},
	}
	for _, c := range cases {
		if got := zorxAuthExceptionMatched(rules, c.r); got != c.want {
			t.Errorf("%s: matched=%v want %v", c.name, got, c.want)
		}
	}

	// With the explicit "trust proxy headers" switch, the forwarded client address is used instead.
	trusted := []*ZorxAuthExceptionRule{{RuleType: AuthExceptionType_CIDR, CIDR: "192.168.0.0/16", UseTrustedProxy: true}}
	if !zorxAuthExceptionMatched(trusted, req("10.0.0.2:1", map[string]string{"X-Real-Ip": "192.168.5.5"})) {
		t.Error("UseTrustedProxy rule must use the forwarded client IP")
	}
}
