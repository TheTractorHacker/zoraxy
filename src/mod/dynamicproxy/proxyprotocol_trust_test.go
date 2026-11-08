package dynamicproxy

import (
	"net"
	"testing"
)

// A PROXY header must only be believed when it comes from a load balancer: a trusted proxy, or a
// loopback / private / link-local peer. Any other peer could otherwise pick the client address that
// access lists, auto-ban and rate limits see. Found by the data-plane e2e suite (proxy_protocol).
func TestProxyProtocolSourceChecker(t *testing.T) {
	listed := map[string]bool{"203.0.113.9": true}
	check := proxyProtocolSourceChecker(func(ip string) bool { return listed[ip] })
	cases := map[string]bool{
		"127.0.0.1:1000":   true,
		"10.1.2.3:1000":    true,
		"172.17.0.2:1000":  true,
		"192.168.1.5:1000": true,
		"[::1]:1000":       true,
		"[fd00::5]:1000":   true,
		"203.0.113.9:1000": true,  // in the trusted proxy list
		"198.51.100.7:99":  false, // public, not listed
		"[2001:db8::1]:99": false,
	}
	for addr, want := range cases {
		host, port, _ := net.SplitHostPort(addr)
		_ = port
		tcp := &net.TCPAddr{IP: net.ParseIP(host), Port: 1000}
		got, err := check(tcp)
		if err != nil || got != want {
			t.Errorf("%s: trusted=%v err=%v, want %v", addr, got, err, want)
		}
	}
}
