package dynamicproxy

import "testing"

func TestPeerSet(t *testing.T) {
	router, sep, rule := newNonTLSTestRouter(t)
	//Even when the access rule trusts forwarded headers from this peer, the peer rule only looks at the socket
	rule.TrustProxyHeadersOnly = false
	sep.AllowedPeerCIDRs = []string{"203.0.113.0/24", " 2001:db8::/32 ", "192.0.2.77", ""}
	sep.initNetworkOptions()
	if sep.peerSetErr != nil {
		t.Fatal(sep.peerSetErr)
	}
	cases := []struct {
		name   string
		remote string
		hdr    map[string]string
		want   int
	}{
		{"peer in v4 CIDR", "203.0.113.9:4000", nil, 299},
		{"peer is the single IP", "192.0.2.77:4000", nil, 299},
		{"peer in v6 CIDR", "[2001:db8::1]:4000", nil, 299},
		{"v4 mapped v6 peer", "[::ffff:203.0.113.9]:4000", nil, 299},
		{"peer outside", "198.51.100.1:4000", nil, 403},
		{"neighbour of the single IP", "192.0.2.78:4000", nil, 403},
		{"outside peer spoofs X-Forwarded-For", "198.51.100.1:4000", map[string]string{"X-Forwarded-For": "203.0.113.9"}, 403},
		{"outside peer spoofs X-Real-IP / CF header / Forwarded", "198.51.100.1:4000", map[string]string{"X-Real-IP": "203.0.113.9", "CF-Connecting-IP": "203.0.113.9", "Forwarded": "for=203.0.113.9"}, 403},
		{"allowed peer forwarding an outside client is fine", "203.0.113.9:4000", map[string]string{"X-Forwarded-For": "198.51.100.1"}, 299},
		{"unparsable peer", "garbage", nil, 403},
		{"empty peer", "", nil, 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if w := serveRaw(router, sep, "GET", "/", c.remote, c.hdr); w.Code != c.want {
				t.Fatalf("got %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestPeerSet_OffByDefaultAndValidation(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.initNetworkOptions()
	if w := serveRaw(router, sep, "GET", "/", "198.51.100.1:1", nil); w.Code != 299 {
		t.Fatalf("no peer list = %d", w.Code)
	}
	for _, bad := range [][]string{{"nonsense"}, {"10.0.0.0/33"}, {"0.0.0.0/0"}, {"::/0"}, {"10.0.0.1", "300.0.0.1"}} {
		if err := ValidatePeerSet(bad); err == nil {
			t.Errorf("%v should be rejected", bad)
		}
	}
	if err := ValidatePeerSet([]string{"10.0.0.0/8", "fd00::/8", "1.2.3.4"}); err != nil {
		t.Errorf("valid list rejected: %v", err)
	}
	//Broken list that reached the runtime: fail closed
	sep.AllowedPeerCIDRs = []string{"nonsense"}
	sep.initNetworkOptions()
	if w := serveRaw(router, sep, "GET", "/", "198.51.100.1:1", nil); w.Code != 503 {
		t.Fatalf("invalid list = %d, want 503", w.Code)
	}
}
