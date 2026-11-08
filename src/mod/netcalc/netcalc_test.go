package netcalc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestIPv4(t *testing.T) {
	cases := []struct {
		in                                                        string
		network, broadcast, mask, wild, first, last, hosts, total string
		class, scope                                              string
		private                                                   bool
	}{
		{"192.168.1.10/24", "192.168.1.0", "192.168.1.255", "255.255.255.0", "0.0.0.255", "192.168.1.1", "192.168.1.254", "254", "256", "C", "private (RFC 1918)", true},
		{"192.168.1.10 255.255.255.0", "192.168.1.0", "192.168.1.255", "255.255.255.0", "0.0.0.255", "192.168.1.1", "192.168.1.254", "254", "256", "C", "private (RFC 1918)", true},
		{"10.1.2.3/255.0.0.0", "10.0.0.0", "10.255.255.255", "255.0.0.0", "0.255.255.255", "10.0.0.1", "10.255.255.254", "16777214", "16777216", "A", "private (RFC 1918)", true},
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255", "0.0.0.0", "255.255.255.255", "0.0.0.1", "255.255.255.254", "4294967294", "4294967296", "A", "this network (unspecified)", false},
		{"8.8.8.8/32", "8.8.8.8", "", "255.255.255.255", "0.0.0.0", "8.8.8.8", "8.8.8.8", "1", "1", "A", "public", false},
		{"8.8.8.8", "8.8.8.8", "", "255.255.255.255", "0.0.0.0", "8.8.8.8", "8.8.8.8", "1", "1", "A", "public", false},
		{"172.16.5.4/31", "172.16.5.4", "", "255.255.255.254", "0.0.0.1", "172.16.5.4", "172.16.5.5", "2", "2", "B", "private (RFC 1918)", true},
		{"172.16.5.5/31", "172.16.5.4", "", "255.255.255.254", "0.0.0.1", "172.16.5.4", "172.16.5.5", "2", "2", "B", "private (RFC 1918)", true},
		{"192.0.2.0/30", "192.0.2.0", "192.0.2.3", "255.255.255.252", "0.0.0.3", "192.0.2.1", "192.0.2.2", "2", "4", "C", "documentation (TEST-NET-1)", false},
		{"100.64.1.1/10", "100.64.0.0", "100.127.255.255", "255.192.0.0", "0.63.255.255", "100.64.0.1", "100.127.255.254", "4194302", "4194304", "A", "carrier-grade NAT (RFC 6598)", false},
		{"127.0.0.1/8", "127.0.0.0", "127.255.255.255", "255.0.0.0", "0.255.255.255", "127.0.0.1", "127.255.255.254", "16777214", "16777216", "A", "loopback", false},
		{"224.0.0.1/4", "224.0.0.0", "239.255.255.255", "240.0.0.0", "15.255.255.255", "224.0.0.1", "239.255.255.254", "268435454", "268435456", "D (multicast)", "multicast", false},
		{"255.255.255.255/32", "255.255.255.255", "", "255.255.255.255", "0.0.0.0", "255.255.255.255", "255.255.255.255", "1", "1", "E (reserved)", "limited broadcast", false},
		{"  169.254.1.1/16  ", "169.254.0.0", "169.254.255.255", "255.255.0.0", "0.0.255.255", "169.254.0.1", "169.254.255.254", "65534", "65536", "B", "link-local", false},
	}
	for _, c := range cases {
		r, err := Calculate(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		got := []string{r.Network, r.Broadcast, r.Netmask, r.Wildcard, r.FirstHost, r.LastHost, r.HostCount, r.AddressCount, r.Class, r.Scope}
		want := []string{c.network, c.broadcast, c.mask, c.wild, c.first, c.last, c.hosts, c.total, c.class, c.scope}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%q field %d: got %q want %q", c.in, i, got[i], want[i])
			}
		}
		if r.Private != c.private || r.Kind != "ipv4" {
			t.Errorf("%q: private=%v kind=%s", c.in, r.Private, r.Kind)
		}
	}
}

func TestIPv4Misc(t *testing.T) {
	r, _ := Calculate("192.168.1.10/24")
	if r.CIDR != "192.168.1.0/24" || r.ReverseDNS != "1.168.192.in-addr.arpa" || r.Binary != "11000000.10101000.00000001.00001010" {
		t.Errorf("unexpected: %+v", r)
	}
	r, _ = Calculate("10.0.0.1/0")
	if r.ReverseDNS != "in-addr.arpa" {
		t.Errorf("rev %s", r.ReverseDNS)
	}
	r, _ = Calculate("10.20.30.40/32")
	if r.ReverseDNS != "40.30.20.10.in-addr.arpa" {
		t.Errorf("rev %s", r.ReverseDNS)
	}
}

func TestInvalid(t *testing.T) {
	bad := []string{
		"", "   ", "abc", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.4/33", "1.2.3.4/-1", "1.2.3.4/abc",
		"1.2.3.4/255.0.255.0", "1.2.3.4/1.2.3", "::1/129", "::1/-1", "1.2.3.4 5.6.7.8 9.9.9.9",
		"fe80::1%eth0", "1.2.3.4/24/8", "::1/255.255.255.0", "010.0.0.1", strings.Repeat("1", 500),
		"1.2.3.4-", "-1.2.3.4", "10.0.0.9-10.0.0.1", "10.0.0.1-::1", "1.2.3.4 - zzz", "0x7f.0.0.1",
	}
	for _, in := range bad {
		if r, err := Calculate(in); err == nil {
			t.Errorf("%q should fail, got %+v", truncate(in), r)
		}
	}
}

func TestIPv6(t *testing.T) {
	r, err := Calculate("2001:db8::1/32")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "ipv6" || r.Network != "2001:db8::" || r.FirstAddress != "2001:db8::" ||
		r.LastAddress != "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff" ||
		r.AddressCount != "79228162514264337593543950336" || r.Scope != "documentation" ||
		r.Expanded != "2001:0db8:0000:0000:0000:0000:0000:0001" || r.Compressed != "2001:db8::1" ||
		r.CIDR != "2001:db8::/32" || r.ReverseDNS != "8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Errorf("unexpected: %+v", r)
	}

	cases := []struct{ in, scope, count string }{
		{"::/0", "unspecified", "340282366920938463463374607431768211456"},
		{"::1/128", "loopback", "1"},
		{"::1", "loopback", "1"},
		{"::", "unspecified", "1"},
		{"fd12:3456:789a::1/48", "unique local address (ULA)", "1208925819614629174706176"},
		{"fe80::1/64", "link-local", "18446744073709551616"},
		{"ff02::1", "multicast (link-local)", "1"},
		{"ff0e::1", "multicast (global)", "1"},
		{"2606:4700::1111/128", "global unicast", "1"},
		{"2002:c000:204::1", "6to4", "1"},
		{"64:ff9b::192.0.2.33", "NAT64 (RFC 6052)", "1"},
		{"::ffff:192.0.2.128", "IPv4-mapped", "1"},
		{"5f00::1", "reserved / unassigned", "1"},
		{"2001:db8::/127", "documentation", "2"},
	}
	for _, c := range cases {
		r, err := Calculate(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if r.Scope != c.scope || r.AddressCount != c.count {
			t.Errorf("%q: scope=%q count=%s", c.in, r.Scope, r.AddressCount)
		}
	}
	r, _ = Calculate("fd00::1")
	if !r.Private {
		t.Error("ULA should be flagged private")
	}
	r, _ = Calculate("::/0")
	if r.LastAddress != "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" || r.ReverseDNS != "ip6.arpa" {
		t.Errorf("::/0 %+v", r)
	}
	r, _ = Calculate("2001:db8::1")
	if r.ReverseDNS != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" || r.Prefix != 128 {
		t.Errorf("rev %s", r.ReverseDNS)
	}
	// prefix not on a nibble boundary truncates the zone
	r, _ = Calculate("2001:db8::/30")
	if r.ReverseDNS != "b.d.0.1.0.0.2.ip6.arpa" { ///30 -> 7 nibbles
		t.Errorf("rev %s", r.ReverseDNS)
	}
}

func TestEmbeddedIPv4(t *testing.T) {
	cases := []struct{ in, v4, kindPrefix string }{
		{"::ffff:1.2.3.4", "1.2.3.4", "IPv4-mapped"},
		{"::ffff:102:304", "1.2.3.4", "IPv4-mapped"},
		{"64:ff9b::c000:221", "192.0.2.33", "NAT64"},
		{"2002:c000:204::1", "192.0.2.4", "6to4"},
		{"::1.2.3.4", "1.2.3.4", "IPv4-compatible"},
	}
	for _, c := range cases {
		r, err := Calculate(c.in)
		if err != nil {
			t.Fatal(c.in, err)
		}
		if r.Kind != "ipv6" || r.EmbeddedIPv4 != c.v4 || !strings.HasPrefix(r.EmbeddedKind, c.kindPrefix) {
			t.Errorf("%q: %+v", c.in, r)
		}
	}
	for _, in := range []string{"::1", "::", "2001:db8::1"} {
		r, _ := Calculate(in)
		if r.EmbeddedIPv4 != "" {
			t.Errorf("%q should have no embedded v4: %s", in, r.EmbeddedIPv4)
		}
	}
}

func TestRanges(t *testing.T) {
	cases := []struct {
		in    string
		cidrs []string
		total string
	}{
		{"192.168.0.0-192.168.0.255", []string{"192.168.0.0/24"}, "256"},
		{"192.168.0.1 - 192.168.0.6", []string{"192.168.0.1/32", "192.168.0.2/31", "192.168.0.4/31", "192.168.0.6/32"}, "6"},
		{"10.0.0.5 to 10.0.0.5", []string{"10.0.0.5/32"}, "1"},
		{"0.0.0.0-255.255.255.255", []string{"0.0.0.0/0"}, "4294967296"},
		{"10.0.0.0-10.0.1.255", []string{"10.0.0.0/23"}, "512"},
		{"10.0.0.255-10.0.1.0", []string{"10.0.0.255/32", "10.0.1.0/32"}, "2"},
		{"1.0.0.1-1.0.0.254", []string{"1.0.0.1/32", "1.0.0.2/31", "1.0.0.4/30", "1.0.0.8/29", "1.0.0.16/28", "1.0.0.32/27", "1.0.0.64/26", "1.0.0.128/26", "1.0.0.192/27", "1.0.0.224/28", "1.0.0.240/29", "1.0.0.248/30", "1.0.0.252/31", "1.0.0.254/32"}, "254"},
		{"::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"::/0"}, "340282366920938463463374607431768211456"},
		{"2001:db8::1-2001:db8::2", []string{"2001:db8::1/128", "2001:db8::2/128"}, "2"},
	}
	for _, c := range cases {
		r, err := Calculate(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if strings.Join(r.CIDRList, ",") != strings.Join(c.cidrs, ",") || r.AddressCount != c.total {
			t.Errorf("%q: got %v (%s) want %v (%s)", c.in, r.CIDRList, r.AddressCount, c.cidrs, c.total)
		}
	}
}

func TestRangeBounded(t *testing.T) {
	// worst case alternating ranges produce at most 2*bits entries and are fast
	a := netip.MustParseAddr("::1")
	b := netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")
	l, err := RangeToCIDRs(a, b)
	if err != nil || len(l) > 256 {
		t.Fatalf("len=%d err=%v", len(l), err)
	}
	r, err := Calculate("0.0.0.1-255.255.255.254")
	if err != nil || len(r.CIDRList) != 62 {
		t.Fatalf("v4 worst case: %d %v", len(r.CIDRList), err)
	}
	// verify coverage: sum of sizes equals the count
	if r.AddressCount != "4294967294" {
		t.Fatal(r.AddressCount)
	}
	if _, err := RangeToCIDRs(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("::1")); err == nil {
		t.Fatal("mixed families must fail")
	}
}

func TestHugeIPv6DoesNotExplode(t *testing.T) {
	for _, in := range []string{"::/0", "2000::/3", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0", "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if _, err := Calculate(in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestHandler(t *testing.T) {
	h := http.HandlerFunc(HandleNetCalc)
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/api/tools/netcalc?q=10.0.0.1/8", nil))
	var r Result
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || r.Network != "10.0.0.0" {
		t.Fatalf("%v %s", err, w.Body.String())
	}
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", "/api/tools/netcalc?q=nope", nil))
	if !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest("POST", "/api/tools/netcalc?q=10.0.0.1", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal(w.Code)
	}
}
