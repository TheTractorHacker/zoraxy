package mdns

import (
	"net"
	"testing"
)

func TestAppendUniqueHost(t *testing.T) {
	mk := func(ip string) *NetworkHost {
		return &NetworkHost{HostName: "Proxy1.local.", Port: 80, IPv4: []net.IP{net.ParseIP(ip)}, MacAddr: []string{"aa:bb"}}
	}
	var list []*NetworkHost
	list = appendUniqueHost(list, mk("10.0.0.2"))
	list = appendUniqueHost(list, mk("10.0.0.2"))
	list = appendUniqueHost(list, mk("10.0.0.2"))
	if len(list) != 1 {
		t.Fatalf("the same host answered on three interfaces was listed %d times", len(list))
	}
	list = appendUniqueHost(list, mk("10.0.0.3"))
	if len(list) != 2 {
		t.Fatal("a different address must stay a separate entry")
	}
}
