package geodb

import (
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
)

// LAN clients must never get a country, whatever form the socket reports them in.
func TestLANAddressesAreNotGivenACountry(t *testing.T) {
	s, err := NewGeoDb(nil, &StoreOptions{Logger: &logger.Logger{}})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"192.168.1.5":           "Private",
		"10.1.0.25":             "Private",
		"172.16.5.4":            "Private",
		"::ffff:192.168.1.5":    "Private", // dual-stack listener, IPv4 LAN client (used to resolve to "AU")
		"::ffff:10.1.0.25":      "Private",
		"[::ffff:10.1.0.25]":    "Private",
		"192.168.1.5:51234":     "Private",
		"[::ffff:127.0.0.1]:80": "Loopback",
		"::ffff:100.64.1.1":     "CarrierNAT",
		"fe80::1%eth0":          "LinkLocal",
		"fd00::1":               "UniqueLocal",
		"10.1.0.25, 1.2.3.4":    "Private",
		"::ffff:3.224.220.101":  "US", // a mapped public address is looked up as IPv4
		"3.224.220.101":         "US",
	}
	for ip, want := range cases {
		info, _ := s.ResolveCountryCodeFromIP(ip)
		if info.CountryIsoCode != want {
			t.Errorf("%q -> %q, want %q", ip, info.CountryIsoCode, want)
		}
	}
}
