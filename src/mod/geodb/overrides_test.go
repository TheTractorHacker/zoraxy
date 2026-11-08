package geodb

import (
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
)

// Upstream #1334: Malaysian IPv6 prefixes resolved to AU because of a very wide AU row in the
// source data. Both lookup modes must return the overridden country, and the neighbours that
// the CSV gets right (or wrong in the same row) must not change.
func TestIPv6OverridesFixMalaysianPrefixes(t *testing.T) {
	for _, slow := range []bool{false, true} {
		store, err := NewGeoDb(nil, &StoreOptions{
			AllowSlowIpv4LookUp: slow,
			AllowSlowIpv6Lookup: slow,
			Logger:              &logger.Logger{},
		})
		if err != nil {
			t.Fatal(err)
		}

		cases := [][2]string{
			{"2001:d08::1", "MY"},
			{"2001:d08:ffff:ffff:ffff:ffff:ffff:ffff", "MY"},
			{"2001:d08:1234:5678::9", "MY"},
			{"2001:f40::1", "MY"},
			{"2001:f40:abcd::1", "MY"},
			{"2001:e68::1", "MY"},
			{"2001:e68:1::1", "MY"},
			// untouched: the rest of the wide row keeps what the data says
			{"2001:d07:ffff::1", "AU"},
			{"2001:d09::1", "AU"},
			{"2001:cf1::1", "AU"},
			// untouched rows
			{"2a01:4f9:3070:124a:1234:5678:9abc:def0", "DE"},
		}
		for _, c := range cases {
			info, err := store.ResolveCountryCodeFromIP(c[0])
			if err != nil {
				t.Fatal(err)
			}
			if info.CountryIsoCode != c[1] {
				t.Errorf("slow=%v: %s = %s, want %s", slow, c[0], info.CountryIsoCode, c[1])
			}
		}
		store.Close()
	}
}

func TestApplyGeoOverridesSplitsRows(t *testing.T) {
	rows := [][]string{
		{"2001:100::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "AU"},
		{"2001:200::", "2001:2ff:ffff:ffff:ffff:ffff:ffff:ffff", "JP"},
		{"2001:300::", "2001:3ff:ffff:ffff:ffff:ffff:ffff:ffff", "KR"},
	}
	got := applyGeoOverrides(rows, []geoOverride{
		{"2001:180::/32", "MY"}, // inside the first row: splits it in three
		{"2001:200::/24", "SG"}, // covers the second row exactly
		{"2001:2ff:8000::/33", "ID"},
	})
	want := [][]string{
		{"2001:100::", "2001:17f:ffff:ffff:ffff:ffff:ffff:ffff", "AU"},
		{"2001:180::", "2001:180:ffff:ffff:ffff:ffff:ffff:ffff", "MY"},
		{"2001:181::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "AU"},
		{"2001:200::", "2001:2ff:ffff:ffff:ffff:ffff:ffff:ffff", "SG"},
		{"2001:2ff:8000::", "2001:2ff:ffff:ffff:ffff:ffff:ffff:ffff", "ID"},
		{"2001:300::", "2001:3ff:ffff:ffff:ffff:ffff:ffff:ffff", "KR"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		for j := 0; j < 3; j++ {
			if got[i][j] != want[i][j] {
				t.Fatalf("row %d: got %v, want %v (all: %v)", i, got[i], want[i], got)
			}
		}
	}

	// no overrides: input returned as is
	if out := applyGeoOverrides(rows, nil); len(out) != len(rows) {
		t.Fatal("nil overrides changed the rows")
	}
}
