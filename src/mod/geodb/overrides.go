package geodb

import (
	"net/netip"
	"sort"
)

/*
	overrides.go

	Corrections applied on top of the geoip CSV datasets (embedded and downloaded) when they
	are loaded.

	The data source (@ip-location-db/geo-whois-asn-country) is deprecated for "incorrect data":
	its IPv6 table contains very wide gap-filling rows, e.g. "2001:cf1::,2001:d27:ffff:...,AU",
	that swallow unrelated allocations, so Malaysian prefixes resolved to AU (upstream #1334).
	Replacing the dataset needs network access and a licence decision, so until that is done the
	known wrong ranges are pinned here. An override replaces whatever the CSV says for its
	range: overlapping CSV rows are trimmed or split around it.

	To add a correction: verify the prefix against the RIR delegation files (APNIC RDAP etc.),
	append it to ipv6Overrides / ipv4Overrides with a test case in overrides_test.go.
	To refresh the data: replace geoipv4.csv / geoipv6.csv (see README.txt), then re-check each
	override and delete the ones the new data already gets right.
*/

// geoOverride pins a prefix to a country code (upper case ISO 3166-1 alpha-2)
type geoOverride struct {
	prefix  string
	country string
}

var ipv4Overrides = []geoOverride{}

var ipv6Overrides = []geoOverride{
	{"2001:d08::/32", "MY"}, // Maxis, was inside "2001:cf1::-2001:d27:ffff::" AU
	{"2001:e68::/32", "MY"}, // TM Net, was inside "2001:e49::-2001:e9f:ffff::" AU
	{"2001:f40::/32", "MY"}, // TT DotCom, was inside "2001:f31::-2001:f58:200a::" AU
}

type geoRow struct {
	start, end netip.Addr
	country    string
}

// applyGeoOverrides returns rows (start, end, country) with the overrides applied.
// Rows that no override touches are returned unchanged and in their original order.
func applyGeoOverrides(rows [][]string, overrides []geoOverride) [][]string {
	if len(overrides) == 0 {
		return rows
	}

	type ovRange struct {
		start, end netip.Addr
		country    string
	}
	ranges := make([]ovRange, 0, len(overrides))
	for _, o := range overrides {
		p, err := netip.ParsePrefix(o.prefix)
		if err != nil {
			continue
		}
		p = p.Masked()
		ranges = append(ranges, ovRange{p.Addr(), lastAddr(p), o.country})
	}

	type outRow struct {
		start netip.Addr
		rec   []string
	}
	out := make([]outRow, 0, len(rows)+len(ranges)*2)
	for _, row := range rows {
		if len(row) < 3 {
			out = append(out, outRow{rec: row})
			continue
		}
		start, err1 := netip.ParseAddr(row[0])
		end, err2 := netip.ParseAddr(row[1])
		if err1 != nil || err2 != nil {
			out = append(out, outRow{rec: row})
			continue
		}
		pieces := []geoRow{{start, end, row[2]}}
		for _, ov := range ranges {
			var next []geoRow
			for _, piece := range pieces {
				if piece.start.BitLen() != ov.start.BitLen() || piece.end.Less(ov.start) || ov.end.Less(piece.start) {
					next = append(next, piece)
					continue
				}
				if piece.start.Less(ov.start) {
					next = append(next, geoRow{piece.start, ov.start.Prev(), piece.country})
				}
				if ov.end.Less(piece.end) {
					next = append(next, geoRow{ov.end.Next(), piece.end, piece.country})
				}
			}
			pieces = next
		}
		if len(pieces) == 1 && pieces[0].start == start && pieces[0].end == end {
			out = append(out, outRow{start, row})
			continue
		}
		for _, piece := range pieces {
			out = append(out, outRow{piece.start, []string{piece.start.String(), piece.end.String(), piece.country}})
		}
	}
	for _, ov := range ranges {
		out = append(out, outRow{ov.start, []string{ov.start.String(), ov.end.String(), ov.country}})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].start.IsValid() || !out[j].start.IsValid() {
			return false
		}
		return out[i].start.Less(out[j].start)
	})
	result := make([][]string, len(out))
	for i := range out {
		result[i] = out[i].rec
	}
	return result
}

// lastAddr returns the last address of a prefix
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for bit := p.Bits(); bit < len(b)*8; bit++ {
		b[bit/8] |= 0x80 >> (bit % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
