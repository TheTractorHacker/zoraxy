// Package netcalc implements IPv4 / IPv6 subnet calculators for the admin UI toolbox.
//
// All arithmetic is done on netip.Addr values or math/big integers; nothing
// ever enumerates addresses, so huge ranges (/0, ::/0) cost constant time and memory.
package netcalc

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
)

const maxQueryLen = 200

// Result is the calculator output. Which fields are filled depends on Kind.
type Result struct {
	Kind  string `json:"kind"` //ipv4, ipv6, range4, range6
	Input string `json:"input"`

	Address string `json:"address,omitempty"`
	Prefix  int    `json:"prefix"`
	CIDR    string `json:"cidr,omitempty"` //Network in CIDR notation

	//IPv4 specifics
	Netmask   string `json:"netmask,omitempty"`
	Wildcard  string `json:"wildcard,omitempty"`
	Broadcast string `json:"broadcast,omitempty"`
	Class     string `json:"class,omitempty"` //A, B, C, D (multicast), E (reserved)
	Private   bool   `json:"private"`         //RFC 1918 / ULA
	Binary    string `json:"binary,omitempty"`

	//Shared
	Network      string   `json:"network,omitempty"`
	FirstHost    string   `json:"firstHost,omitempty"`
	LastHost     string   `json:"lastHost,omitempty"`
	FirstAddress string   `json:"firstAddress,omitempty"`
	LastAddress  string   `json:"lastAddress,omitempty"`
	HostCount    string   `json:"hostCount,omitempty"`    //usable hosts (decimal, arbitrary size)
	AddressCount string   `json:"addressCount,omitempty"` //total addresses (decimal, arbitrary size)
	Scope        string   `json:"scope,omitempty"`        //human readable address type
	ReverseDNS   string   `json:"reverseDns,omitempty"`   //in-addr.arpa / ip6.arpa name
	Expanded     string   `json:"expanded,omitempty"`     //IPv6 full form
	Compressed   string   `json:"compressed,omitempty"`   //IPv6 RFC 5952 form
	EmbeddedIPv4 string   `json:"embeddedIpv4,omitempty"` //IPv4 inside an IPv6 address
	EmbeddedKind string   `json:"embeddedKind,omitempty"` //mapped, NAT64, 6to4 ...
	CIDRList     []string `json:"cidrList,omitempty"`     //range -> minimal CIDR list
	RangeStart   string   `json:"rangeStart,omitempty"`
	RangeEnd     string   `json:"rangeEnd,omitempty"`
}

// Calculate detects the kind of query and computes the result.
//
// Accepted forms: "10.0.0.1", "10.0.0.1/24", "10.0.0.1/255.255.255.0",
// "10.0.0.1 255.255.255.0", "2001:db8::1", "2001:db8::/32" and ranges
// "10.0.0.5 - 10.0.0.99" / "2001:db8::1-2001:db8::ffff".
func Calculate(q string) (*Result, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, errors.New("empty query")
	}
	if len(q) > maxQueryLen {
		return nil, errors.New("query too long")
	}
	if i := strings.Index(strings.ToLower(q), " to "); i > 0 {
		return calcRange(q[:i], q[i+4:], q)
	}
	if i := strings.Index(q, "-"); i > 0 {
		return calcRange(q[:i], q[i+1:], q)
	}
	if strings.Contains(q, "/") {
		parts := strings.SplitN(q, "/", 2)
		return calcPrefix(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), q)
	}
	if f := strings.Fields(q); len(f) == 2 {
		return calcPrefix(f[0], f[1], q)
	} else if len(f) > 2 {
		return nil, errors.New("unrecognised input")
	}
	return calcPrefix(q, "", q)
}

func parseAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", truncate(s))
	}
	if a.Zone() != "" {
		return netip.Addr{}, errors.New("IPv6 zone identifiers are not supported")
	}
	return a, nil
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// maskToPrefix converts a dotted netmask (or wildcard-free) into a prefix length
func maskToPrefix(mask string) (int, error) {
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return 0, errors.New("invalid netmask")
	}
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	ones := 0
	for v&0x80000000 != 0 {
		ones++
		v <<= 1
	}
	if v != 0 {
		return 0, errors.New("netmask is not contiguous")
	}
	return ones, nil
}

func calcPrefix(addrStr, prefixStr, input string) (*Result, error) {
	a, err := parseAddr(addrStr)
	if err != nil {
		return nil, err
	}
	bits := a.BitLen()
	prefix := bits
	if prefixStr != "" {
		if strings.Contains(prefixStr, ".") && a.Is4() {
			prefix, err = maskToPrefix(prefixStr)
			if err != nil {
				return nil, err
			}
		} else {
			p, perr := strconv.Atoi(prefixStr)
			if perr != nil || p < 0 || p > bits {
				return nil, fmt.Errorf("prefix length must be between 0 and %d", bits)
			}
			prefix = p
		}
	}
	if a.Is4() {
		return calcV4(a, prefix, input), nil
	}
	return calcV6(a, prefix, input), nil
}

func addrToBig(a netip.Addr) *big.Int {
	b := a.AsSlice()
	return new(big.Int).SetBytes(b)
}

func bigToAddr(v *big.Int, bits int) netip.Addr {
	size := bits / 8
	buf := make([]byte, size)
	v.FillBytes(buf)
	a, _ := netip.AddrFromSlice(buf)
	return a
}

func pow2(n int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(n)) }

// blockBounds returns the first and last address of the prefix containing a
func blockBounds(a netip.Addr, prefix int) (netip.Addr, netip.Addr) {
	bits := a.BitLen()
	host := bits - prefix
	v := addrToBig(a)
	mask := new(big.Int).Sub(pow2(host), big.NewInt(1))
	first := new(big.Int).AndNot(v, mask)
	last := new(big.Int).Or(first, mask)
	return bigToAddr(first, bits), bigToAddr(last, bits)
}

func calcV4(a netip.Addr, prefix int, input string) *Result {
	first, last := blockBounds(a, prefix)
	host := 32 - prefix
	maskVal := uint32(0)
	if prefix > 0 {
		maskVal = ^uint32(0) << uint(32-prefix)
	}
	r := &Result{
		Kind: "ipv4", Input: input, Address: a.String(), Prefix: prefix,
		Network: first.String(), Broadcast: last.String(),
		CIDR:     netip.PrefixFrom(first, prefix).String(),
		Netmask:  u32ToAddr(maskVal).String(),
		Wildcard: u32ToAddr(^maskVal).String(),
		Binary:   binary4(a),
	}
	r.AddressCount = pow2(host).String()
	switch {
	case prefix == 32:
		r.HostCount, r.FirstHost, r.LastHost = "1", a.String(), a.String()
		r.Broadcast = ""
	case prefix == 31: //RFC 3021 point-to-point, both addresses usable
		r.HostCount, r.FirstHost, r.LastHost = "2", first.String(), last.String()
		r.Broadcast = ""
	default:
		r.HostCount = new(big.Int).Sub(pow2(host), big.NewInt(2)).String()
		r.FirstHost = first.Next().String()
		r.LastHost = last.Prev().String()
	}
	r.FirstAddress, r.LastAddress = first.String(), last.String()
	b := a.As4()
	switch {
	case b[0] < 128:
		r.Class = "A"
	case b[0] < 192:
		r.Class = "B"
	case b[0] < 224:
		r.Class = "C"
	case b[0] < 240:
		r.Class = "D (multicast)"
	default:
		r.Class = "E (reserved)"
	}
	r.Private = a.IsPrivate()
	r.Scope = scope4(a)
	r.ReverseDNS = reverse4(a, prefix)
	return r
}

func u32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func binary4(a netip.Addr) string {
	b := a.As4()
	return fmt.Sprintf("%08b.%08b.%08b.%08b", b[0], b[1], b[2], b[3])
}

var special4 = []struct {
	prefix string
	name   string
}{
	{"0.0.0.0/8", "this network (unspecified)"},
	{"10.0.0.0/8", "private (RFC 1918)"},
	{"100.64.0.0/10", "carrier-grade NAT (RFC 6598)"},
	{"127.0.0.0/8", "loopback"},
	{"169.254.0.0/16", "link-local"},
	{"172.16.0.0/12", "private (RFC 1918)"},
	{"192.0.0.0/24", "IETF protocol assignments"},
	{"192.0.2.0/24", "documentation (TEST-NET-1)"},
	{"192.168.0.0/16", "private (RFC 1918)"},
	{"198.18.0.0/15", "benchmarking"},
	{"198.51.100.0/24", "documentation (TEST-NET-2)"},
	{"203.0.113.0/24", "documentation (TEST-NET-3)"},
	{"224.0.0.0/4", "multicast"},
	{"255.255.255.255/32", "limited broadcast"},
	{"240.0.0.0/4", "reserved (class E)"},
}

func scope4(a netip.Addr) string {
	for _, s := range special4 {
		if netip.MustParsePrefix(s.prefix).Contains(a) {
			return s.name
		}
	}
	return "public"
}

func reverse4(a netip.Addr, prefix int) string {
	b := a.As4()
	octets := prefix / 8
	if octets == 0 {
		return "in-addr.arpa"
	}
	var parts []string
	for i := octets - 1; i >= 0; i-- {
		parts = append(parts, strconv.Itoa(int(b[i])))
	}
	return strings.Join(parts, ".") + ".in-addr.arpa"
}

func calcV6(a netip.Addr, prefix int, input string) *Result {
	first, last := blockBounds(a, prefix)
	r := &Result{
		Kind: "ipv6", Input: input, Address: a.String(), Prefix: prefix,
		Network: first.String(), FirstAddress: first.String(), LastAddress: last.String(),
		FirstHost: first.String(), LastHost: last.String(),
		CIDR:       netip.PrefixFrom(first, prefix).String(),
		Compressed: a.String(), Expanded: a.StringExpanded(),
		Private: isULA(a),
	}
	count := pow2(128 - prefix)
	r.AddressCount = count.String()
	r.HostCount = count.String() //IPv6 has no broadcast / network address reservation
	r.Scope = scope6(a)
	r.ReverseDNS = reverse6(a, prefix)
	if v4, kind, ok := embeddedV4(a); ok {
		r.EmbeddedIPv4, r.EmbeddedKind = v4.String(), kind
	}
	return r
}

func isULA(a netip.Addr) bool { return a.Is6() && !a.Is4In6() && a.As16()[0]&0xfe == 0xfc }

var special6 = []struct {
	prefix string
	name   string
}{
	{"::/128", "unspecified"},
	{"::1/128", "loopback"},
	{"::ffff:0:0/96", "IPv4-mapped"},
	{"64:ff9b::/96", "NAT64 (RFC 6052)"},
	{"100::/64", "discard-only (RFC 6666)"},
	{"2001:db8::/32", "documentation"},
	{"2001::/32", "Teredo"},
	{"2002::/16", "6to4"},
	{"fc00::/7", "unique local address (ULA)"},
	{"fe80::/10", "link-local"},
	{"ff00::/8", "multicast"},
	{"2000::/3", "global unicast"},
}

func scope6(a netip.Addr) string {
	// most specific match wins (list is ordered specific first except /3 and /7 last)
	for _, s := range special6 {
		if netip.MustParsePrefix(s.prefix).Contains(a) {
			if s.name == "multicast" {
				return "multicast (" + mcScope(a) + ")"
			}
			return s.name
		}
	}
	return "reserved / unassigned"
}

func mcScope(a netip.Addr) string {
	switch a.As16()[1] & 0x0f {
	case 1:
		return "interface-local"
	case 2:
		return "link-local"
	case 4:
		return "admin-local"
	case 5:
		return "site-local"
	case 8:
		return "organization-local"
	case 0xe:
		return "global"
	}
	return "other scope"
}

func embeddedV4(a netip.Addr) (netip.Addr, string, bool) {
	if a.Is4In6() {
		return a.Unmap(), "IPv4-mapped (::ffff:0:0/96)", true
	}
	b := a.As16()
	if netip.MustParsePrefix("64:ff9b::/96").Contains(a) {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), "NAT64 (64:ff9b::/96)", true
	}
	if b[0] == 0x20 && b[1] == 0x02 {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), "6to4 (2002::/16)", true
	}
	// deprecated IPv4-compatible ::a.b.c.d, excluding ::, ::1
	allZero := true
	for i := 0; i < 12; i++ {
		if b[i] != 0 {
			allZero = false
		}
	}
	if allZero && (b[12] != 0 || b[13] != 0 || b[14] != 0 || b[15] > 1) {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), "IPv4-compatible (deprecated)", true
	}
	return netip.Addr{}, "", false
}

// reverse6 returns the ip6.arpa name; for a prefix it is the zone truncated at the nibble boundary
func reverse6(a netip.Addr, prefix int) string {
	b := a.As16()
	const hexd = "0123456789abcdef"
	nibbles := prefix / 4
	var sb strings.Builder
	for i := nibbles - 1; i >= 0; i-- {
		v := b[i/2]
		if i%2 == 0 {
			v >>= 4
		}
		sb.WriteByte(hexd[v&0xf])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}

func calcRange(s1, s2, input string) (*Result, error) {
	a, err := parseAddr(s1)
	if err != nil {
		return nil, err
	}
	b, err := parseAddr(s2)
	if err != nil {
		return nil, err
	}
	if a.Is4() != b.Is4() {
		return nil, errors.New("range ends must be the same IP family")
	}
	list, err := RangeToCIDRs(a, b)
	if err != nil {
		return nil, err
	}
	r := &Result{Kind: "range4", Input: input, RangeStart: a.String(), RangeEnd: b.String()}
	if !a.Is4() {
		r.Kind = "range6"
	}
	for _, p := range list {
		r.CIDRList = append(r.CIDRList, p.String())
	}
	diff := new(big.Int).Sub(addrToBig(b), addrToBig(a))
	r.AddressCount = diff.Add(diff, big.NewInt(1)).String()
	return r, nil
}

// RangeToCIDRs returns the minimal list of CIDR blocks covering first..last
// (inclusive). The result never exceeds 2*bits entries.
func RangeToCIDRs(first, last netip.Addr) ([]netip.Prefix, error) {
	if first.Is4() != last.Is4() {
		return nil, errors.New("range ends must be the same IP family")
	}
	bits := first.BitLen()
	cur := addrToBig(first)
	end := addrToBig(last)
	if cur.Cmp(end) > 0 {
		return nil, errors.New("range start is after range end")
	}
	one := big.NewInt(1)
	var out []netip.Prefix
	for cur.Cmp(end) <= 0 {
		// largest block aligned at cur
		size := bits
		if cur.Sign() != 0 {
			size = int(cur.TrailingZeroBits())
		}
		remaining := new(big.Int).Sub(end, cur)
		remaining.Add(remaining, one)
		if fit := remaining.BitLen() - 1; fit < size {
			size = fit
		}
		out = append(out, netip.PrefixFrom(bigToAddr(cur, bits), bits-size))
		cur.Add(cur, pow2(size))
	}
	return out, nil
}
