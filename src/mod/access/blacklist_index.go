package access

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

/*
	blacklist_index.go

	Precompiled lookup structure for the IP blacklist (upstream #986).

	The blacklist used to be scanned linearly on every request, re-parsing every
	CIDR each time. The index parses once and answers in O(1) for exact entries,
	O(distinct prefix lengths) for CIDRs and O(16) for IPv4 wildcard patterns,
	independent of the number of entries.

	Semantics are identical to the old scan:
	  1. exact string match of the key
	  2. IPv4 wildcard pattern ("10.1.*.*", octets compared as text)
	  3. CIDR containment (IPv4 and IPv6, IPv4-mapped IPv6 clients count as IPv4,
	     a "%zone" suffix on the client address is ignored)
*/

// wildcardNode is a trie over the four dotted octets, "*" matches any octet
type wildcardNode struct {
	children map[string]*wildcardNode
	star     *wildcardNode
	leaf     bool
	comment  string
}

type blacklistIndex struct {
	src     *map[string]string //The map this index was built from
	size    int                //Its length at build time, detects in-place growth
	exact   map[string]string
	wild    *wildcardNode
	v4Bits  []int //Distinct IPv4 prefix lengths present, longest first
	v6Bits  []int
	prefix4 map[netip.Prefix]string
	prefix6 map[netip.Prefix]string
}

func buildBlacklistIndex(src *map[string]string) *blacklistIndex {
	idx := &blacklistIndex{
		src:     src,
		size:    len(*src),
		exact:   *src,
		wild:    &wildcardNode{},
		prefix4: map[netip.Prefix]string{},
		prefix6: map[netip.Prefix]string{},
	}
	seen4 := map[int]bool{}
	seen6 := map[int]bool{}

	for entry, comment := range *src {
		// IPv4 wildcard / dotted entries: exactly four dot separated parts
		if parts := strings.Split(entry, "."); len(parts) == 4 {
			node := idx.wild
			for _, part := range parts {
				if part == "*" {
					if node.star == nil {
						node.star = &wildcardNode{}
					}
					node = node.star
					continue
				}
				if node.children == nil {
					node.children = map[string]*wildcardNode{}
				}
				next := node.children[part]
				if next == nil {
					next = &wildcardNode{}
					node.children[part] = next
				}
				node = next
			}
			node.leaf = true
			node.comment = comment
		}

		// CIDR entries, parsed with the same function as the legacy matcher
		if !strings.Contains(entry, "/") {
			continue
		}
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		// net.IPNet treats an IPv4-mapped network with a /96 or longer prefix as an IPv4 network
		if addr.Is4In6() && ones >= 96 {
			addr, ones = addr.Unmap(), ones-96
		}
		pfx := netip.PrefixFrom(addr, ones).Masked()
		if addr.Is4() {
			idx.prefix4[pfx] = comment
			seen4[ones] = true
		} else {
			idx.prefix6[pfx] = comment
			seen6[ones] = true
		}
	}

	for bits := range seen4 {
		idx.v4Bits = append(idx.v4Bits, bits)
	}
	for bits := range seen6 {
		idx.v6Bits = append(idx.v6Bits, bits)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(idx.v4Bits)))
	sort.Sort(sort.Reverse(sort.IntSlice(idx.v6Bits)))
	return idx
}

func (n *wildcardNode) match(octets []string) (string, bool) {
	if len(octets) == 0 {
		return n.comment, n.leaf
	}
	if child := n.children[octets[0]]; child != nil {
		if c, ok := child.match(octets[1:]); ok {
			return c, true
		}
	}
	if n.star != nil {
		return n.star.match(octets[1:])
	}
	return "", false
}

// lookup returns the comment of a matching entry. Exact entries win, then wildcards,
// then the most specific CIDR.
func (idx *blacklistIndex) lookup(ipAddr string) (string, bool) {
	if comment, ok := idx.exact[ipAddr]; ok {
		return comment, true
	}

	if octets := strings.Split(ipAddr, "."); len(octets) == 4 {
		if comment, ok := idx.wild.match(octets); ok {
			return comment, true
		}
	}

	if len(idx.v4Bits) == 0 && len(idx.v6Bits) == 0 {
		return "", false
	}
	// same preprocessing as netutils.MatchIpCIDR
	if i := strings.Index(ipAddr, "%"); i != -1 {
		ipAddr = ipAddr[:i]
	}
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return "", false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		for _, bits := range idx.v4Bits {
			if comment, ok := idx.prefix4[netip.PrefixFrom(addr, bits).Masked()]; ok {
				return comment, true
			}
		}
		return "", false
	}
	for _, bits := range idx.v6Bits {
		if comment, ok := idx.prefix6[netip.PrefixFrom(addr, bits).Masked()]; ok {
			return comment, true
		}
	}
	return "", false
}

// blacklistIndexFor returns the index matching the current IP blacklist, rebuilding it when
// the list was replaced (Add / Remove swap the map) or grew in place.
func (s *AccessRule) blacklistIndexFor() *blacklistIndex {
	src := s.BlackListIP
	if cached, ok := s.blIndex.Load().(*blacklistIndex); ok && cached.src == src && cached.size == len(*src) {
		return cached
	}
	idx := buildBlacklistIndex(src)
	s.blIndex.Store(idx)
	return idx
}
