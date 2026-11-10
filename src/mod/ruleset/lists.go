package ruleset

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

/*
	lists.go

	Named lists: sets of networks (ip), exact strings (string) or country codes (country) that rules
	reference as $name. They are edited in one place (lists.json) and used by any number of rules.
*/

const (
	ListIP      = "ip"
	ListString  = "string"
	ListCountry = "country"

	MaxLists       = 100
	MaxListItems   = 10000
	MaxListItemLen = 256
	MaxListDescLen = 200
)

// List is a named list
type List struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // ip | string | country
	Description string   `json:"description,omitempty"`
	Items       []string `json:"items"`

	set  map[string]struct{}
	nets *ipSet
}

// parseAddr reads an IP address (a port or zone is not accepted)
func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// ipSet matches addresses against a set of networks in at most one map lookup per distinct prefix length
type ipSet struct {
	m     map[netip.Prefix]struct{}
	bits4 []int
	bits6 []int
}

func newIPSet(items []string) (*ipSet, error) {
	s := &ipSet{m: make(map[netip.Prefix]struct{}, len(items))}
	have4, have6 := map[int]bool{}, map[int]bool{}
	for _, it := range items {
		it = strings.TrimSpace(it)
		var p netip.Prefix
		if strings.Contains(it, "/") {
			pp, err := netip.ParsePrefix(it)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid network (use 10.0.0.0/8 or 2001:db8::/32)", it)
			}
			p = pp
		} else {
			a, err := netip.ParseAddr(it)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid address or network", it)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		// v4-mapped networks are treated as the IPv4 network
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		s.m[p] = struct{}{}
		if p.Addr().Is4() {
			have4[p.Bits()] = true
		} else {
			have6[p.Bits()] = true
		}
	}
	for b := range have4 {
		s.bits4 = append(s.bits4, b)
	}
	for b := range have6 {
		s.bits6 = append(s.bits6, b)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.bits4)))
	sort.Sort(sort.Reverse(sort.IntSlice(s.bits6)))
	return s, nil
}

func (s *ipSet) contains(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	bits := s.bits6
	if a.Is4() {
		bits = s.bits4
	}
	for _, b := range bits {
		p, err := a.Prefix(b)
		if err != nil {
			continue
		}
		if _, ok := s.m[p]; ok {
			return true
		}
	}
	return false
}

// Validate checks and compiles a list
func (l *List) Validate() error {
	if !validListName(l.Name) {
		return fmt.Errorf("list names are lower case letters, digits and _, starting with a letter, at most %d characters", maxListName)
	}
	if len(l.Description) > MaxListDescLen {
		return fmt.Errorf("the description is longer than %d characters", MaxListDescLen)
	}
	if len(l.Items) > MaxListItems {
		return fmt.Errorf("a list holds at most %d entries", MaxListItems)
	}
	switch l.Type {
	case ListIP:
		set, err := newIPSet(l.Items)
		if err != nil {
			return err
		}
		l.nets, l.set = set, nil
	case ListString, ListCountry:
		l.set = make(map[string]struct{}, len(l.Items))
		for _, it := range l.Items {
			if it == "" || len(it) > MaxListItemLen || strings.ContainsAny(it, "\x00\r\n") {
				return fmt.Errorf("invalid entry %q (1-%d characters, no line breaks)", it, MaxListItemLen)
			}
			if l.Type == ListCountry && !countryRe.MatchString(it) {
				return fmt.Errorf("%q is not a country code (two upper case letters such as US)", it)
			}
			l.set[it] = struct{}{}
		}
		l.nets = nil
	default:
		return fmt.Errorf("the list type must be ip, string or country")
	}
	return nil
}

// link resolves $name references against the lists, checking the list type fits the field
func (x *Expr) link(lists map[string]*List) *Error {
	var walk func(n *Node) *Error
	walk = func(n *Node) *Error {
		if n.Kind != NCond {
			for _, k := range n.Kids {
				if err := walk(k); err != nil {
					return err
				}
			}
			return nil
		}
		c := n.C
		if c.Val.Kind != VRef {
			return nil
		}
		l := lists[c.Val.Ref]
		if l == nil {
			return errAt(c.Pos, c.Pos+len(c.Field.Name), "unknown list $%s (create it under Lists first)", c.Val.Ref)
		}
		switch {
		case c.Field.Type == TIP && l.Type != ListIP:
			return errAt(c.Pos, c.Pos+len(c.Field.Name), "$%s is a %s list, %s needs an ip list", l.Name, l.Type, c.Field.Name)
		case c.Field.Type == TString && l.Type == ListIP:
			return errAt(c.Pos, c.Pos+len(c.Field.Name), "$%s is an ip list and cannot be compared with the text field %s", l.Name, c.Field.Name)
		case c.Field.Type == TString && l.Type == ListCountry && !c.Field.Country:
			return errAt(c.Pos, c.Pos+len(c.Field.Name), "$%s is a country list and can only be used with ip.country", l.Name)
		}
		c.ref = l
		return nil
	}
	return walk(x.Root)
}

// Link resolves the named lists of the expression. The expression is usable for evaluation afterwards.
func (x *Expr) Link(lists map[string]*List) *Error { return x.link(lists) }
