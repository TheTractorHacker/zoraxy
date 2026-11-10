package ruleset

import (
	"fmt"
	"strings"
)

// analyze returns the warnings for a validated expression: conditions that can never match, always match,
// or that are expensive. They never block saving a rule.
func analyze(root *Node) []string {
	var out []string
	seen := map[string]bool{}
	warn := func(format string, a ...any) {
		m := fmt.Sprintf(format, a...)
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	var walk func(n *Node)
	walk = func(n *Node) {
		if n.Kind == NCond {
			analyzeCond(n.C, warn)
			return
		}
		if n.Kind == NAnd {
			analyzeAnd(n, warn)
		}
		for _, k := range n.Kids {
			walk(k)
		}
	}
	walk(root)
	return out
}

func literals(c *Cond) []string {
	switch c.Val.Kind {
	case VString:
		return []string{c.Val.Str}
	case VList:
		return c.Val.List
	}
	return nil
}

func analyzeCond(c *Cond, warn func(string, ...any)) {
	name := c.operand()
	positive := c.Op == OpEq || c.Op == OpContains || c.Op == OpStartsWith || c.Op == OpEndsWith || c.Op == OpIn || c.Op == OpMatches
	lits := literals(c)
	if c.Lower && positive && c.Op != OpMatches {
		for _, l := range lits {
			if l != strings.ToLower(l) {
				warn("this rule can never match: %s is lower case, but %s has upper case letters", name, quote(l))
				break
			}
		}
	}
	if positive && c.Op != OpMatches && c.Field.Type == TString {
		switch c.Field.id {
		case fMethod:
			for _, l := range lits {
				if l != strings.ToUpper(l) && !c.Lower {
					warn("this rule can never match: HTTP methods are upper case (%s)", quote(l))
					break
				}
			}
		case fHost:
			for _, l := range lits {
				if l != strings.ToLower(l) && c.Op != OpContains {
					warn("this rule can never match: http.host is lower case, but %s has upper case letters", quote(l))
					break
				}
			}
		case fScheme:
			for _, l := range lits {
				if l != "http" && l != "https" {
					warn(`http.scheme is "http" or "https", never %s`, quote(l))
					break
				}
			}
		case fTLSVersion:
			for _, l := range lits {
				if l != "" && l != "TLSv1.0" && l != "TLSv1.1" && l != "TLSv1.2" && l != "TLSv1.3" {
					warn(`tls.version is TLSv1.0, TLSv1.1, TLSv1.2 or TLSv1.3, never %s`, quote(l))
					break
				}
			}
		case fPath:
			for _, l := range lits {
				if (c.Op == OpEq || c.Op == OpStartsWith || c.Op == OpIn) && !strings.HasPrefix(l, "/") {
					warn("this rule can never match: http.path always starts with / (%s does not)", quote(l))
					break
				}
				if c.Op == OpEq && len(l) > 1 && strings.HasSuffix(l, "/") {
					warn("this rule can never match: http.path has no trailing slash, so %s never equals it (use starts_with)", quote(l))
					break
				}
			}
		}
	}
	switch c.Op {
	case OpContains, OpStartsWith, OpEndsWith:
		if c.Val.Kind == VString && c.Val.Str == "" {
			warn("%s %s \"\" is always true", name, opText[c.Op])
		}
	case OpNotContains, OpNotStartsWith, OpNotEndsWith:
		if c.Val.Kind == VString && c.Val.Str == "" {
			warn("%s %s \"\" is always false", name, opText[c.Op])
		}
	case OpMatches, OpNotMatches:
		if m := regexExpensive(c.Val.Str); m != "" {
			warn("%s", m)
		}
		if !strings.HasPrefix(c.Val.Str, "^") && !strings.HasPrefix(c.Val.Str, "(?") && !strings.HasPrefix(c.Val.Str, "\\A") && c.Field.id == fPath {
			warn("matches is not anchored: it matches anywhere in the value; start the pattern with ^ to match from the beginning")
		}
	case OpLt, OpLe:
		if c.Val.Int < -1 || (c.Op == OpLt && c.Val.Int <= -1) {
			if c.Field.id == fReqSize {
				warn("req.size is never below -1")
			}
		}
	}
	if c.Field.id == fReqSize && c.Op == OpEq && c.Val.Int == 0 {
		warn("req.size == 0 does not match requests with an unknown size (chunked bodies report -1)")
	}
}

type opKey struct {
	field fieldID
	key   string
	lower bool
}

// analyzeAnd finds children of an AND that exclude each other
func analyzeAnd(n *Node, warn func(string, ...any)) {
	eq := map[opKey]*Cond{}
	for _, k := range n.Kids {
		if k.Kind != NCond {
			continue
		}
		c := k.C
		if c.Field.Type == TBool && c.Val.Kind == VBool {
			continue
		}
		key := opKey{c.Field.id, c.Key, c.Lower}
		switch c.Op {
		case OpEq:
			if prev := eq[key]; prev != nil {
				if !sameValue(prev.Val, c.Val) {
					warn("this rule can never match: %s cannot equal both %s and %s", c.operand(), valueText(prev.Val), valueText(c.Val))
				}
			} else {
				eq[key] = c
			}
		}
	}
	for _, k := range n.Kids {
		if k.Kind != NCond || k.C.Op != OpNe {
			continue
		}
		c := k.C
		if prev := eq[opKey{c.Field.id, c.Key, c.Lower}]; prev != nil && sameValue(prev.Val, c.Val) {
			warn("this rule can never match: %s is required to be both equal and not equal to %s", c.operand(), valueText(c.Val))
		}
	}
}

func valueText(v Value) string {
	switch v.Kind {
	case VString:
		return quote(v.Str)
	case VInt:
		return fmt.Sprint(v.Int)
	case VBool:
		return fmt.Sprint(v.Bool)
	}
	return "a list"
}

func sameValue(a, b Value) bool {
	return a.Kind == b.Kind && a.Str == b.Str && a.Int == b.Int && a.Bool == b.Bool && a.Ref == b.Ref
}
