package ruleset

import (
	"fmt"
	"strings"
)

/*
	eval.go

	Evaluation of a linked expression against an Env.

	Cost model: every node costs 1 step, a condition on a value costs one more step per 256 bytes of the value
	(per 32 bytes for a regular expression). A rule may spend RuleBudget steps and a request RequestBudget
	steps over all rules. The field values are capped at 32 KiB, so with the parser limits a validated rule
	cannot reach its budget; the budget is the backstop behind those limits, tested with lowered budgets.
	Running out of budget aborts the rule: it does not match and is counted as an error (fail open).
*/

const (
	RuleBudget    = 50000
	RequestBudget = 400000
)

// budget is spent by evaluation
type budget struct {
	left     int
	exceeded bool
}

func (b *budget) spend(n int) bool {
	if b.exceeded {
		return false
	}
	b.left -= n
	if b.left < 0 {
		b.exceeded = true
		return false
	}
	return true
}

// TraceEntry is one evaluated node, for the request tester
type TraceEntry struct {
	Path   string `json:"path"`
	Depth  int    `json:"depth"`
	Text   string `json:"text"`
	Actual string `json:"actual,omitempty"`
	Result bool   `json:"result"`
}

type trace struct{ entries []TraceEntry }

// evalExpr evaluates the root; with tr set, every node is evaluated (no short-circuit) and recorded
func evalExpr(root *Node, e *Env, b *budget, tr *trace) bool {
	return evalNode(root, e, b, tr, "0", 0)
}

func evalNode(n *Node, e *Env, b *budget, tr *trace, path string, depth int) bool {
	if !b.spend(1) {
		return false
	}
	idx := -1
	if tr != nil {
		idx = len(tr.entries)
		text := ""
		switch n.Kind {
		case NCond:
			text = n.C.Text()
		case NAnd:
			text = "all of"
		case NOr:
			text = "any of"
		case NNot:
			text = "not"
		}
		tr.entries = append(tr.entries, TraceEntry{Path: path, Depth: depth, Text: text})
	}
	var res bool
	switch n.Kind {
	case NCond:
		var actual string
		res, actual = n.C.eval(e, b, tr != nil)
		if tr != nil {
			tr.entries[idx].Actual = actual
		}
	case NNot:
		res = !evalNode(n.Kids[0], e, b, tr, childPath(tr, path, 0), depth+1)
	case NAnd:
		res = true
		for i, k := range n.Kids {
			if !evalNode(k, e, b, tr, childPath(tr, path, i), depth+1) {
				res = false
				if tr == nil {
					break
				}
			}
		}
	case NOr:
		for i, k := range n.Kids {
			if evalNode(k, e, b, tr, childPath(tr, path, i), depth+1) {
				res = true
				if tr == nil {
					break
				}
			}
		}
	}
	if idx >= 0 {
		tr.entries[idx].Result = res
	}
	return res
}

func (c *Cond) inSet(v string) bool {
	if c.ref != nil {
		_, ok := c.ref.set[v]
		return ok
	}
	_, ok := c.set[v]
	return ok
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// eval returns the truth value and a short description of the value that was looked at (for the tester)
func (c *Cond) eval(e *Env, b *budget, want bool) (bool, string) {
	f := c.Field
	switch f.Type {
	case TString:
		v, present := e.strValue(f, c.Key)
		switch c.Op {
		case OpExists:
			return present, presentText(present)
		case OpNotExists:
			return !present, presentText(present)
		}
		if c.Lower {
			v = strings.ToLower(v)
		}
		steps := 1 + len(v)>>8
		if c.re != nil {
			steps = 4 + len(v)>>5
		}
		if !b.spend(steps) {
			return false, ""
		}
		var r bool
		switch c.Op {
		case OpEq:
			r = v == c.Val.Str
		case OpNe:
			r = v != c.Val.Str
		case OpContains:
			r = strings.Contains(v, c.Val.Str)
		case OpNotContains:
			r = !strings.Contains(v, c.Val.Str)
		case OpStartsWith:
			r = strings.HasPrefix(v, c.Val.Str)
		case OpNotStartsWith:
			r = !strings.HasPrefix(v, c.Val.Str)
		case OpEndsWith:
			r = strings.HasSuffix(v, c.Val.Str)
		case OpNotEndsWith:
			r = !strings.HasSuffix(v, c.Val.Str)
		case OpMatches:
			r = c.re.MatchString(v)
		case OpNotMatches:
			r = !c.re.MatchString(v)
		case OpIn:
			r = c.inSet(v)
		case OpNotIn:
			r = !c.inSet(v)
		}
		if !want {
			return r, ""
		}
		return r, quote(clip(v))
	case TInt:
		v := e.intValue(f)
		var r bool
		switch c.Op {
		case OpEq:
			r = v == c.Val.Int
		case OpNe:
			r = v != c.Val.Int
		case OpLt:
			r = v < c.Val.Int
		case OpGt:
			r = v > c.Val.Int
		case OpLe:
			r = v <= c.Val.Int
		case OpGe:
			r = v >= c.Val.Int
		}
		if !want {
			return r, ""
		}
		return r, fmt.Sprint(v)
	case TBool:
		v := e.boolValue(f)
		r := v == c.Val.Bool
		if c.Op == OpNe {
			r = !r
		}
		if !want {
			return r, ""
		}
		return r, fmt.Sprint(v)
	case TIP:
		a := e.Addr()
		var r bool
		switch c.Op {
		case OpEq:
			r = a == c.addr
		case OpNe:
			r = a != c.addr
		case OpIn, OpNotIn:
			set := c.nets
			if c.ref != nil {
				set = c.ref.nets
			}
			r = set.contains(a)
			if c.Op == OpNotIn {
				r = !r
			}
		}
		if !want {
			return r, ""
		}
		return r, a.String()
	}
	return false, ""
}

func presentText(p bool) string {
	if p {
		return "present"
	}
	return "absent"
}

// Eval evaluates a linked expression once (used by tests and the tester)
func (x *Expr) Eval(e *Env) bool {
	b := &budget{left: RuleBudget}
	return evalExpr(x.Root, e, b, nil) && !b.exceeded
}

// childPath builds a node path only when a trace is being recorded; the request
// path (tr == nil) must not allocate a string per child.
func childPath(tr *trace, path string, i int) string {
	if tr == nil {
		return ""
	}
	return fmt.Sprintf("%s.%d", path, i)
}
