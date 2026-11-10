package ruleset

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

/*
	tree.go

	The structured form of an expression, edited by the visual builder:

	  {"type":"and","children":[
	     {"type":"cond","field":"http.path","op":"starts_with","value":"/admin"},
	     {"type":"not","children":[{"type":"cond","field":"ip.country","op":"eq","value":"US"}]}
	  ]}

	Group types: and, or (1 or more children), not (exactly one child). A condition has field, optional key
	(for http.header / http.cookie / http.query_arg), optional transform ("lower"), op (see Operators) and a
	value: a string, a whole number, a boolean, an array of strings, or {"list":"name"} for a named list.

	The tree and the text are two spellings of the same Expr: Parse(text).Tree() and FromTree(tree).Text()
	give back the same thing. A group with a single child collapses into the child, so trees are normalised
	by the round trip (the UI keeps the normalised tree the validate endpoint returns).
*/

// TreeNode is the JSON form
type TreeNode struct {
	Type      string      `json:"type"`
	Children  []*TreeNode `json:"children,omitempty"`
	Field     string      `json:"field,omitempty"`
	Key       string      `json:"key,omitempty"`
	Transform string      `json:"transform,omitempty"`
	Op        string      `json:"op,omitempty"`
	Value     interface{} `json:"value,omitempty"`
}

// Tree converts the expression to the structured form
func (x *Expr) Tree() *TreeNode { return nodeTree(x.Root) }

func nodeTree(n *Node) *TreeNode {
	switch n.Kind {
	case NCond:
		c := n.C
		t := &TreeNode{Type: "cond", Field: c.Field.Name, Key: c.Key, Op: string(c.Op)}
		if c.Lower {
			t.Transform = "lower"
		}
		switch c.Val.Kind {
		case VString:
			t.Value = c.Val.Str
		case VInt:
			t.Value = c.Val.Int
		case VBool:
			t.Value = c.Val.Bool
		case VList:
			t.Value = append([]string{}, c.Val.List...)
		case VRef:
			t.Value = map[string]string{"list": c.Val.Ref}
		}
		return t
	}
	t := &TreeNode{}
	switch n.Kind {
	case NAnd:
		t.Type = "and"
	case NOr:
		t.Type = "or"
	case NNot:
		t.Type = "not"
	}
	for _, k := range n.Kids {
		t.Children = append(t.Children, nodeTree(k))
	}
	return t
}

// ParseTreeJSON decodes a tree strictly (unknown members are errors; whole numbers only)
func ParseTreeJSON(data []byte) (*TreeNode, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var t TreeNode
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// FromTree validates a tree and builds the expression. Errors carry the path of the offending node.
func FromTree(t *TreeNode) (*Expr, *Error) {
	if t == nil {
		return nil, &Error{Path: "", Msg: "the tree is empty"}
	}
	b := &treeBuilder{}
	root, err := b.node(t, "", 1)
	if err != nil {
		return nil, err
	}
	x := &Expr{Root: root, nodes: b.nodes}
	// A tree has no text, so the limits on text length apply to the canonical text it produces
	if txt := x.Text(); len(txt) > MaxExprLen {
		return nil, &Error{Path: "", Msg: fmt.Sprintf("the expression is too long (%d bytes, the limit is %d)", len(txt), MaxExprLen)}
	}
	finishExpr(x)
	return x, nil
}

type treeBuilder struct{ nodes int }

func pathJoin(base string, i int) string {
	if base == "" {
		return "children[" + strconv.Itoa(i) + "]"
	}
	return base + ".children[" + strconv.Itoa(i) + "]"
}

func terr(path, format string, a ...any) *Error {
	return &Error{Path: path, Msg: fmt.Sprintf(format, a...)}
}

func (b *treeBuilder) node(t *TreeNode, path string, depth int) (*Node, *Error) {
	if depth > MaxDepth {
		return nil, terr(path, "nested too deeply (limit %d levels)", MaxDepth)
	}
	b.nodes++
	if b.nodes > MaxNodes {
		return nil, terr(path, "too many conditions and groups (limit %d)", MaxNodes)
	}
	typ := t.Type
	if typ == "" && t.Field != "" {
		typ = "cond"
	}
	switch typ {
	case "and", "or", "not":
		if t.Field != "" || t.Op != "" || t.Value != nil || t.Key != "" || t.Transform != "" {
			return nil, terr(path, "a %s group has children only", typ)
		}
		if len(t.Children) == 0 {
			return nil, terr(path, "an empty %s group", typ)
		}
		if typ == "not" && len(t.Children) != 1 {
			return nil, terr(path, "a not group has exactly one child (wrap several in an and / or group)")
		}
		var kids []*Node
		for i, c := range t.Children {
			if c == nil {
				return nil, terr(pathJoin(path, i), "null node")
			}
			k, err := b.node(c, pathJoin(path, i), depth+1)
			if err != nil {
				return nil, err
			}
			kids = append(kids, k)
		}
		if typ != "not" && len(kids) == 1 {
			b.nodes-- // collapsed
			return kids[0], nil
		}
		kind := NAnd
		switch typ {
		case "or":
			kind = NOr
		case "not":
			kind = NNot
		}
		return &Node{Kind: kind, Kids: kids}, nil
	case "cond":
		if len(t.Children) != 0 {
			return nil, terr(path, "a condition has no children")
		}
		if t.Transform != "" && t.Transform != "lower" {
			return nil, terr(path, `unknown transform %q (only "lower")`, t.Transform)
		}
		val, err := treeValue(t.Value)
		if err != nil {
			return nil, terr(path, "%v", err)
		}
		if t.Field == "" {
			return nil, terr(path, "a condition needs a field")
		}
		c, perr := buildCond(t.Field, t.Key, t.Transform == "lower", Op(t.Op), val, 0, 0)
		if perr != nil {
			return nil, terr(path, "%s", perr.Msg)
		}
		return &Node{Kind: NCond, C: c}, nil
	}
	return nil, terr(path, "unknown node type %q (and, or, not or cond)", t.Type)
}

func treeValue(v interface{}) (Value, error) {
	switch x := v.(type) {
	case nil:
		return Value{}, nil
	case string:
		if len(x) > MaxLiteralLen {
			return Value{}, fmt.Errorf("string value is too long (limit %d bytes)", MaxLiteralLen)
		}
		return Value{Kind: VString, Str: x}, nil
	case bool:
		return Value{Kind: VBool, Bool: x}, nil
	case json.Number:
		n, err := strconv.ParseInt(x.String(), 10, 64)
		if err != nil {
			return Value{}, fmt.Errorf("numbers must be whole")
		}
		return Value{Kind: VInt, Int: n}, nil
	case int:
		return Value{Kind: VInt, Int: int64(x)}, nil
	case int64:
		return Value{Kind: VInt, Int: x}, nil
	case float64:
		if x != float64(int64(x)) {
			return Value{}, fmt.Errorf("numbers must be whole")
		}
		return Value{Kind: VInt, Int: int64(x)}, nil
	case []string:
		return listValue(x)
	case []interface{}:
		items := make([]string, 0, len(x))
		for _, it := range x {
			s, ok := it.(string)
			if !ok {
				return Value{}, fmt.Errorf("list entries are strings")
			}
			items = append(items, s)
		}
		return listValue(items)
	case map[string]string:
		if n, ok := x["list"]; ok && len(x) == 1 {
			return refValue(n)
		}
	case map[string]interface{}:
		if n, ok := x["list"].(string); ok && len(x) == 1 {
			return refValue(n)
		}
	}
	return Value{}, fmt.Errorf("unsupported value")
}

func listValue(items []string) (Value, error) {
	if len(items) == 0 {
		return Value{}, fmt.Errorf("a list needs at least one entry")
	}
	if len(items) > MaxInlineList {
		return Value{}, fmt.Errorf("inline lists hold at most %d entries (use a named list)", MaxInlineList)
	}
	for _, s := range items {
		if len(s) > MaxLiteralLen {
			return Value{}, fmt.Errorf("list entry is too long")
		}
	}
	return Value{Kind: VList, List: items}, nil
}

func refValue(name string) (Value, error) {
	if !validListName(name) {
		return Value{}, fmt.Errorf("invalid list name %q", name)
	}
	return Value{Kind: VRef, Ref: name}, nil
}
