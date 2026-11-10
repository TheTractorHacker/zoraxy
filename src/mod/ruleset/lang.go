package ruleset

import (
	"fmt"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

/*
	lang.go

	The expression language: a small hand-written lexer and recursive descent parser, the AST, the
	canonical printer and the condition builder shared with the JSON tree form (tree.go).

	Grammar (keywords are lower case):

	  expr    = or
	  or      = and { "or" and }
	  and     = unary { "and" unary }
	  unary   = "not" unary | "(" expr ")" | cond
	  cond    = operand ( cmp value | wordop value | "in" list | "exists" | "not" ("contains"|"starts_with"|"ends_with"|"matches"|"in"|"exists") ... )
	  operand = [ "lower" "(" ] field [ "[" string "]" ] [ ")" ]
	  cmp     = "==" | "!=" | "<" | ">" | "<=" | ">="      (aliases: eq ne lt gt le ge)
	  value   = string | integer | "true" | "false"
	  list    = "[" string { "," string } "]" | "$" name

	There are no user defined functions, no arithmetic, no loops, no variables other than the named lists,
	and no way to reach anything but the typed fields. The parser is the only code that reads the text, so
	the limits below are enforced in one place.
*/

// Hard limits (also reported to the UI by Limits())
const (
	MaxExprLen    = 2000 // bytes of expression text
	MaxNodes      = 200  // groups + conditions
	MaxDepth      = 24   // nesting of groups
	MaxRegexLen   = 200  // bytes of one regular expression
	MaxRegexProg  = 1000 // compiled RE2 instructions
	MaxInlineList = 100  // entries of an inline list
	MaxLiteralLen = 1024 // bytes of a string literal
	MaxKeyLen     = 128  // bytes of an index key (header / cookie / argument name)
	maxListName   = 32
)

// Error is a validation error with a position in the text (byte offset) or a path in the JSON tree
type Error struct {
	Pos  int    `json:"pos"`
	End  int    `json:"end"`
	Path string `json:"path,omitempty"`
	Msg  string `json:"message"`
}

func (e *Error) Error() string {
	if e.Path != "" {
		return e.Path + ": " + e.Msg
	}
	return fmt.Sprintf("at %d: %s", e.Pos, e.Msg)
}

func errAt(pos, end int, format string, a ...any) *Error {
	return &Error{Pos: pos, End: end, Msg: fmt.Sprintf(format, a...)}
}

// Op is a comparison operator (the JSON names)
type Op string

const (
	OpEq            Op = "eq"
	OpNe            Op = "ne"
	OpLt            Op = "lt"
	OpGt            Op = "gt"
	OpLe            Op = "le"
	OpGe            Op = "ge"
	OpContains      Op = "contains"
	OpNotContains   Op = "not_contains"
	OpStartsWith    Op = "starts_with"
	OpNotStartsWith Op = "not_starts_with"
	OpEndsWith      Op = "ends_with"
	OpNotEndsWith   Op = "not_ends_with"
	OpMatches       Op = "matches"
	OpNotMatches    Op = "not_matches"
	OpIn            Op = "in"
	OpNotIn         Op = "not_in"
	OpExists        Op = "exists"
	OpNotExists     Op = "not_exists"
)

var opText = map[Op]string{
	OpEq: "==", OpNe: "!=", OpLt: "<", OpGt: ">", OpLe: "<=", OpGe: ">=",
	OpContains: "contains", OpNotContains: "not contains",
	OpStartsWith: "starts_with", OpNotStartsWith: "not starts_with",
	OpEndsWith: "ends_with", OpNotEndsWith: "not ends_with",
	OpMatches: "matches", OpNotMatches: "not matches",
	OpIn: "in", OpNotIn: "not in", OpExists: "exists", OpNotExists: "not exists",
}

// OpInfo describes an operator for the builder UI
type OpInfo struct {
	Op    Op     `json:"op"`
	Text  string `json:"text"`
	Types []Type `json:"types"`
	Value string `json:"value"` // string | int | bool | list | regex | none
}

// Operators lists the operators and the field types they apply to
func Operators() []OpInfo {
	s, i := []Type{TString}, []Type{TInt}
	return []OpInfo{
		{OpEq, "==", []Type{TString, TInt, TBool, TIP}, "value"}, {OpNe, "!=", []Type{TString, TInt, TBool, TIP}, "value"},
		{OpLt, "<", i, "int"}, {OpGt, ">", i, "int"}, {OpLe, "<=", i, "int"}, {OpGe, ">=", i, "int"},
		{OpContains, "contains", s, "string"}, {OpNotContains, "not contains", s, "string"},
		{OpStartsWith, "starts_with", s, "string"}, {OpNotStartsWith, "not starts_with", s, "string"},
		{OpEndsWith, "ends_with", s, "string"}, {OpNotEndsWith, "not ends_with", s, "string"},
		{OpMatches, "matches", s, "regex"}, {OpNotMatches, "not matches", s, "regex"},
		{OpIn, "in", []Type{TString, TIP}, "list"}, {OpNotIn, "not in", []Type{TString, TIP}, "list"},
		{OpExists, "exists", s, "none"}, {OpNotExists, "not exists", s, "none"},
	}
}

// ValueKind is the kind of a literal
type ValueKind int

const (
	VNone ValueKind = iota
	VString
	VInt
	VBool
	VList // inline list of strings
	VRef  // named list
)

// Value is the right hand side of a condition
type Value struct {
	Kind ValueKind
	Str  string
	Int  int64
	Bool bool
	List []string
	Ref  string
}

// NodeKind is the kind of an expression node
type NodeKind int

const (
	NCond NodeKind = iota + 1
	NAnd
	NOr
	NNot
)

// Node is one node of the expression tree
type Node struct {
	Kind NodeKind
	Kids []*Node
	C    *Cond
}

// Cond is one condition: [lower(] field [key] op value
type Cond struct {
	Field *FieldDef
	Key   string
	Lower bool
	Op    Op
	Val   Value
	Pos   int

	re    *regexp.Regexp
	set   map[string]struct{} // inline string list
	nets  *ipSet              // inline CIDR list
	ref   *List               // resolved named list
	addr  netip.Addr          // ip == literal
	nodes int
}

// Expr is a parsed and validated expression
type Expr struct {
	Root     *Node
	Fields   []string // distinct fields used (names, without keys)
	Lists    []string // named lists referenced
	Warnings []string
	nodes    int
}

// ---------------------------------------------------------------------
// lexer

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tString
	tInt
	tListRef
	tLParen
	tRParen
	tLBrack
	tRBrack
	tComma
	tCmp
)

type token struct {
	kind     tokKind
	text     string // identifier / operator / list name
	str      string // decoded string literal
	num      int64
	pos, end int
}

func (t token) describe() string {
	switch t.kind {
	case tEOF:
		return "end of expression"
	case tString:
		return "a string"
	case tInt:
		return "a number"
	}
	return strconv.Quote(t.text)
}

// forbiddenRune reports characters that are never accepted in the text, not even inside a string:
// control characters, format characters (zero width, bidi overrides, BOM), line / paragraph separators and
// every space other than the ASCII one. They can only be written with an escape inside a string.
func forbiddenRune(r rune) bool {
	if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	if r == utf8.RuneError || unicode.IsControl(r) {
		return true
	}
	return unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs, unicode.Co, unicode.Cs)
}

func lex(src string) ([]token, *Error) {
	if len(src) > MaxExprLen {
		return nil, errAt(MaxExprLen, len(src), "expression is too long (%d bytes, the limit is %d)", len(src), MaxExprLen)
	}
	if !utf8.ValidString(src) {
		return nil, errAt(0, len(src), "expression is not valid UTF-8")
	}
	var toks []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{kind: tLParen, text: "(", pos: i, end: i + 1})
			i++
		case c == ')':
			toks = append(toks, token{kind: tRParen, text: ")", pos: i, end: i + 1})
			i++
		case c == '[':
			toks = append(toks, token{kind: tLBrack, text: "[", pos: i, end: i + 1})
			i++
		case c == ']':
			toks = append(toks, token{kind: tRBrack, text: "]", pos: i, end: i + 1})
			i++
		case c == ',':
			toks = append(toks, token{kind: tComma, text: ",", pos: i, end: i + 1})
			i++
		case c == '"':
			s, n, err := lexString(src, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tString, str: s, text: src[i : i+n], pos: i, end: i + n})
			i += n
		case c == '$':
			j := i + 1
			for j < len(src) && (src[j] >= 'a' && src[j] <= 'z' || src[j] >= '0' && src[j] <= '9' || src[j] == '_') {
				j++
			}
			name := src[i+1 : j]
			if !validListName(name) {
				return nil, errAt(i, j, "invalid list name %q (lower case letters, digits and _, starting with a letter, at most %d characters)", src[i:j], maxListName)
			}
			toks = append(toks, token{kind: tListRef, text: name, pos: i, end: j})
			i = j
		case c >= '0' && c <= '9' || c == '-' && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9':
			j := i + 1
			for j < len(src) && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			if j-i > 16 {
				return nil, errAt(i, j, "number is too large")
			}
			n, _ := strconv.ParseInt(src[i:j], 10, 64)
			toks = append(toks, token{kind: tInt, num: n, text: src[i:j], pos: i, end: j})
			i = j
		case c == '=' || c == '!' || c == '<' || c == '>':
			j := i + 1
			if j < len(src) && src[j] == '=' {
				j++
			}
			op := src[i:j]
			switch op {
			case "==", "!=", "<", ">", "<=", ">=":
			case "=":
				return nil, errAt(i, j, `use "==" to compare`)
			default:
				return nil, errAt(i, j, "unexpected %q (use \"not\" for negation)", op)
			}
			toks = append(toks, token{kind: tCmp, text: op, pos: i, end: j})
			i = j
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_':
			j := i + 1
			for j < len(src) && (src[j] >= 'a' && src[j] <= 'z' || src[j] >= 'A' && src[j] <= 'Z' || src[j] >= '0' && src[j] <= '9' || src[j] == '_' || src[j] == '.') {
				j++
			}
			toks = append(toks, token{kind: tIdent, text: src[i:j], pos: i, end: j})
			i = j
		default:
			r, w := utf8.DecodeRuneInString(src[i:])
			if forbiddenRune(r) {
				return nil, errAt(i, i+w, "unexpected character U+%04X (only plain ASCII spaces are allowed outside strings; use \\u escapes inside strings)", r)
			}
			if c == '&' || c == '|' {
				return nil, errAt(i, i+w, "unexpected %q (write \"and\" / \"or\")", string(r))
			}
			return nil, errAt(i, i+w, "unexpected character %q", string(r))
		}
	}
	toks = append(toks, token{kind: tEOF, pos: len(src), end: len(src)})
	return toks, nil
}

func validListName(n string) bool {
	if n == "" || len(n) > maxListName || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// lexString decodes the string literal starting at src[start] == '"'. It returns the value and the bytes used.
func lexString(src string, start int) (string, int, *Error) {
	var b strings.Builder
	i := start + 1
	for i < len(src) {
		c := src[i]
		switch {
		case c == '"':
			return b.String(), i + 1 - start, nil
		case c == '\\':
			if i+1 >= len(src) {
				return "", 0, errAt(start, len(src), "unterminated string")
			}
			switch src[i+1] {
			case '\\', '"':
				b.WriteByte(src[i+1])
				i += 2
			case 'n':
				b.WriteByte('\n')
				i += 2
			case 'r':
				b.WriteByte('\r')
				i += 2
			case 't':
				b.WriteByte('\t')
				i += 2
			case 'x':
				if i+3 >= len(src) {
					return "", 0, errAt(i, len(src), `\x needs two hex digits`)
				}
				v, err := strconv.ParseUint(src[i+2:i+4], 16, 8)
				if err != nil || v > 0x7f {
					return "", 0, errAt(i, i+4, `\x escapes must be 00-7f (write other characters with \u)`)
				}
				b.WriteByte(byte(v))
				i += 4
			case 'u', 'U':
				n := 4
				if src[i+1] == 'U' {
					n = 8
				}
				if i+2+n > len(src) {
					return "", 0, errAt(i, len(src), `\%c needs %d hex digits`, src[i+1], n)
				}
				v, err := strconv.ParseUint(src[i+2:i+2+n], 16, 32)
				if err != nil || v > unicode.MaxRune || (v >= 0xd800 && v <= 0xdfff) {
					return "", 0, errAt(i, i+2+n, "invalid unicode escape")
				}
				b.WriteRune(rune(v))
				i += 2 + n
			default:
				return "", 0, errAt(i, i+2, `unknown escape \%c`, src[i+1])
			}
		default:
			r, w := utf8.DecodeRuneInString(src[i:])
			if forbiddenRune(r) {
				return "", 0, errAt(i, i+w, "invisible or control character U+%04X in a string (write it as an escape)", r)
			}
			b.WriteString(src[i : i+w])
			i += w
		}
		if b.Len() > MaxLiteralLen {
			return "", 0, errAt(start, i, "string literal is too long (limit %d bytes)", MaxLiteralLen)
		}
	}
	return "", 0, errAt(start, len(src), "unterminated string")
}

// Quote renders s as a string literal of the expression language
func Quote(s string) string { return quote(s) }

// quote renders a string literal that lex reads back to the same value
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r == ' ':
			b.WriteByte(' ')
		case forbiddenRune(r):
			if r > 0xffff {
				fmt.Fprintf(&b, `\U%08x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---------------------------------------------------------------------
// parser

type parser struct {
	toks  []token
	i     int
	depth int
	nodes int
	x     *Expr
}

// Parse reads the text form. The result is validated (types, regular expressions, lists syntax) but list
// references are not resolved yet, see Link.
func Parse(src string) (*Expr, *Error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	if len(toks) == 1 {
		return nil, errAt(0, 0, "the expression is empty")
	}
	p := &parser{toks: toks, x: &Expr{}}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, errAt(t.pos, t.end, "unexpected %s (expected \"and\", \"or\" or the end of the expression)", t.describe())
	}
	p.x.Root = root
	p.x.nodes = p.nodes
	finishExpr(p.x)
	return p.x, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) isWord(w string) bool {
	t := p.peek()
	return t.kind == tIdent && t.text == w
}

func (p *parser) countNode(t token) *Error {
	p.nodes++
	if p.nodes > MaxNodes {
		return errAt(t.pos, t.end, "expression is too complex (more than %d conditions and groups)", MaxNodes)
	}
	return nil
}

func (p *parser) enter(t token) *Error {
	p.depth++
	if p.depth > MaxDepth {
		return errAt(t.pos, t.end, "expression is nested too deeply (limit %d levels)", MaxDepth)
	}
	return nil
}

func (p *parser) parseOr() (*Node, *Error) {
	if err := p.enter(p.peek()); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	first, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	if !p.isWord("or") {
		return first, nil
	}
	n := &Node{Kind: NOr, Kids: []*Node{first}}
	for p.isWord("or") {
		t := p.next()
		if err := p.countNode(t); err != nil {
			return nil, err
		}
		k, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		n.Kids = append(n.Kids, k)
	}
	return n, nil
}

func (p *parser) parseAnd() (*Node, *Error) {
	first, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	if !p.isWord("and") {
		return first, nil
	}
	n := &Node{Kind: NAnd, Kids: []*Node{first}}
	for p.isWord("and") {
		t := p.next()
		if err := p.countNode(t); err != nil {
			return nil, err
		}
		k, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		n.Kids = append(n.Kids, k)
	}
	return n, nil
}

func (p *parser) parseUnary() (*Node, *Error) {
	t := p.peek()
	if err := p.enter(t); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	switch {
	case t.kind == tIdent && t.text == "not":
		p.next()
		if err := p.countNode(t); err != nil {
			return nil, err
		}
		k, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &Node{Kind: NNot, Kids: []*Node{k}}, nil
	case t.kind == tLParen:
		p.next()
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if c := p.next(); c.kind != tRParen {
			return nil, errAt(c.pos, c.end, "expected \")\" but found %s", c.describe())
		}
		return n, nil
	}
	return p.parseCond()
}

var wordOps = map[string]Op{
	"eq": OpEq, "ne": OpNe, "lt": OpLt, "gt": OpGt, "le": OpLe, "ge": OpGe,
	"contains": OpContains, "starts_with": OpStartsWith, "ends_with": OpEndsWith,
	"matches": OpMatches, "in": OpIn, "exists": OpExists,
}
var cmpOps = map[string]Op{"==": OpEq, "!=": OpNe, "<": OpLt, ">": OpGt, "<=": OpLe, ">=": OpGe}

func negate(op Op) (Op, bool) {
	switch op {
	case OpContains:
		return OpNotContains, true
	case OpStartsWith:
		return OpNotStartsWith, true
	case OpEndsWith:
		return OpNotEndsWith, true
	case OpMatches:
		return OpNotMatches, true
	case OpIn:
		return OpNotIn, true
	case OpExists:
		return OpNotExists, true
	}
	return "", false
}

func (p *parser) parseCond() (*Node, *Error) {
	start := p.peek()
	if err := p.countNode(start); err != nil {
		return nil, err
	}
	lower := false
	t := p.next()
	if t.kind != tIdent {
		return nil, errAt(t.pos, t.end, "expected a field name (for example http.path) but found %s", t.describe())
	}
	if t.text == "lower" {
		if p.peek().kind != tLParen {
			return nil, errAt(t.pos, t.end, `"lower" is a function: write lower(http.path)`)
		}
		p.next()
		lower = true
		t = p.next()
		if t.kind != tIdent {
			return nil, errAt(t.pos, t.end, "lower() takes a field, found %s", t.describe())
		}
	}
	fieldTok := t
	key, keyTok := "", token{}
	if p.peek().kind == tLBrack {
		p.next()
		kt := p.next()
		if kt.kind != tString {
			return nil, errAt(kt.pos, kt.end, `expected a quoted name such as ["x-api-key"]`)
		}
		key, keyTok = kt.str, kt
		if c := p.next(); c.kind != tRBrack {
			return nil, errAt(c.pos, c.end, `expected "]"`)
		}
	}
	if lower {
		if c := p.next(); c.kind != tRParen {
			return nil, errAt(c.pos, c.end, `expected ")" after the field inside lower(`)
		}
	}
	opTok := p.peek()
	var op Op
	switch {
	case opTok.kind == tCmp:
		p.next()
		op = cmpOps[opTok.text]
	case opTok.kind == tIdent && opTok.text == "not":
		p.next()
		w := p.next()
		base, ok := wordOps[w.text]
		neg, ok2 := negate(base)
		if w.kind != tIdent || !ok || !ok2 {
			return nil, errAt(w.pos, w.end, `"not" can be followed by contains, starts_with, ends_with, matches, in or exists, found %s`, w.describe())
		}
		op = neg
	case opTok.kind == tIdent && wordOps[opTok.text] != "":
		p.next()
		op = wordOps[opTok.text]
	default:
		// a bare boolean field means "== true"
		if f := fieldByName[fieldTok.text]; f != nil && f.Type == TBool && !lower && key == "" && (opTok.kind == tEOF || opTok.kind == tRParen || opTok.kind == tIdent && (opTok.text == "and" || opTok.text == "or")) {
			c, err := buildCond(fieldTok.text, "", false, OpEq, Value{Kind: VBool, Bool: true}, fieldTok.pos, opTok.pos)
			if err != nil {
				return nil, err
			}
			return &Node{Kind: NCond, C: c}, nil
		}
		return nil, errAt(opTok.pos, opTok.end, "expected an operator (==, !=, contains, starts_with, ends_with, matches, in, exists ...) but found %s", opTok.describe())
	}

	val := Value{}
	switch op {
	case OpExists, OpNotExists:
	case OpIn, OpNotIn:
		v, err := p.parseList()
		if err != nil {
			return nil, err
		}
		val = v
	default:
		vt := p.next()
		switch vt.kind {
		case tString:
			val = Value{Kind: VString, Str: vt.str}
		case tInt:
			val = Value{Kind: VInt, Int: vt.num}
		case tIdent:
			if vt.text == "true" || vt.text == "false" {
				val = Value{Kind: VBool, Bool: vt.text == "true"}
			} else {
				return nil, errAt(vt.pos, vt.end, "expected a value (a quoted string, a number, true or false) but found %s; fields cannot be compared with each other", vt.describe())
			}
		default:
			return nil, errAt(vt.pos, vt.end, "expected a value but found %s", vt.describe())
		}
	}
	c, err := buildCond(fieldTok.text, key, lower, op, val, fieldTok.pos, p.toks[p.i-1].end)
	if err != nil {
		return nil, err
	}
	_ = keyTok
	return &Node{Kind: NCond, C: c}, nil
}

func (p *parser) parseList() (Value, *Error) {
	t := p.next()
	switch t.kind {
	case tListRef:
		return Value{Kind: VRef, Ref: t.text}, nil
	case tLBrack:
		var items []string
		if p.peek().kind == tRBrack {
			return Value{}, errAt(t.pos, p.peek().end, "a list needs at least one entry")
		}
		for {
			it := p.next()
			if it.kind != tString {
				return Value{}, errAt(it.pos, it.end, "list entries are quoted strings, found %s", it.describe())
			}
			items = append(items, it.str)
			if len(items) > MaxInlineList {
				return Value{}, errAt(it.pos, it.end, "inline lists hold at most %d entries (use a named list)", MaxInlineList)
			}
			c := p.next()
			if c.kind == tRBrack {
				break
			}
			if c.kind != tComma {
				return Value{}, errAt(c.pos, c.end, `expected "," or "]"`)
			}
		}
		return Value{Kind: VList, List: items}, nil
	}
	return Value{}, errAt(t.pos, t.end, `expected a list such as ["a", "b"] or a named list such as $office, found %s`, t.describe())
}

// ---------------------------------------------------------------------
// condition builder (shared by the text and the tree front ends)

var countryRe = regexp.MustCompile(`^[A-Z][A-Z0-9]$`)

// buildCond validates a condition and precompiles its regular expression / address sets
func buildCond(fieldName, key string, lower bool, op Op, val Value, pos, end int) (*Cond, *Error) {
	f := fieldByName[fieldName]
	if f == nil {
		if why, ok := unavailableFields[fieldName]; ok {
			return nil, errAt(pos, pos+len(fieldName), "%s", why)
		}
		return nil, errAt(pos, pos+len(fieldName), "unknown field %q", fieldName)
	}
	fe := pos + len(fieldName)
	if f.Indexed && key == "" {
		return nil, errAt(pos, fe, `%s needs a name, for example %s["name"]`, f.Name, f.Name)
	}
	if !f.Indexed && key != "" {
		return nil, errAt(pos, fe, "%s does not take a name", f.Name)
	}
	if len(key) > MaxKeyLen || strings.ContainsAny(key, "\x00\r\n") {
		return nil, errAt(pos, end, "invalid name for %s", f.Name)
	}
	if f.Indexed && f.id == fHeader {
		if !validToken(key) {
			return nil, errAt(pos, end, "%q is not a valid header name", key)
		}
	}
	if lower && f.Type != TString {
		return nil, errAt(pos, end, "lower() only applies to text fields, %s is %s", f.Name, f.Type)
	}
	c := &Cond{Field: f, Key: key, Lower: lower, Op: op, Val: val, Pos: pos}

	typeErr := func() *Error {
		return errAt(pos, end, "operator %q cannot be used with %s (%s)", opText[op], f.Name, f.Type)
	}
	valErr := func(want string) *Error {
		return errAt(pos, end, "%s %s needs %s", f.Name, opText[op], want)
	}
	switch op {
	case OpExists, OpNotExists:
		if !f.Indexed {
			return nil, errAt(pos, end, "%q only applies to header, cookie and query argument fields (other fields always exist)", opText[op])
		}
		if val.Kind != VNone {
			return nil, valErr("no value")
		}
	case OpEq, OpNe:
		switch f.Type {
		case TString:
			if val.Kind != VString {
				return nil, valErr("a quoted string")
			}
		case TInt:
			if val.Kind != VInt {
				return nil, valErr("a number")
			}
		case TBool:
			if val.Kind != VBool {
				return nil, valErr("true or false")
			}
		case TIP:
			if val.Kind != VString {
				return nil, valErr(`an address in quotes, such as "203.0.113.5" (use "in" for networks)`)
			}
			a, ok := parseAddr(val.Str)
			if !ok {
				return nil, valErr("a valid IP address")
			}
			c.addr = a
		}
	case OpLt, OpGt, OpLe, OpGe:
		if f.Type != TInt {
			return nil, typeErr()
		}
		if val.Kind != VInt {
			return nil, valErr("a number")
		}
	case OpContains, OpNotContains, OpStartsWith, OpNotStartsWith, OpEndsWith, OpNotEndsWith:
		if f.Type != TString {
			return nil, typeErr()
		}
		if val.Kind != VString {
			return nil, valErr("a quoted string")
		}
	case OpMatches, OpNotMatches:
		if f.Type != TString {
			return nil, typeErr()
		}
		if val.Kind != VString {
			return nil, valErr("a quoted regular expression (RE2 syntax)")
		}
		re, err := compileRegex(val.Str)
		if err != nil {
			return nil, errAt(pos, end, "invalid regular expression: %v", err)
		}
		c.re = re
	case OpIn, OpNotIn:
		if f.Type != TString && f.Type != TIP {
			return nil, typeErr()
		}
		switch val.Kind {
		case VRef:
			// resolved later by Link
		case VList:
			if f.Type == TIP {
				set, err := newIPSet(val.List)
				if err != nil {
					return nil, errAt(pos, end, "%v", err)
				}
				c.nets = set
			} else {
				c.set = make(map[string]struct{}, len(val.List))
				for _, s := range val.List {
					c.set[s] = struct{}{}
				}
			}
		default:
			return nil, valErr("a list")
		}
	default:
		return nil, errAt(pos, end, "unknown operator %q", op)
	}
	if f.Country && val.Kind == VString {
		if !countryRe.MatchString(val.Str) {
			return nil, errAt(pos, end, "country codes are two upper case letters such as US (got %q)", val.Str)
		}
	}
	if f.Country && val.Kind == VList {
		for _, s := range val.List {
			if !countryRe.MatchString(s) {
				return nil, errAt(pos, end, "country codes are two upper case letters such as US (got %q)", s)
			}
		}
	}
	if (op == OpContains || op == OpNotContains || op == OpStartsWith || op == OpNotStartsWith || op == OpEndsWith || op == OpNotEndsWith) && f.Country {
		return nil, typeErr()
	}
	return c, nil
}

// validToken reports whether s is an RFC 9110 token (header / cookie name)
func validToken(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return false
		}
	}
	return true
}

// compileRegex compiles RE2 syntax only (Go's regexp has no backtracking engine), bounded in size
func compileRegex(src string) (*regexp.Regexp, error) {
	if src == "" {
		return nil, fmt.Errorf("the pattern is empty")
	}
	if len(src) > MaxRegexLen {
		return nil, fmt.Errorf("the pattern is longer than %d bytes", MaxRegexLen)
	}
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil, err
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, err
	}
	if len(prog.Inst) > MaxRegexProg {
		return nil, fmt.Errorf("the pattern is too large once compiled (%d steps, limit %d)", len(prog.Inst), MaxRegexProg)
	}
	return regexp.Compile(src)
}

// regexExpensive returns a reason when the pattern is likely to be slow on long input
func regexExpensive(src string) string {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return ""
	}
	if prog, err := syntax.Compile(re.Simplify()); err == nil && len(prog.Inst) > 300 {
		return fmt.Sprintf("this regular expression is large (%d steps) and costs time on every request", len(prog.Inst))
	}
	var walk func(r *syntax.Regexp, inRepeat bool) string
	walk = func(r *syntax.Regexp, inRepeat bool) string {
		rep := r.Op == syntax.OpStar || r.Op == syntax.OpPlus || r.Op == syntax.OpRepeat
		if rep && inRepeat {
			return "this regular expression has nested repetition such as (a+)+; it is safe (RE2 runs in linear time) but slow on long input"
		}
		if r.Op == syntax.OpRepeat && r.Max > 100 {
			return "this regular expression repeats a part more than 100 times, which makes it large"
		}
		for _, s := range r.Sub {
			if m := walk(s, inRepeat || rep); m != "" {
				return m
			}
		}
		return ""
	}
	return walk(re, false)
}

// ---------------------------------------------------------------------
// printer (the canonical text)

// Text renders the expression in its canonical form. Parsing the result gives the same tree.
func (x *Expr) Text() string { return printNode(x.Root, 0) }

func printNode(n *Node, parent NodeKind) string {
	switch n.Kind {
	case NCond:
		return n.C.Text()
	case NNot:
		return "not (" + printNode(n.Kids[0], 0) + ")"
	}
	sep := " and "
	if n.Kind == NOr {
		sep = " or "
	}
	parts := make([]string, len(n.Kids))
	for i, k := range n.Kids {
		parts[i] = printNode(k, n.Kind)
	}
	s := strings.Join(parts, sep)
	// An And inside an Or needs no parentheses (and binds tighter); any other group inside a group does
	if parent == NAnd || (parent == NOr && n.Kind == NOr) {
		return "(" + s + ")"
	}
	return s
}

func (c *Cond) operand() string {
	s := c.Field.Name
	if c.Key != "" {
		s += "[" + quote(c.Key) + "]"
	}
	if c.Lower {
		s = "lower(" + s + ")"
	}
	return s
}

// Text renders one condition
func (c *Cond) Text() string {
	s := c.operand() + " " + opText[c.Op]
	switch c.Val.Kind {
	case VString:
		s += " " + quote(c.Val.Str)
	case VInt:
		s += " " + strconv.FormatInt(c.Val.Int, 10)
	case VBool:
		s += " " + strconv.FormatBool(c.Val.Bool)
	case VRef:
		s += " $" + c.Val.Ref
	case VList:
		items := make([]string, len(c.Val.List))
		for i, it := range c.Val.List {
			items[i] = quote(it)
		}
		s += " [" + strings.Join(items, ", ") + "]"
	}
	return s
}

// finishExpr collects the used fields / lists and the warnings
func finishExpr(x *Expr) {
	fields := map[string]bool{}
	lists := map[string]bool{}
	var walk func(n *Node)
	walk = func(n *Node) {
		if n.Kind == NCond {
			fields[n.C.Field.Name] = true
			if n.C.Val.Kind == VRef {
				lists[n.C.Val.Ref] = true
			}
			return
		}
		for _, k := range n.Kids {
			walk(k)
		}
	}
	walk(x.Root)
	x.Fields, x.Lists = nil, nil
	for f := range fields {
		x.Fields = append(x.Fields, f)
	}
	for l := range lists {
		x.Lists = append(x.Lists, l)
	}
	sort.Strings(x.Fields)
	sort.Strings(x.Lists)
	x.Warnings = analyze(x.Root)
}
