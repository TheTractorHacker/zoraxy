package luascript

import (
	"strings"

	lua "github.com/yuin/gopher-lua"
)

/*
	lpattern.go

	Lua 5.1 pattern matching (a port of lstrlib.c) with a step budget and a recursion cap.

	The pattern functions that ship with gopher-lua can backtrack exponentially ("a*a*a*a*b" on a long run of "a"),
	and a native call cannot be interrupted by the context deadline. This matcher counts steps and aborts with an error
	when the budget is used up, so a hostile pattern costs at most maxPatternSteps iterations.
*/

const (
	maxCaptures     = 32
	capUnfinished   = -1
	capPosition     = -2
	maxMatchDepth   = 200
	maxPatternSteps = 400000
	maxPatternBytes = 256
	maxSubjectBytes = 256 * 1024
)

type matcher struct {
	src, pat string
	level    int
	capInit  [maxCaptures]int
	capLen   [maxCaptures]int
	steps    int
	depth    int
}

type matchError struct{ msg string }

func (m *matcher) fail(msg string) { panic(matchError{msg}) }

func (m *matcher) reset() { m.level = 0 }

func isalpha(c byte) bool  { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isdigit(c byte) bool  { return c >= '0' && c <= '9' }
func islower(c byte) bool  { return c >= 'a' && c <= 'z' }
func isupper(c byte) bool  { return c >= 'A' && c <= 'Z' }
func isspace(c byte) bool  { return c == ' ' || c >= 9 && c <= 13 }
func iscntrl(c byte) bool  { return c < 32 || c == 127 }
func isalnum(c byte) bool  { return isalpha(c) || isdigit(c) }
func isxdigit(c byte) bool { return isdigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func ispunct(c byte) bool  { return c > 32 && c < 127 && !isalnum(c) }

func matchClass(c, cl byte) bool {
	var res bool
	lower := cl | 0x20
	switch lower {
	case 'a':
		res = isalpha(c)
	case 'c':
		res = iscntrl(c)
	case 'd':
		res = isdigit(c)
	case 'l':
		res = islower(c)
	case 'p':
		res = ispunct(c)
	case 's':
		res = isspace(c)
	case 'u':
		res = isupper(c)
	case 'w':
		res = isalnum(c)
	case 'x':
		res = isxdigit(c)
	case 'z':
		res = c == 0
	default:
		return cl == c
	}
	if isupper(cl) {
		return !res
	}
	return res
}

func (m *matcher) classEnd(p int) int {
	if p >= len(m.pat) {
		m.fail("malformed pattern")
	}
	c := m.pat[p]
	p++
	switch c {
	case '%':
		if p >= len(m.pat) {
			m.fail("malformed pattern (ends with '%')")
		}
		return p + 1
	case '[':
		if p < len(m.pat) && m.pat[p] == '^' {
			p++
		}
		for {
			if p >= len(m.pat) {
				m.fail("malformed pattern (missing ']')")
			}
			cc := m.pat[p]
			p++
			if cc == '%' && p < len(m.pat) {
				p++
			}
			if p < len(m.pat) && m.pat[p] == ']' {
				break
			}
			if p >= len(m.pat) {
				m.fail("malformed pattern (missing ']')")
			}
		}
		return p + 1
	}
	return p
}

func (m *matcher) matchBracketClass(c byte, p, ec int) bool {
	sig := true
	if m.pat[p+1] == '^' {
		sig = false
		p++
	}
	for p++; p < ec; p++ {
		if m.pat[p] == '%' {
			p++
			if matchClass(c, m.pat[p]) {
				return sig
			}
		} else if p+2 < ec && m.pat[p+1] == '-' {
			p += 2
			if m.pat[p-2] <= c && c <= m.pat[p] {
				return sig
			}
		} else if m.pat[p] == c {
			return sig
		}
	}
	return !sig
}

func (m *matcher) singleMatch(c byte, p, ep int) bool {
	switch m.pat[p] {
	case '.':
		return true
	case '%':
		return matchClass(c, m.pat[p+1])
	case '[':
		return m.matchBracketClass(c, p, ep-1)
	}
	return m.pat[p] == c
}

func (m *matcher) matchBalance(s, p int) int {
	if p+1 >= len(m.pat) {
		m.fail("unbalanced pattern")
	}
	if s >= len(m.src) || m.src[s] != m.pat[p] {
		return -1
	}
	b, e := m.pat[p], m.pat[p+1]
	cont := 1
	for s++; s < len(m.src); s++ {
		if m.src[s] == e {
			cont--
			if cont == 0 {
				return s + 1
			}
		} else if m.src[s] == b {
			cont++
		}
	}
	return -1
}

func (m *matcher) maxExpand(s, p, ep int) int {
	i := 0
	for s+i < len(m.src) && m.singleMatch(m.src[s+i], p, ep) {
		i++
		m.step()
	}
	for i >= 0 {
		if res := m.do(s+i, ep+1); res != -1 {
			return res
		}
		i--
	}
	return -1
}

func (m *matcher) minExpand(s, p, ep int) int {
	for {
		if res := m.do(s, ep+1); res != -1 {
			return res
		}
		if s < len(m.src) && m.singleMatch(m.src[s], p, ep) {
			s++
			m.step()
		} else {
			return -1
		}
	}
}

func (m *matcher) startCapture(s, p, what int) int {
	if m.level >= maxCaptures {
		m.fail("too many captures")
	}
	m.capInit[m.level] = s
	m.capLen[m.level] = what
	m.level++
	res := m.do(s, p)
	if res == -1 {
		m.level--
	}
	return res
}

func (m *matcher) captureToClose() int {
	for l := m.level - 1; l >= 0; l-- {
		if m.capLen[l] == capUnfinished {
			return l
		}
	}
	m.fail("invalid pattern capture")
	return 0
}

func (m *matcher) endCapture(s, p int) int {
	l := m.captureToClose()
	m.capLen[l] = s - m.capInit[l]
	res := m.do(s, p)
	if res == -1 {
		m.capLen[l] = capUnfinished
	}
	return res
}

func (m *matcher) matchCapture(s int, l byte) int {
	idx := int(l) - '1'
	if idx < 0 || idx >= m.level || m.capLen[idx] == capUnfinished {
		m.fail("invalid capture index")
	}
	n := m.capLen[idx]
	if n < 0 {
		m.fail("invalid capture index")
	}
	if len(m.src)-s >= n && m.src[m.capInit[idx]:m.capInit[idx]+n] == m.src[s:s+n] {
		return s + n
	}
	return -1
}

func (m *matcher) step() {
	m.steps++
	if m.steps > maxPatternSteps {
		m.fail("pattern too complex")
	}
}

// do returns the end index of the match of pat[p:] at src[s:], or -1
func (m *matcher) do(s, p int) int {
	m.depth++
	if m.depth > maxMatchDepth {
		m.fail("pattern too complex")
	}
	defer func() { m.depth-- }()
	for {
		m.step()
		if p >= len(m.pat) {
			return s
		}
		dflt := false
		switch m.pat[p] {
		case '(':
			if p+1 < len(m.pat) && m.pat[p+1] == ')' {
				return m.startCapture(s, p+2, capPosition)
			}
			return m.startCapture(s, p+1, capUnfinished)
		case ')':
			return m.endCapture(s, p+1)
		case '$':
			if p+1 == len(m.pat) {
				if s == len(m.src) {
					return s
				}
				return -1
			}
			dflt = true
		case '%':
			if p+1 < len(m.pat) {
				switch c := m.pat[p+1]; {
				case c == 'b':
					s = m.matchBalance(s, p+2)
					if s != -1 {
						p += 4
						continue
					}
					return -1
				case c == 'f':
					p += 2
					if p >= len(m.pat) || m.pat[p] != '[' {
						m.fail("missing '[' after '%f' in pattern")
					}
					ep := m.classEnd(p)
					var prev, cur byte
					if s > 0 {
						prev = m.src[s-1]
					}
					if s < len(m.src) {
						cur = m.src[s]
					}
					if !m.matchBracketClass(prev, p, ep-1) && m.matchBracketClass(cur, p, ep-1) {
						p = ep
						continue
					}
					return -1
				case isdigit(c):
					s = m.matchCapture(s, c)
					if s != -1 {
						p += 2
						continue
					}
					return -1
				}
			}
			dflt = true
		default:
			dflt = true
		}
		if !dflt {
			continue
		}
		ep := m.classEnd(p)
		var epc byte
		if ep < len(m.pat) {
			epc = m.pat[ep]
		}
		if !(s < len(m.src) && m.singleMatch(m.src[s], p, ep)) {
			if epc == '*' || epc == '?' || epc == '-' {
				p = ep + 1
				continue
			}
			return -1
		}
		switch epc {
		case '?':
			if res := m.do(s+1, ep+1); res != -1 {
				return res
			}
			p = ep + 1
			continue
		case '+':
			return m.maxExpand(s+1, p, ep)
		case '*':
			return m.maxExpand(s, p, ep)
		case '-':
			return m.minExpand(s, p, ep)
		}
		s++
		p = ep
	}
}

func (m *matcher) capture(L *lua.LState, i, s, e int) lua.LValue {
	if i >= m.level {
		if i == 0 {
			return lua.LString(m.src[s:e])
		}
		m.fail("invalid capture index")
	}
	l := m.capLen[i]
	if l == capUnfinished {
		m.fail("unfinished capture")
	}
	if l == capPosition {
		return lua.LNumber(m.capInit[i] + 1)
	}
	return lua.LString(m.src[m.capInit[i] : m.capInit[i]+l])
}

func (m *matcher) pushCaptures(L *lua.LState, s, e int, wholeIfNone bool) int {
	n := m.level
	if n == 0 && wholeIfNone {
		n = 1
	}
	for i := 0; i < n; i++ {
		L.Push(m.capture(L, i, s, e))
	}
	return n
}

func hasSpecials(p string) bool { return strings.ContainsAny(p, "^$*+?.([%-") }

// guard converts matcher failures into Lua errors
func guard(L *lua.LState, f func() int) (n int) {
	defer func() {
		if r := recover(); r != nil {
			if me, ok := r.(matchError); ok {
				L.RaiseError("%s", me.msg)
			}
			panic(r)
		}
	}()
	return f()
}

func checkPatArgs(L *lua.LState) (string, string) {
	s := L.CheckString(1)
	p := L.CheckString(2)
	if len(s) > maxSubjectBytes {
		L.ArgError(1, "subject too long")
	}
	if len(p) > maxPatternBytes {
		L.ArgError(2, "pattern too long")
	}
	return s, p
}

func strFindAux(L *lua.LState, find bool) int {
	s, p := checkPatArgs(L)
	init := L.OptInt(3, 1)
	if init < 0 {
		init = len(s) + init + 1
		if init < 1 {
			init = 1
		}
	} else if init == 0 {
		init = 1
	}
	init--
	if init > len(s) {
		L.Push(lua.LNil)
		return 1
	}
	if find && (lua.LVAsBool(L.Get(4)) || !hasSpecials(p)) {
		idx := strings.Index(s[init:], p)
		if idx < 0 {
			L.Push(lua.LNil)
			return 1
		}
		L.Push(lua.LNumber(init + idx + 1))
		L.Push(lua.LNumber(init + idx + len(p)))
		return 2
	}
	return guard(L, func() int {
		m := &matcher{src: s, pat: p}
		anchor := len(p) > 0 && p[0] == '^'
		pstart := 0
		if anchor {
			pstart = 1
		}
		for s1 := init; s1 <= len(s); s1++ {
			m.reset()
			if e := m.do(s1, pstart); e != -1 {
				if find {
					L.Push(lua.LNumber(s1 + 1))
					L.Push(lua.LNumber(e))
					return m.pushCaptures(L, -1, -1, false) + 2
				}
				return m.pushCaptures(L, s1, e, true)
			}
			if anchor {
				break
			}
		}
		L.Push(lua.LNil)
		return 1
	})
}

func strFind(L *lua.LState) int  { return strFindAux(L, true) }
func strMatch(L *lua.LState) int { return strFindAux(L, false) }

func strGmatch(L *lua.LState) int {
	s, p := checkPatArgs(L)
	pos := 0
	steps := 0
	iter := func(L *lua.LState) int {
		return guard(L, func() int {
			m := &matcher{src: s, pat: p}
			for src := pos; src <= len(s); src++ {
				m.reset()
				m.steps = steps
				e := m.do(src, 0)
				steps = m.steps
				if e != -1 {
					if e == src {
						pos = e + 1
					} else {
						pos = e
					}
					return m.pushCaptures(L, src, e, true)
				}
			}
			pos = len(s) + 1
			return 0
		})
	}
	L.Push(L.NewFunction(iter))
	return 1
}

const maxGsubResult = 1 << 20

func strGsub(L *lua.LState) int {
	s, p := checkPatArgs(L)
	repl := L.Get(3)
	switch repl.Type() {
	case lua.LTString, lua.LTNumber, lua.LTTable, lua.LTFunction:
	default:
		L.ArgError(3, "string/function/table expected")
	}
	maxN := L.OptInt(4, len(s)+1)
	return guard(L, func() int {
		m := &matcher{src: s, pat: p}
		anchor := len(p) > 0 && p[0] == '^'
		pstart := 0
		if anchor {
			pstart = 1
		}
		var b strings.Builder
		src, n := 0, 0
		for n < maxN {
			m.reset()
			e := m.do(src, pstart)
			if e != -1 {
				n++
				addValue(L, m, &b, repl, src, e)
				if b.Len() > maxGsubResult {
					L.RaiseError("result too large")
				}
			}
			if e != -1 && e > src {
				src = e
			} else if src < len(s) {
				b.WriteByte(s[src])
				src++
			} else {
				break
			}
			if anchor {
				break
			}
		}
		b.WriteString(s[src:])
		if b.Len() > maxGsubResult {
			L.RaiseError("result too large")
		}
		L.Push(lua.LString(b.String()))
		L.Push(lua.LNumber(n))
		return 2
	})
}

func addValue(L *lua.LState, m *matcher, b *strings.Builder, repl lua.LValue, s, e int) {
	var val lua.LValue
	switch repl.Type() {
	case lua.LTString, lua.LTNumber:
		r := lua.LVAsString(repl)
		for i := 0; i < len(r); i++ {
			if r[i] != '%' {
				b.WriteByte(r[i])
				continue
			}
			i++
			if i >= len(r) {
				L.RaiseError("invalid use of '%%' in replacement string")
			}
			switch {
			case r[i] == '%':
				b.WriteByte('%')
			case isdigit(r[i]):
				if r[i] == '0' {
					b.WriteString(m.src[s:e])
				} else {
					v := m.capture(L, int(r[i]-'1'), s, e)
					b.WriteString(lua.LVAsString(v))
				}
			default:
				L.RaiseError("invalid use of '%%' in replacement string")
			}
		}
		return
	case lua.LTTable:
		val = L.GetTable(repl, m.capture(L, 0, s, e))
	case lua.LTFunction:
		L.Push(repl)
		n := m.pushCaptures(L, s, e, true)
		L.Call(n, 1)
		val = L.Get(-1)
		L.Pop(1)
	}
	switch val.Type() {
	case lua.LTNil:
		b.WriteString(m.src[s:e])
	case lua.LTBool:
		if lua.LVAsBool(val) {
			L.RaiseError("invalid replacement value (a boolean)")
		}
		b.WriteString(m.src[s:e])
	case lua.LTString, lua.LTNumber:
		b.WriteString(lua.LVAsString(val))
	default:
		L.RaiseError("invalid replacement value (a %s)", val.Type().String())
	}
}
