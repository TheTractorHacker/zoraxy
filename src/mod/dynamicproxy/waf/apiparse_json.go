package waf

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

/*
	apiparse_json.go

	Bounded, allocation-free JSON structure checker. It never builds a tree
	and stops at the first violation, so a 10 MB deeply nested payload is
	rejected after reading a few dozen bytes. Memory is O(nesting depth) plus
	the key set of one object when duplicate key detection is on (bounded by
	the keys-per-object limit).
*/

// violation is one limit that was exceeded
type violation struct {
	Code   string // see apiViolations
	Detail string // short, non sensitive (numbers and limit names only)
}

func (v *violation) String() string { return v.Code + ": " + v.Detail }

type jsonChecker struct {
	b      []byte
	i      int
	lim    APILimits
	maxDep int
	v      *violation
	syntax bool // v is a syntax error (content type mismatch)
}

func (c *jsonChecker) fail(code, format string, args ...interface{}) bool {
	if c.v == nil {
		c.v = &violation{Code: code, Detail: fmt.Sprintf(format, args...)}
	}
	return false
}

func (c *jsonChecker) bad(format string, args ...interface{}) bool {
	c.syntax = true
	return c.fail(codeSyntax, format, args...)
}

func (c *jsonChecker) ws() {
	for c.i < len(c.b) {
		switch c.b[c.i] {
		case ' ', '\t', '\n', '\r':
			c.i++
		default:
			return
		}
	}
}

// checkJSON validates the structure of b. nil = fine.
func checkJSON(b []byte, lim APILimits) *violation {
	c := &jsonChecker{b: b, lim: lim, maxDep: lim.JSONMaxDepth}
	if c.maxDep <= 0 || c.maxDep > hardNestingCap {
		c.maxDep = hardNestingCap
	}
	c.ws()
	if c.i >= len(b) {
		return nil // empty body
	}
	if c.value(1) {
		c.ws()
		if c.i != len(b) {
			c.bad("unexpected data after the JSON value")
		}
	}
	return c.v
}

func (c *jsonChecker) value(depth int) bool {
	c.ws()
	if c.i >= len(c.b) {
		return c.bad("unexpected end of JSON")
	}
	switch ch := c.b[c.i]; {
	case ch == '{':
		return c.object(depth)
	case ch == '[':
		return c.array(depth)
	case ch == '"':
		_, ok := c.str(false)
		return ok
	case ch == '-' || ch >= '0' && ch <= '9':
		return c.number()
	case ch == 't':
		return c.lit("true")
	case ch == 'f':
		return c.lit("false")
	case ch == 'n':
		return c.lit("null")
	}
	return c.bad("invalid character at offset %d", c.i)
}

func (c *jsonChecker) lit(w string) bool {
	if len(c.b)-c.i >= len(w) && string(c.b[c.i:c.i+len(w)]) == w {
		c.i += len(w)
		return true
	}
	return c.bad("invalid literal at offset %d", c.i)
}

func (c *jsonChecker) number() bool {
	start := c.i
	if c.b[c.i] == '-' {
		c.i++
	}
	digits := func() int {
		n := 0
		for c.i < len(c.b) && c.b[c.i] >= '0' && c.b[c.i] <= '9' {
			c.i++
			n++
		}
		return n
	}
	if c.i < len(c.b) && c.b[c.i] == '0' {
		c.i++
	} else if digits() == 0 {
		return c.bad("invalid number at offset %d", start)
	}
	if c.i < len(c.b) && c.b[c.i] == '.' {
		c.i++
		if digits() == 0 {
			return c.bad("invalid number at offset %d", start)
		}
	}
	if c.i < len(c.b) && (c.b[c.i] == 'e' || c.b[c.i] == 'E') {
		c.i++
		if c.i < len(c.b) && (c.b[c.i] == '+' || c.b[c.i] == '-') {
			c.i++
		}
		if digits() == 0 {
			return c.bad("invalid number at offset %d", start)
		}
	}
	if c.i-start > 4096 {
		return c.bad("number token too long")
	}
	return true
}

// str scans a string starting at the opening quote and returns its raw content (without quotes)
// and whether it contained escapes.
func (c *jsonChecker) str(isKey bool) (raw []byte, ok bool) {
	c.i++ // opening quote
	start := c.i
	escaped := false
	for c.i < len(c.b) {
		ch := c.b[c.i]
		switch {
		case ch == '"':
			raw = c.b[start:c.i]
			c.i++
			if c.lim.RejectInvalidUTF8 && !utf8.Valid(raw) {
				return nil, c.fail(codeJSONUTF8, "invalid UTF-8 in a string")
			}
			if escaped && isKey {
				raw = append([]byte{'\\'}, raw...) // marker, see decodeKey
			}
			return raw, true
		case ch == '\\':
			escaped = true
			c.i++
			if c.i >= len(c.b) {
				return nil, c.bad("unterminated string")
			}
			switch c.b[c.i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				c.i++
			case 'u':
				if c.i+4 >= len(c.b) {
					return nil, c.bad("invalid unicode escape")
				}
				for k := 1; k <= 4; k++ {
					h := c.b[c.i+k]
					if !(h >= '0' && h <= '9' || h >= 'a' && h <= 'f' || h >= 'A' && h <= 'F') {
						return nil, c.bad("invalid unicode escape")
					}
				}
				c.i += 5
			default:
				return nil, c.bad("invalid escape sequence")
			}
		case ch < 0x20:
			return nil, c.bad("control character in a string")
		default:
			c.i++
		}
		if c.lim.JSONMaxStringLen > 0 && c.i-start > c.lim.JSONMaxStringLen {
			return nil, c.fail(codeJSONStringLen, "string longer than %d bytes", c.lim.JSONMaxStringLen)
		}
	}
	return nil, c.bad("unterminated string")
}

func decodeKey(raw []byte) string {
	if len(raw) > 0 && raw[0] == '\\' && len(raw) > 1 {
		// escaped keys are re-decoded properly; the marker byte is not part of the key
		var s string
		if err := json.Unmarshal(append(append([]byte{'"'}, raw[1:]...), '"'), &s); err == nil {
			return s
		}
		return string(raw)
	}
	return string(raw)
}

func (c *jsonChecker) object(depth int) bool {
	if depth > c.maxDep {
		return c.fail(codeJSONDepth, "nesting deeper than %d", c.maxDep)
	}
	c.i++ // {
	c.ws()
	if c.i < len(c.b) && c.b[c.i] == '}' {
		c.i++
		return true
	}
	var seen map[string]struct{}
	if c.lim.RejectDuplicateKeys {
		seen = map[string]struct{}{}
	}
	keys := 0
	for {
		c.ws()
		if c.i >= len(c.b) || c.b[c.i] != '"' {
			return c.bad("object key expected at offset %d", c.i)
		}
		keyRaw, ok := c.str(true)
		if !ok {
			return false
		}
		keys++
		if c.lim.JSONMaxKeys > 0 && keys > c.lim.JSONMaxKeys {
			return c.fail(codeJSONKeys, "more than %d keys in an object", c.lim.JSONMaxKeys)
		}
		if seen != nil {
			k := decodeKey(keyRaw)
			if _, dup := seen[k]; dup {
				return c.fail(codeJSONDupKey, "duplicate key in an object")
			}
			seen[k] = struct{}{}
		}
		c.ws()
		if c.i >= len(c.b) || c.b[c.i] != ':' {
			return c.bad("':' expected at offset %d", c.i)
		}
		c.i++
		if !c.value(depth + 1) {
			return false
		}
		c.ws()
		if c.i >= len(c.b) {
			return c.bad("unexpected end of JSON")
		}
		switch c.b[c.i] {
		case ',':
			c.i++
		case '}':
			c.i++
			return true
		default:
			return c.bad("',' or '}' expected at offset %d", c.i)
		}
	}
}

func (c *jsonChecker) array(depth int) bool {
	if depth > c.maxDep {
		return c.fail(codeJSONDepth, "nesting deeper than %d", c.maxDep)
	}
	c.i++ // [
	c.ws()
	if c.i < len(c.b) && c.b[c.i] == ']' {
		c.i++
		return true
	}
	n := 0
	for {
		n++
		if c.lim.JSONMaxArrayLen > 0 && n > c.lim.JSONMaxArrayLen {
			return c.fail(codeJSONArrayLen, "more than %d array elements", c.lim.JSONMaxArrayLen)
		}
		if !c.value(depth + 1) {
			return false
		}
		c.ws()
		if c.i >= len(c.b) {
			return c.bad("unexpected end of JSON")
		}
		switch c.b[c.i] {
		case ',':
			c.i++
		case ']':
			c.i++
			return true
		default:
			return c.bad("',' or ']' expected at offset %d", c.i)
		}
	}
}
