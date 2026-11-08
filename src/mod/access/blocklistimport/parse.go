// Package blocklistimport imports IP / CIDR lists into the blacklist or
// whitelist of an access rule: parsing and validation, a dry-run report,
// SSRF-safe download of URL sources and scheduled refresh that only ever
// replaces the entries it added itself.
package blocklistimport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

const (
	// DefaultMaxEntries is the maximum number of distinct entries one import may contain
	DefaultMaxEntries = 1_000_000
	// MaxLineBytes is the longest line that is parsed; longer lines are reported invalid
	MaxLineBytes = 4096
	// MaxIssuesReported caps the per-category issue lists in a report (counts stay exact)
	MaxIssuesReported = 500
	// MaxCommentLen caps a stored comment
	MaxCommentLen = 120
)

// ErrTooManyEntries is returned when an input exceeds the entry limit
var ErrTooManyEntries = errors.New("too many entries in import")

// Entry is one validated, canonical IP address or CIDR with its source line
type Entry struct {
	Value   string
	Comment string
	Line    int
}

// Issue is a rejected or skipped input line
type Issue struct {
	Line   int    `json:"line"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

// Parsed is the result of parsing an input
type Parsed struct {
	Lines      int     //number of lines read
	Entries    []Entry //unique valid entries, in input order
	Invalid    []Issue //capped at MaxIssuesReported
	Duplicates []Issue //duplicates inside the input, capped
	InvalidN   int
	DuplicateN int
}

var stripTags = bluemonday.StripTagsPolicy()

// CleanComment removes markup and bounds the length of a comment. Comments are
// shown unescaped by parts of the admin UI, so markup must never be stored.
func CleanComment(c string) string {
	c = strings.TrimSpace(stripTags.Sanitize(c))
	c = strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&#34;", `"`, "&#39;", "'").Replace(c)
	c = strings.ReplaceAll(strings.ReplaceAll(c, "<", ""), ">", "")
	if len(c) > MaxCommentLen {
		c = strings.ToValidUTF8(c[:MaxCommentLen], "")
	}
	return c
}

// Normalize validates one IP address or CIDR and returns its canonical text:
// single hosts without prefix, networks masked to their base address.
func Normalize(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty")
	}
	if strings.ContainsAny(s, "%*") {
		return "", errors.New("scope ids and wildcards are not supported, use a CIDR")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", errors.New("invalid CIDR")
		}
		if p.Bits() == 0 {
			return "", errors.New("refusing /0 prefix (matches every address)")
		}
		a := p.Addr()
		if a.Is4In6() {
			// ::ffff:a.b.c.d/N -> a.b.c.d/(N-96)
			if p.Bits() < 96 {
				return "", errors.New("unsupported IPv4-mapped prefix")
			}
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
			if p.Bits() == 0 {
				return "", errors.New("refusing /0 prefix (matches every address)")
			}
		}
		p = p.Masked()
		if p.Addr().IsUnspecified() {
			return "", errors.New("unspecified address")
		}
		if p.Bits() == p.Addr().BitLen() {
			return p.Addr().String(), nil
		}
		return p.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", errors.New("not an IP address or CIDR")
	}
	a = a.Unmap()
	if a.IsUnspecified() {
		return "", errors.New("unspecified address")
	}
	return a.String(), nil
}

func isSep(r byte) bool { return r == ',' || r == ';' || r == '\t' || r == ' ' }

// splitLine returns the first token and the remaining comment text of a line
func splitLine(line string) (token, comment string) {
	i := 0
	for i < len(line) && !isSep(line[i]) && line[i] != '#' {
		i++
	}
	token = strings.Trim(line[:i], `"'`)
	rest := strings.TrimLeft(line[i:], ", \t;")
	rest = strings.TrimLeft(rest, "#")
	rest = strings.Trim(strings.TrimSpace(rest), `"'`)
	return token, rest
}

// Parse reads a text, TXT or CSV blocklist: one entry per line, '#' or ';'
// starting a comment line, optional trailing comment after the entry
// (whitespace, comma, tab, ';' or '#' separated; the first column of a CSV is
// the address). maxEntries <= 0 uses DefaultMaxEntries. defaultComment is
// used for entries without their own comment.
func Parse(r io.Reader, maxEntries int, defaultComment string, keepLineComments bool) (*Parsed, error) {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	out := &Parsed{}
	seen := make(map[string]int)
	br := bufio.NewReaderSize(r, 64*1024)
	defaultComment = CleanComment(defaultComment)
	for {
		raw, isPrefix, err := br.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return out, err
		}
		out.Lines++
		line := out.Lines
		if isPrefix {
			// discard the rest of an over-long line
			for isPrefix {
				_, isPrefix, err = br.ReadLine()
				if err != nil {
					break
				}
			}
			out.InvalidN++
			if len(out.Invalid) < MaxIssuesReported {
				out.Invalid = append(out.Invalid, Issue{line, truncate(string(raw)), "line too long"})
			}
			continue
		}
		text := string(raw)
		if line == 1 {
			text = strings.TrimPrefix(text, "\xef\xbb\xbf")
		}
		text = strings.TrimSpace(text)
		if text == "" || text[0] == '#' || text[0] == ';' {
			continue
		}
		token, lineComment := splitLine(text)
		val, nerr := Normalize(token)
		if nerr != nil {
			out.InvalidN++
			if len(out.Invalid) < MaxIssuesReported {
				out.Invalid = append(out.Invalid, Issue{line, truncate(text), nerr.Error()})
			}
			continue
		}
		if first, dup := seen[val]; dup {
			out.DuplicateN++
			if len(out.Duplicates) < MaxIssuesReported {
				out.Duplicates = append(out.Duplicates, Issue{line, truncate(text), fmt.Sprintf("duplicate of line %d", first)})
			}
			continue
		}
		if len(out.Entries) >= maxEntries {
			return out, ErrTooManyEntries
		}
		seen[val] = line
		comment := defaultComment
		if keepLineComments && lineComment != "" {
			comment = CleanComment(lineComment)
		}
		out.Entries = append(out.Entries, Entry{Value: val, Comment: comment, Line: line})
	}
	return out, nil
}

func truncate(s string) string {
	if len(s) > 80 {
		return strings.ToValidUTF8(s[:80], "") + "..."
	}
	return s
}
