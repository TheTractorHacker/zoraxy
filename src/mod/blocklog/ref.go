package blocklog

import (
	"crypto/rand"
	"strings"
)

/*
	ref.go

	The reference ID of a blocked request: 8 characters of the Crockford base32 alphabet (no I, L, O, U,
	so it can be read out over the phone), 40 bits from the system random source. It is shown to the
	visitor as ZX-XXXX-XXXX and stored without the prefix. It carries no information about the rule.
*/

const (
	refAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	refLen      = 8
)

// NewRef returns a fresh random reference (8 characters). Cheap enough for the request path:
// one 5 byte read from the system random source and no allocation besides the result.
func NewRef() string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "" //no reference is better than a predictable one
	}
	v := uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	var out [refLen]byte
	for i := refLen - 1; i >= 0; i-- {
		out[i] = refAlphabet[v&31]
		v >>= 5
	}
	return string(out[:])
}

// FormatRef renders a stored reference the way the visitor sees it: ZX-XXXX-XXXX. An invalid
// reference gives "".
func FormatRef(ref string) string {
	ref = NormalizeRef(ref)
	if ref == "" {
		return ""
	}
	return "ZX-" + ref[:4] + "-" + ref[4:]
}

// NormalizeRef accepts any spelling a person may type or paste (zx-abcd-1234, ABCD 1234, with
// O read as 0 and I or L as 1, the Crockford rules) and returns the stored form, or "" when the
// text is not a reference.
func NormalizeRef(in string) string {
	in = strings.ToUpper(strings.TrimSpace(in))
	in = strings.TrimPrefix(in, "ZX")
	var b strings.Builder
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch c {
		case '-', ' ', '_':
			continue
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		if strings.IndexByte(refAlphabet, c) < 0 {
			return ""
		}
		b.WriteByte(c)
	}
	if b.Len() != refLen {
		return ""
	}
	return b.String()
}

// Get returns the entry with this sequence number if it is still in the log. O(1): sequence numbers
// are consecutive, so the position in the ring follows from the newest one.
func (l *Log) Get(seq uint64) (Entry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.getLocked(seq)
}

func (l *Log) getLocked(seq uint64) (Entry, bool) {
	if seq == 0 || seq > l.seq || l.count == 0 {
		return Entry{}, false
	}
	if d := l.seq - seq; d < uint64(l.count) {
		idx := ((l.next-1-int(d))%len(l.ring) + len(l.ring)) % len(l.ring)
		if l.ring[idx].Seq == seq {
			return l.ring[idx], true
		}
	}
	// the sequence numbers were not consecutive (a log restored from an odd file): fall back to a scan
	for i := 0; i < len(l.ring) && i < l.count; i++ {
		if e := &l.ring[i]; e.Seq == seq {
			return *e, true
		}
	}
	return Entry{}, false
}

// GetByRef returns the entry the visitor was given this reference for. O(1) through the index.
func (l *Log) GetByRef(ref string) (Entry, bool) {
	ref = NormalizeRef(ref)
	if ref == "" {
		return Entry{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	seq, ok := l.byRef[ref]
	if !ok {
		return Entry{}, false
	}
	return l.getLocked(seq)
}
