package ech

/*
	fallbacks.go

	Diagnostics only: remembers which server names were answered with the fallback certificate although they match no
	proxy rule and no alias. It never influences which certificate is served.

	The interesting case is the ECH outer name of another provider. A browser that offers ECH with a config published
	in DNS by someone else (typically Cloudflare, public name cloudflare-ech.com) sends the OUTER public name as SNI:
	Zoraxy cannot decrypt the inner hello, so the real host name (the key of every per-host certificate choice) is never
	visible and the fallback certificate is served. Chrome reports ERR_ECH_FALLBACK_CERTIFICATE_INVALID.
*/

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Classes of a name that was answered with the fallback certificate
const (
	FallbackForeignECH = "foreign-ech" // looks like the ECH public name of another provider
	FallbackOwnECH     = "own-ech"     // Zoraxy's own ECH public name
	FallbackNoSNI      = "no-sni"      // the client sent no server name (IP access, old client)
	FallbackUnknown    = "unknown"     // unknown host, scanner or access by IP: not guessed any further
)

// KnownECHPublicNames are public names of other providers' ECH configurations. Names ending in a suffix of
// ForeignECHSuffixes are treated the same way. Edit here only.
var KnownECHPublicNames = []string{"cloudflare-ech.com"}

// ForeignECHSuffixes are host name suffixes that identify an ECH public name
var ForeignECHSuffixes = []string{"-ech.com"}

const (
	fallbackMaxEntries = 64 // distinct names kept; the least recently seen is dropped when full
	fallbackMaxName    = 253
	fallbackLogEvery   = time.Hour
	fallbackIdle       = 7 * 24 * time.Hour
)

// ClassifyFallback names the likely reason a server name reached the fallback certificate.
// ownPublicName is Zoraxy's active ECH public name ("" when ECH is off).
func ClassifyFallback(name, ownPublicName string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" {
		return FallbackNoSNI
	}
	if ownPublicName != "" && n == strings.TrimSuffix(strings.ToLower(ownPublicName), ".") {
		return FallbackOwnECH
	}
	for _, k := range KnownECHPublicNames {
		if n == k {
			return FallbackForeignECH
		}
	}
	for _, s := range ForeignECHSuffixes {
		if strings.HasSuffix(n, s) {
			return FallbackForeignECH
		}
	}
	return FallbackUnknown
}

// FallbackEntry is one name in the table
type FallbackEntry struct {
	Name      string
	Class     string
	Count     uint64
	FirstSeen int64 // unix seconds
	LastSeen  int64
	lastLog   time.Time
}

// FallbackTable is a small bounded table. Only handshakes that already ended in the fallback certificate for an
// unknown name reach it, so its lock is not on the normal path.
type FallbackTable struct {
	mu      sync.Mutex
	entries map[string]*FallbackEntry
	dropped uint64
	now     func() time.Time
}

func NewFallbackTable() *FallbackTable {
	return &FallbackTable{entries: map[string]*FallbackEntry{}, now: time.Now}
}

func cleanFallbackName(name string) string {
	n := strings.ToLower(name)
	if len(n) > fallbackMaxName {
		n = n[:fallbackMaxName]
	}
	// the name comes from the network: keep printable ASCII only
	return strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return '?'
		}
		return r
	}, n)
}

// Note records one handshake. logNow is true when the caller should write the plain language log line (foreign ECH
// names only, once per name per hour).
func (t *FallbackTable) Note(name, ownPublicName string) (logNow bool, class, clean string) {
	clean = cleanFallbackName(name)
	class = ClassifyFallback(clean, ownPublicName)
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entries[clean]
	if e == nil {
		if len(t.entries) >= fallbackMaxEntries {
			var oldest string
			var oldestSeen int64 = 1<<63 - 1
			for k, v := range t.entries {
				if v.LastSeen < oldestSeen {
					oldest, oldestSeen = k, v.LastSeen
				}
			}
			delete(t.entries, oldest)
			t.dropped++
		}
		e = &FallbackEntry{Name: clean, FirstSeen: now.Unix()}
		t.entries[clean] = e
	}
	e.Class = class
	e.Count++
	e.LastSeen = now.Unix()
	if class == FallbackForeignECH && now.Sub(e.lastLog) >= fallbackLogEvery {
		e.lastLog = now
		logNow = true
	}
	return
}

// Snapshot returns the table, foreign ECH names first, then by most recent. Entries not seen for a week are left out.
func (t *FallbackTable) Snapshot() (list []FallbackEntry, dropped uint64) {
	cut := t.now().Add(-fallbackIdle).Unix()
	t.mu.Lock()
	list = make([]FallbackEntry, 0, len(t.entries))
	for _, e := range t.entries {
		if e.LastSeen >= cut {
			list = append(list, *e)
		}
	}
	dropped = t.dropped
	t.mu.Unlock()
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i].Class == FallbackForeignECH, list[j].Class == FallbackForeignECH
		if a != b {
			return a
		}
		if list[i].LastSeen != list[j].LastSeen {
			return list[i].LastSeen > list[j].LastSeen
		}
		return list[i].Name < list[j].Name
	})
	return
}

// HasForeignECH says whether a foreign ECH outer name was seen recently
func (t *FallbackTable) HasForeignECH() bool {
	l, _ := t.Snapshot()
	for _, e := range l {
		if e.Class == FallbackForeignECH {
			return true
		}
	}
	return false
}

// ForeignECHMessage is the plain language log line for a foreign ECH outer name
func ForeignECHMessage(name string) string {
	return "Handshakes for " + name + " were answered with the fallback certificate. " + name + " is an Encrypted Client Hello public name: " +
		"browsers use an ECH configuration from DNS that this proxy did not publish and cannot decrypt, so no certificate can be valid. " +
		"Fix the DNS (see Tools > Encrypted Client Hello > Check domains) or turn ECH off at the DNS provider."
}
