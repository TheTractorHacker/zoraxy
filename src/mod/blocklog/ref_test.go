package blocklog

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRefFormatAndUniqueness(t *testing.T) {
	re := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{8}$`)
	seen := map[string]bool{}
	for i := 0; i < 20000; i++ {
		r := NewRef()
		if !re.MatchString(r) {
			t.Fatalf("bad ref %q", r)
		}
		if seen[r] {
			t.Fatalf("duplicate ref %q after %d", r, i)
		}
		seen[r] = true
	}
	f := FormatRef("0123abcd")
	if f != "ZX-0123-ABCD" {
		t.Fatalf("format: %q", f)
	}
	for in, want := range map[string]string{"ZX-0123-ABCD": "0123ABCD", "zx-0123-abcd": "0123ABCD", "0123 abcd": "0123ABCD",
		"OI23ABCD": "0123ABCD", " zx_0123_abcd ": "0123ABCD", "ZX12ABCD": "ZX12ABCD", "ZX-ZX12-ABCD": "ZX12ABCD"} {
		if got := NormalizeRef(in); got != want {
			t.Errorf("%q normalised to %q, want %q", in, got, want)
		}
	}
	if f := FormatRef("ZX12ABCD"); f != "ZX-ZX12-ABCD" || NormalizeRef(f) != "ZX12ABCD" {
		t.Errorf("a reference starting with ZX must round-trip: %q", f)
	}
	for _, bad := range []string{"", "ZX-1234", "ZX-0123-ABCDE", "ZX-0123-ABCU", "hello there"} {
		if NormalizeRef(bad) != "" || FormatRef(bad) != "" {
			t.Errorf("%q must not be a reference", bad)
		}
	}
}

func TestLookupByRefAndSeq(t *testing.T) {
	l := New("", 5, DefaultSettings())
	refs := []string{}
	for i := 0; i < 8; i++ {
		r := NewRef()
		refs = append(refs, r)
		l.Record(Entry{IP: "192.0.2.1", Host: "h", Reason: ReasonBot, Path: "/p", Ref: r, RuleID: "bot:http_library"})
	}
	// the first three rolled out of the ring: their references are gone, the rest resolve
	for i, r := range refs {
		e, ok := l.GetByRef(FormatRef(r))
		if i < 3 {
			if ok {
				t.Errorf("rolled-over ref %d still resolves", i)
			}
			continue
		}
		if !ok || e.Ref != r || e.Seq != uint64(i+1) || e.RuleID != "bot:http_library" {
			t.Errorf("ref %d: %+v ok=%v", i, e, ok)
		}
	}
	if len(l.byRef) != 5 {
		t.Errorf("index must follow the ring, has %d", len(l.byRef))
	}
	res := l.List(Filter{Ref: strings.ToLower(FormatRef(refs[6]))}, 0, 10)
	if res.Total != 1 || len(res.Items) != 1 || res.Items[0].Seq != 7 {
		t.Errorf("list by ref: %+v", res)
	}
	if res := l.List(Filter{Ref: FormatRef(refs[6]), Host: "other"}, 0, 10); res.Total != 0 {
		t.Errorf("ref plus a filter that does not match: %+v", res)
	}
	if res := l.List(Filter{Ref: "ZX-0000-0000"}, 0, 10); res.Total != 0 || res.Items == nil {
		t.Errorf("unknown ref: %+v", res)
	}
	for seq := uint64(1); seq <= 8; seq++ {
		e, ok := l.Get(seq)
		if (seq <= 3) == ok || (ok && e.Seq != seq) {
			t.Errorf("Get(%d) = %+v ok=%v", seq, e, ok)
		}
	}
	if _, ok := l.Get(0); ok {
		t.Error("seq 0")
	}
	if _, ok := l.Get(99); ok {
		t.Error("future seq")
	}
	// by IP still works next to the reference
	if res := l.List(Filter{IP: "192.0.2.1"}, 0, 10); res.Total != 5 {
		t.Errorf("by ip: %d", res.Total)
	}
	l.Clear()
	if _, ok := l.GetByRef(refs[7]); ok {
		t.Error("clear must empty the index")
	}
	if _, ok := l.Get(8); ok {
		t.Error("clear must empty Get")
	}
}

func TestRefSurvivesReloadAndOldFilesLoad(t *testing.T) {
	file := filepath.Join(t.TempDir(), "blocked.json.gz")
	l := New(file, 10, DefaultSettings())
	l.Start()
	ref := NewRef()
	l.Record(Entry{IP: "192.0.2.1", Host: "h", Reason: ReasonBot, Ref: ref, RuleID: "bot:scanner"})
	l.Close()
	l2 := New(file, 10, DefaultSettings())
	l2.Start()
	if e, ok := l2.GetByRef(ref); !ok || e.RuleID != "bot:scanner" {
		t.Fatalf("reload lost the reference: %+v %v", e, ok)
	}
	l2.Close()

	// A file written by a version that had no ref / rid fields (same format version)
	old := filepath.Join(t.TempDir(), "old.json.gz")
	raw := `{"v":1,"saved":1700000000,"seq":2,"entries":[` +
		`{"seq":1,"t":1700000000,"ip":"192.0.2.7","host":"a.test","method":"GET","path":"/x","status":403,"reason":"bot","detail":"challenge-unavailable","ua":"curl/8"},` +
		`{"seq":2,"t":1700000001,"ip":"192.0.2.8","host":"a.test","method":"GET","path":"/y","status":403,"reason":"blacklist"}]}`
	f, err := os.Create(old)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	zw.Write([]byte(raw))
	zw.Close()
	f.Close()
	l3 := New(old, 10, DefaultSettings())
	l3.Start()
	defer l3.Close()
	res := l3.List(Filter{}, 0, 10)
	if res.Total != 2 || res.Items[0].Ref != "" || res.Items[1].UA != "curl/8" {
		t.Fatalf("old file: %+v", res)
	}
	if e, ok := l3.Get(1); !ok || e.IP != "192.0.2.7" {
		t.Errorf("Get on an old entry: %+v %v", e, ok)
	}
	l3.Record(Entry{IP: "192.0.2.9", Reason: ReasonBot, Ref: NewRef()})
	if e, ok := l3.Get(3); !ok || e.Seq != 3 {
		t.Errorf("sequence continues after an old file: %+v", e)
	}
	// and the JSON of an entry without them does not carry the fields
	js, _ := json.Marshal(Entry{Seq: 1, IP: "x", Reason: ReasonBot})
	if strings.Contains(string(js), `"ref"`) || strings.Contains(string(js), `"rid"`) {
		t.Errorf("empty ref / rid must be omitted: %s", js)
	}
}

// The three "challenge, no CAPTCHA" classes keep their reason keys (and so the counters and IsBlocked) and
// say in the detail that the challenge could not be served.
func TestClassifyChallengeUnavailable(t *testing.T) {
	for ft, want := range map[string]string{
		"bot-challenge-unavailable": ReasonBot, "rule-challenge-unavailable": ReasonRule, "country-challenge-unavailable": ReasonCountryChallenge,
	} {
		reason, detail, ok := Classify(ft)
		if !ok || reason != want || detail != DetailChallengeUnavailable {
			t.Errorf("%s: %q %q %v", ft, reason, detail, ok)
		}
	}
	if d := ChallengeDetail("http_library", true); d != "http_library (challenge, no CAPTCHA, acted as block)" {
		t.Errorf("detail: %q", d)
	}
	if d := ChallengeDetail("http_library", false); d != "http_library (challenge)" {
		t.Errorf("detail: %q", d)
	}
	if d := ChallengeDetail("", true); d != DetailChallengeUnavailable {
		t.Errorf("detail: %q", d)
	}
}

// What counts as a block did not change: this table is the full set of classes before the change.
func TestClassifyKeysAndBlockedSetUnchanged(t *testing.T) {
	blocked := map[string]string{
		"blacklist": "blacklist", "blacklist-dropped": "blacklist", "whitelist": "whitelist", "whitelist-dropped": "whitelist",
		"auto-ban": "auto-ban", "auto-ban-dropped": "auto-ban", "ratelimit": "ratelimit", "waf-blocked": "waf",
		"exploit-blocked": "exploit", "captcha-required": "captcha", "plugin-blocked": "plugin", "peer-not-allowed": "peer",
		"path-rule-deny": "path-rule", "path-rule-noauth": "path-rule", "path-rule-ratelimit": "path-rule",
		"rule-block": "rule", "rule-ratelimit": "rule", "rule-challenge": "rule", "rule-challenge-unavailable": "rule",
		"country-challenge": "country-challenge", "country-challenge-unavailable": "country-challenge",
		"bot-challenge": "bot", "bot-challenge-unavailable": "bot", "bot-scanner": "bot", "bot-scanner-dropped": "bot",
		"bot-custom:x": "bot", "client-cert-missing": "client-cert", "auth-basic": "auth", "header-rule-1-x": "header-rule",
	}
	for ft, want := range blocked {
		got, _, ok := Classify(ft)
		if !ok || got != want || !IsBlocked(ft) {
			t.Errorf("%s: reason %q ok=%v", ft, got, ok)
		}
	}
	for _, ft := range []string{"host-http", "vdir-http", "bot-scanner-logonly", "rule-redirect", "waf-challenged", "", "subdomain-websocket"} {
		if IsBlocked(ft) {
			t.Errorf("%q must not count as a block", ft)
		}
	}
}

func TestRepeatedRefDoesNotTakeOverTheIndex(t *testing.T) {
	l := New("", 5, DefaultSettings())
	l.Record(Entry{IP: "192.0.2.1", Host: "h", Reason: ReasonBot, UA: "curl/8", Ref: "S0Q3D7BM"})
	l.Record(Entry{IP: "192.0.2.2", Host: "h", Reason: ReasonBot, UA: "sqlmap/1", Ref: "s0q3-d7bm"})
	e, ok := l.GetByRef("ZX-S0Q3-D7BM")
	if !ok || e.UA != "curl/8" {
		t.Fatalf("the first entry must keep its reference: %+v %v", e, ok)
	}
}
