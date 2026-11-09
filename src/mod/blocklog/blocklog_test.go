package blocklog

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"blacklist": ReasonBlacklist, "blacklist-dropped": ReasonBlacklist, "whitelist": ReasonWhitelist,
		"ratelimit": ReasonRateLimit, "waf-blocked": ReasonWAF, "exploit-blocked": ReasonExploit,
		"captcha-required": ReasonCaptcha, "plugin-blocked": ReasonPlugin, "peer-not-allowed": ReasonPeer,
		"path-rule-deny": ReasonPathRule, "path-rule-noauth": ReasonPathRule, "path-rule-ratelimit": ReasonPathRule,
		"client-cert-expired": ReasonClientCert, "header-rule-2-x-key": ReasonHeaderRule, "header-rule-2-x-key-dropped": ReasonHeaderRule,
		"bot-scanner": ReasonBot, "bot-scanner-dropped": ReasonBot, "bot-challenge": ReasonBot,
		"country-challenge": ReasonCountryChallenge, "country-challenge-unavailable": ReasonCountryChallenge,
		"auto-ban": ReasonAutoBan, "auto-ban-dropped": ReasonAutoBan, "auth-basic": ReasonAuth,
	}
	for ft, want := range cases {
		got, _, ok := Classify(ft)
		if !ok || got != want {
			t.Errorf("%s: got %q ok=%v, want %q", ft, got, ok, want)
		}
	}
	for _, ft := range []string{"host-http", "vdir-http", "redirect", "bot-scanner-logonly", "static-response", "sablier-waiting", ""} {
		if IsBlocked(ft) {
			t.Errorf("%q must not count as blocked", ft)
		}
	}
	// every reason has an explanation and a place to go
	seen := map[string]bool{}
	for _, ri := range Reasons() {
		if ri.Label == "" || ri.Why == "" || ri.Tab == "" || ri.Where == "" || seen[ri.Key] {
			t.Errorf("bad reason info %+v", ri)
		}
		seen[ri.Key] = true
	}
	for _, r := range cases {
		if !seen[r] {
			t.Errorf("reason %s has no ReasonInfo", r)
		}
	}
}

func TestRingIsBoundedAndNewestFirst(t *testing.T) {
	l := New("", 50, DefaultSettings())
	for i := 0; i < 120; i++ {
		l.Record(Entry{IP: "192.0.2.1", Host: "A.Example.com", Reason: ReasonWAF, Path: fmt.Sprintf("/p%d", i), Time: time.Now().Unix()})
	}
	res := l.List(Filter{}, 0, 500)
	if res.Total != 50 || len(res.Items) != 50 {
		t.Fatalf("log must keep only the newest 50: total=%d items=%d", res.Total, len(res.Items))
	}
	if res.Items[0].Path != "/p119" || res.Items[49].Path != "/p70" {
		t.Errorf("order: %s ... %s", res.Items[0].Path, res.Items[49].Path)
	}
	if res.Items[0].Host != "a.example.com" {
		t.Errorf("host not lower-cased: %s", res.Items[0].Host)
	}
	// paging
	p1 := l.List(Filter{}, 0, 20)
	if p1.Next == 0 || len(p1.Items) != 20 {
		t.Fatalf("page 1: %+v", p1.Next)
	}
	p2 := l.List(Filter{}, p1.Next+0, 20)
	if p2.Items[0].Path != "/p99" {
		t.Errorf("page 2 should continue after the first page, got %s", p2.Items[0].Path)
	}
	if s := l.Summarize(Filter{}, time.Now()); !s.Truncated || s.Recorded != 120 || s.Kept != 50 {
		t.Errorf("summary must say the log is full: %+v", s)
	}
}

func TestFiltersAndSummary(t *testing.T) {
	l := New("", 100, DefaultSettings())
	now := time.Now()
	add := func(ip, host, reason, path string, age time.Duration) {
		l.Record(Entry{IP: ip, Host: host, Reason: reason, Path: path, Time: now.Add(-age).Unix(), Detail: "d " + reason})
	}
	add("192.0.2.1", "a.test", ReasonWAF, "/x", time.Minute)
	add("192.0.2.1", "a.test", ReasonWAF, "/x", 2*time.Minute)
	add("192.0.2.2", "b.test", ReasonBlacklist, "/y", 3*time.Hour)
	add("2001:db8:0:0:0:0:0:1", "b.test", ReasonRateLimit, "/z", 30*time.Hour)
	if got := l.List(Filter{Reason: ReasonWAF}, 0, 10).Total; got != 2 {
		t.Errorf("reason filter: %d", got)
	}
	if got := l.List(Filter{Host: "b.test"}, 0, 10).Total; got != 2 {
		t.Errorf("host filter: %d", got)
	}
	if got := l.List(Filter{IP: "2001:db8::1"}, 0, 10).Total; got != 1 {
		t.Errorf("ip filter must match the normalised address: %d", got)
	}
	if got := l.List(Filter{Q: "RATELIMIT"}, 0, 10).Total; got != 1 {
		t.Errorf("search: %d", got)
	}
	if got := l.List(Filter{Since: now.Add(-4 * time.Hour).Unix()}, 0, 10).Total; got != 3 {
		t.Errorf("since: %d", got)
	}
	s := l.Summarize(Filter{Reason: ReasonWAF, Since: now.Add(-4 * time.Hour).Unix()}, now)
	if s.Total != 3 || len(s.Reasons) != 2 || s.Reasons[0].Key != ReasonWAF || s.Reasons[0].N != 2 {
		t.Errorf("summary ignores the reason filter so the breakdown stays complete: %+v", s)
	}
	if s.TopIPs[0].Key != "192.0.2.1" || s.TopIPs[0].N != 2 || s.TopPaths[0].Key != "/x" {
		t.Errorf("tops: %+v %+v", s.TopIPs, s.TopPaths)
	}
	var sum int
	for _, b := range s.Hourly {
		sum += b.N
	}
	if len(s.Hourly) != 24 || sum != 3 {
		t.Errorf("hourly: %d buckets, %d counted", len(s.Hourly), sum)
	}
}

func TestPersistenceAndClear(t *testing.T) {
	file := filepath.Join(t.TempDir(), "blocked.json.gz")
	l := New(file, 10, DefaultSettings())
	l.Start()
	for i := 0; i < 3; i++ {
		l.Record(Entry{IP: "192.0.2.9", Host: "h", Reason: ReasonBot, Path: fmt.Sprint("/", i)})
	}
	l.Close()

	l2 := New(file, 10, DefaultSettings())
	l2.Start()
	res := l2.List(Filter{}, 0, 10)
	if res.Total != 3 || res.Items[0].Path != "/2" {
		t.Fatalf("reload: %+v", res)
	}
	l2.Record(Entry{IP: "192.0.2.9", Host: "h", Reason: ReasonBot, Path: "/3"})
	if got := l2.List(Filter{}, 0, 10).Items[0]; got.Seq != 4 {
		t.Errorf("sequence numbers must continue after a reload: %d", got.Seq)
	}
	l2.Clear()
	l2.Close()
	l3 := New(file, 10, DefaultSettings())
	l3.Start()
	defer l3.Close()
	if l3.List(Filter{}, 0, 10).Total != 0 {
		t.Error("clear must persist")
	}
}

func TestLimitsAndDisabled(t *testing.T) {
	l := New("", 5, Settings{Enabled: false})
	l.Record(Entry{IP: "192.0.2.1", Reason: ReasonWAF})
	if l.List(Filter{}, 0, 10).Total != 0 {
		t.Error("disabled log recorded")
	}
	l.SetEnabled(true)
	l.Record(Entry{IP: "192.0.2.1", Reason: ReasonWAF, Path: strings.Repeat("é", 1000), UA: strings.Repeat("u", 1000), Detail: strings.Repeat("d", 1000)})
	e := l.List(Filter{}, 0, 10).Items[0]
	if len(e.Path) > maxPathLen || len(e.UA) > maxUALen || len(e.Detail) > maxDetailLen {
		t.Errorf("field limits: %d %d %d", len(e.Path), len(e.UA), len(e.Detail))
	}
	if !strings.HasSuffix(e.Path, "é") {
		t.Error("truncation must not cut a UTF-8 sequence")
	}
	l.Record(Entry{IP: "", Reason: ReasonWAF})
	l.Record(Entry{IP: "192.0.2.1", Reason: ""})
	if l.List(Filter{}, 0, 10).Total != 1 {
		t.Error("entries without ip or reason must be ignored")
	}
}
