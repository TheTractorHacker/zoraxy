package visitors

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestTracker(t *testing.T, s Settings) *Tracker {
	t.Helper()
	tr := New(filepath.Join(t.TempDir(), "visitors.json.gz"), s)
	tr.Start()
	t.Cleanup(tr.Close)
	return tr
}

// flush waits until the writer goroutine consumed everything that was queued
func flush(t *testing.T, tr *Tracker, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if tr.Stats().Recorded >= want {
			time.Sleep(5 * time.Millisecond)
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("writer did not process %d events (got %d)", want, tr.Stats().Recorded)
}

func ev(ip, host, path string, status int) Event {
	return Event{Time: time.Now(), IP: ip, Host: host, Method: "GET", Path: path, UA: "ua/1", Country: "de", Status: status, Via: ViaDirect}
}

func TestAggregateAndRing(t *testing.T) {
	tr := newTestTracker(t, DefaultSettings())
	tr.Record(ev("1.1.1.1", "A.example.com:8443", "/x?token=secret", 200))
	tr.Record(ev("1.1.1.1", "b.example.com", "/y", 404))
	blocked := ev("1.1.1.1", "a.example.com", "/z", 403)
	blocked.Blocked = true
	tr.Record(blocked)
	tr.Record(ev("2.2.2.2", "a.example.com", "/", 200))
	flush(t, tr, 4)

	v, recent := tr.Get("1.1.1.1")
	if v == nil || v.Hits != 3 || v.Blocked != 1 || v.Country != "DE" {
		t.Fatalf("bad aggregate: %+v", v)
	}
	if v.Hosts["a.example.com"] != 2 || v.Hosts["b.example.com"] != 1 {
		t.Fatalf("hosts (lower case, port stripped): %v", v.Hosts)
	}
	if _, ok := v.Paths["/x"]; !ok {
		t.Fatalf("query string must be stripped by default: %v", v.Paths)
	}
	for p := range v.Paths {
		if strings.Contains(p, "secret") {
			t.Fatal("query leaked into storage")
		}
	}
	if len(recent) != 3 || recent[0].Path != "/z" || !recent[2].NewVisitr {
		t.Fatalf("recent visits (newest first): %+v", recent)
	}
	if tr.Stats().IPs != 2 {
		t.Fatalf("ips: %d", tr.Stats().IPs)
	}
}

func TestKeepQuery(t *testing.T) {
	s := DefaultSettings()
	s.KeepQuery = true
	tr := newTestTracker(t, s)
	tr.Record(ev("1.1.1.1", "a", "/x?a=1", 200))
	flush(t, tr, 1)
	v, _ := tr.Get("1.1.1.1")
	if _, ok := v.Paths["/x?a=1"]; !ok {
		t.Fatalf("query should be kept: %v", v.Paths)
	}
}

func TestDisabledAndExcluded(t *testing.T) {
	s := DefaultSettings()
	s.Enabled = false
	tr := newTestTracker(t, s)
	tr.Record(ev("1.1.1.1", "a", "/", 200))
	time.Sleep(30 * time.Millisecond)
	if tr.Stats().Recorded != 0 || tr.Stats().IPs != 0 {
		t.Fatal("disabled tracker recorded")
	}
	s.Enabled = true
	tr.SetSettings(s)
	tr.SetExcluder(func(ip string) bool { return ip == "9.9.9.9" })
	tr.Record(ev("9.9.9.9", "a", "/", 200))
	tr.Record(ev("8.8.8.8", "a", "/", 200))
	flush(t, tr, 1)
	time.Sleep(30 * time.Millisecond)
	if _, _ = tr.Get("9.9.9.9"); tr.Stats().IPs != 1 {
		t.Fatalf("excluded IP was recorded, ips=%d", tr.Stats().IPs)
	}
}

func TestCardinalityCaps(t *testing.T) {
	s := DefaultSettings()
	s.MaxIPs = 100
	s.MaxVisits = 100
	tr := newTestTracker(t, s)
	n := 0
	for i := 0; i < 400; i++ {
		e := ev(fmt.Sprintf("10.0.%d.%d", i/200, i%200), "a", "/", 200)
		e.Time = time.Now().Add(time.Duration(i) * time.Second) // later = newer
		tr.Record(e)
		n++
	}
	// one IP touching many hosts and paths
	for i := 0; i < 200; i++ {
		e := ev("7.7.7.7", fmt.Sprintf("h%d.example", i), fmt.Sprintf("/p%d", i), 200)
		e.Time = time.Now().Add(time.Hour)
		tr.Record(e)
		n++
	}
	flush(t, tr, uint64(n))
	tr.Prune(time.Now().Add(10 * time.Minute))
	st := tr.Stats()
	if st.IPs > 100 {
		t.Fatalf("MaxIPs not enforced: %d", st.IPs)
	}
	if st.Visits != 100 {
		t.Fatalf("ring should hold exactly MaxVisits: %d", st.Visits)
	}
	v, _ := tr.Get("7.7.7.7")
	if v == nil {
		t.Fatal("recent heavy IP was pruned")
	}
	if len(v.Hosts) > maxHostsPerIP || len(v.Paths) > maxPathsPerIP {
		t.Fatalf("per IP caps: hosts %d paths %d", len(v.Hosts), len(v.Paths))
	}
	// oldest IPs went first
	if old, _ := tr.Get("10.0.0.0"); old != nil {
		t.Fatal("oldest IP survived the cap")
	}
}

func TestLongFieldsAndControlChars(t *testing.T) {
	tr := newTestTracker(t, DefaultSettings())
	e := ev("1.1.1.1", strings.Repeat("h", 1000), "/"+strings.Repeat("p", 5000), 200)
	e.UA = "evil\x1b[31m\nua" + strings.Repeat("u", 1000)
	tr.Record(e)
	flush(t, tr, 1)
	v, _ := tr.Get("1.1.1.1")
	if len(v.LastUA) > maxUALen || strings.ContainsAny(v.LastUA, "\x1b\n") {
		t.Fatalf("ua not sanitised: %q", v.LastUA)
	}
	if len(v.LastPath) > maxPathLen || len(v.LastHost) > maxHostLen {
		t.Fatal("path/host not truncated")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "v.json.gz")
	tr := New(file, DefaultSettings())
	tr.Start()
	for i := 0; i < 50; i++ {
		tr.Record(ev(fmt.Sprintf("3.3.3.%d", i), "a.example", "/p", 200))
	}
	flush(t, tr, 50)
	tr.Close() // persists

	tr2 := New(file, DefaultSettings())
	tr2.Start()
	defer tr2.Close()
	st := tr2.Stats()
	if st.IPs != 50 || st.Visits != 50 || st.Seq != 50 {
		t.Fatalf("restored %+v", st)
	}
	v, _ := tr2.Get("3.3.3.7")
	if v == nil || v.Hits != 1 || v.Hosts["a.example"] != 1 || v.Country != "DE" {
		t.Fatalf("restored visitor: %+v", v)
	}
	// new events continue the sequence
	tr2.Record(ev("3.3.3.7", "a.example", "/q", 200))
	flush(t, tr2, 1)
	if tr2.Stats().Seq != 51 {
		t.Fatalf("seq %d", tr2.Stats().Seq)
	}
}

func TestCorruptFileIgnored(t *testing.T) {
	file := filepath.Join(t.TempDir(), "v.json.gz")
	if err := os.WriteFile(file, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := New(file, DefaultSettings())
	tr.Start()
	defer tr.Close()
	if tr.Stats().IPs != 0 {
		t.Fatal("corrupt file should yield an empty store")
	}
}

func TestRetentionByAge(t *testing.T) {
	s := DefaultSettings()
	s.MaxAgeDays = 30
	tr := newTestTracker(t, s)
	old := ev("4.4.4.4", "a", "/", 200)
	old.Time = time.Now().Add(-45 * 24 * time.Hour)
	tr.Record(old)
	tr.Record(ev("5.5.5.5", "a", "/", 200))
	flush(t, tr, 2)
	if got := tr.Prune(time.Now()); got != 1 {
		t.Fatalf("pruned %d", got)
	}
	if v, _ := tr.Get("4.4.4.4"); v != nil {
		t.Fatal("old IP kept")
	}
	if v, _ := tr.Get("5.5.5.5"); v == nil {
		t.Fatal("fresh IP removed")
	}
}

func TestDeleteAndPurge(t *testing.T) {
	tr := newTestTracker(t, DefaultSettings())
	tr.Record(ev("1.1.1.1", "a", "/", 200))
	tr.Record(ev("2.2.2.2", "a", "/", 200))
	tr.Record(ev("1.1.1.1", "a", "/2", 200))
	flush(t, tr, 3)
	if !tr.Delete("1.1.1.1") || tr.Delete("1.1.1.1") {
		t.Fatal("delete result")
	}
	if rs := tr.Recent(0, 10, Filter{}); len(rs) != 1 || rs[0].IP != "2.2.2.2" {
		t.Fatalf("recent after delete: %+v", rs)
	}
	tr.Purge()
	if st := tr.Stats(); st.IPs != 0 || st.Visits != 0 {
		t.Fatalf("purge left data: %+v", st)
	}
}

func TestResizeRing(t *testing.T) {
	tr := newTestTracker(t, DefaultSettings())
	for i := 0; i < 300; i++ {
		tr.Record(ev("1.1.1.1", "a", fmt.Sprintf("/%d", i), 200))
	}
	flush(t, tr, 300)
	s := tr.Settings()
	s.MaxVisits = 100
	tr.SetSettings(s)
	r := tr.Recent(0, 0, Filter{})
	if len(r) != 100 || r[0].Path != "/299" {
		t.Fatalf("ring after resize: %d first %q", len(r), r[0].Path)
	}
}

func TestListFilterSortPage(t *testing.T) {
	tr := newTestTracker(t, DefaultSettings())
	for i := 0; i < 30; i++ {
		e := ev(fmt.Sprintf("6.6.6.%d", i), "a.example", "/", 200)
		e.Country = []string{"us", "de", "fr"}[i%3]
		if i%5 == 0 {
			e.Blocked = true
		}
		tr.Record(e)
		for j := 0; j < i; j++ { // different hit counts
			tr.Record(e)
		}
	}
	tr.Record(Event{Time: time.Now(), IP: "11.11.11.11", Host: "cf.example", Path: "/", Country: "jp", Status: 200, Via: ViaCloudflare, ViaHeader: "CF-Connecting-IP"})
	flush(t, tr, 30+435+1)

	res := tr.List(ListQuery{Sort: "hits", Desc: true, Size: 5})
	if res.Total != 31 || len(res.Items) != 5 || res.Items[0].IP != "6.6.6.29" {
		t.Fatalf("top by hits: %+v", res)
	}
	res = tr.List(ListQuery{Filter: Filter{Country: "de"}, Sort: "ip", Size: 100})
	if res.Total != 10 {
		t.Fatalf("country filter: %d", res.Total)
	}
	res = tr.List(ListQuery{Filter: Filter{BlockedOnly: true}, Size: 100})
	if res.Total != 6 {
		t.Fatalf("blocked only: %d", res.Total)
	}
	res = tr.List(ListQuery{Filter: Filter{Via: ViaCloudflare}})
	if res.Total != 1 || res.Items[0].ViaHeader != "CF-Connecting-IP" {
		t.Fatalf("via filter: %+v", res)
	}
	res = tr.List(ListQuery{Filter: Filter{Q: "cf.exa"}})
	if res.Total != 1 {
		t.Fatalf("search by host: %d", res.Total)
	}
	res = tr.List(ListQuery{Sort: "ip", Size: 10, Page: 3})
	if len(res.Items) != 1 || res.Page != 3 {
		t.Fatalf("last page: %+v", res)
	}
	res = tr.List(ListQuery{Page: 99})
	if len(res.Items) != 0 {
		t.Fatal("past the end should be empty")
	}
	sum := tr.Summary(time.Now())
	if sum.IPs != 31 || sum.New1h != 31 || sum.Via[ViaCloudflare] != 1 || len(sum.TopCountry) == 0 {
		t.Fatalf("summary: %+v", sum)
	}
}

func TestNewCountryCallback(t *testing.T) {
	s := DefaultSettings()
	s.NotifyNewCountry = true
	tr := New("", s)
	var got []string
	var mu sync.Mutex
	tr.OnNewCountry = func(c, ip, host string) { mu.Lock(); got = append(got, c); mu.Unlock() }
	tr.Start()
	defer tr.Close()
	tr.Record(ev("1.1.1.1", "a", "/", 200)) // first country ever: no alert (nothing to compare with)
	e := ev("2.2.2.2", "a", "/", 200)
	e.Country = "br"
	tr.Record(e)
	tr.Record(e)
	flush(t, tr, 3)
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "BR" {
		t.Fatalf("new country callbacks: %v", got)
	}
}

func TestConcurrentRecordAndQuery(t *testing.T) {
	tr := newTestTracker(t, DefaultSettings())
	var wg sync.WaitGroup
	var sent atomic.Uint64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				tr.Record(ev(fmt.Sprintf("12.0.%d.%d", g, i%50), "a", "/", 200))
				sent.Add(1)
			}
		}(g)
	}
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < 2; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					tr.List(ListQuery{Sort: "hits", Desc: true})
					tr.Recent(0, 20, Filter{})
					tr.Summary(time.Now())
					tr.Stats()
				}
			}
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && tr.Stats().Recorded+tr.Stats().Dropped < sent.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	readers.Wait()
	st := tr.Stats()
	if st.Recorded+st.Dropped != 8000 {
		t.Fatalf("recorded %d + dropped %d != 8000", st.Recorded, st.Dropped)
	}
	if st.IPs != 400 {
		t.Fatalf("ips %d", st.IPs)
	}
}

// ---- client attribution ----

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestAttribute(t *testing.T) {
	// the access layer resolved the client from CF-Connecting-IP because the peer is a trusted proxy
	via, header := Attribute("173.245.48.1", "203.0.113.9", hdr("CF-Connecting-IP", "203.0.113.9", "X-Forwarded-For", "203.0.113.9"))
	if via != ViaCloudflare || header != "CF-Connecting-IP" {
		t.Fatalf("cloudflare: %s %s", via, header)
	}
	// other trusted proxy
	via, header = Attribute("10.0.0.2", "198.51.100.4", hdr("X-Forwarded-For", "198.51.100.4, 10.0.0.2"))
	if via != ViaProxy || header != "X-Forwarded-For" {
		t.Fatalf("proxy: %s %s", via, header)
	}
	// spoofed CF-Connecting-IP from an untrusted peer: the access layer ignored it (client == peer)
	via, header = Attribute("198.51.100.77", "198.51.100.77", hdr("CF-Connecting-IP", "1.2.3.4"))
	if via != ViaDirect || header != "" {
		t.Fatalf("spoofed header must not mark the hit as cloudflare: %s %s", via, header)
	}
	// IPv4-mapped IPv6 peer equals the client
	if via, _ = Attribute("::ffff:192.0.2.1", "192.0.2.1", hdr()); via != ViaDirect {
		t.Fatal("mapped address should be direct")
	}
	// True-Client-IP alone (no Cf-Ray) is not cloudflare
	if via, _ = Attribute("10.0.0.2", "9.9.9.9", hdr("True-Client-IP", "9.9.9.9")); via != ViaProxy {
		t.Fatalf("true-client-ip without cf-ray: %s", via)
	}
}

// ---- export ----

func TestCSVFormulaInjection(t *testing.T) {
	for in, want := range map[string]string{
		"=1+1": "'=1+1", "+cmd|' /C calc'!A0": "'+cmd|' /C calc'!A0", "-2+3": "'-2+3", "@SUM(A1)": "'@SUM(A1)",
		"\tx": "'\tx", "normal": "normal", "": "",
	} {
		if got := CSVSafe(in); got != want {
			t.Errorf("CSVSafe(%q) = %q want %q", in, got, want)
		}
	}
	var buf bytes.Buffer
	err := WriteVisitorsCSV(&buf, []Visitor{{IP: "1.1.1.1", LastUA: "=HYPERLINK(\"http://evil\")", LastPath: "/a,b\"c", Hosts: map[string]uint32{"@h": 1}}})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "'=HYPERLINK") || !strings.Contains(out, "'@h") {
		t.Fatalf("formula not neutralised:\n%s", out)
	}
	if !strings.Contains(out, `"/a,b""c"`) {
		t.Fatalf("csv quoting broken:\n%s", out)
	}
	buf.Reset()
	if err := WriteVisitsCSV(&buf, []Visit{{IP: "1.1.1.1", UA: "+evil", Path: "/", Time: 1700000000}}); err != nil || !strings.Contains(buf.String(), "'+evil") {
		t.Fatalf("visits csv: %v\n%s", err, buf.String())
	}
}

func TestSettingsNormalize(t *testing.T) {
	s := Settings{MaxIPs: 5, MaxAgeDays: 99999, MaxVisits: -1}.Normalize()
	if s.MaxIPs != 100 || s.MaxAgeDays != 3650 || s.MaxVisits != 5000 {
		t.Fatalf("normalize: %+v", s)
	}
	if d := (Settings{}).Normalize(); d.MaxIPs != 20000 || d.MaxAgeDays != 90 {
		t.Fatalf("defaults: %+v", d)
	}
}

// ---- benchmarks: the hot path is a channel send; a mutex guarded map is what it replaces ----

func BenchmarkRecordParallel(b *testing.B) {
	tr := New("", DefaultSettings())
	tr.Start()
	defer tr.Close()
	e := ev("1.2.3.4", "a.example", "/index", 200)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tr.Record(e)
		}
	})
}

func BenchmarkGlobalMutexMapParallel(b *testing.B) {
	var mu sync.Mutex
	m := map[string]*Visitor{}
	e := ev("1.2.3.4", "a.example", "/index", 200)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			v := m[e.IP]
			if v == nil {
				v = &Visitor{Hosts: map[string]uint32{}}
				m[e.IP] = v
			}
			v.Hits++
			bump(v.Hosts, e.Host, maxHostsPerIP)
			mu.Unlock()
		}
	})
}
