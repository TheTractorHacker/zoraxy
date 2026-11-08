package logviewer

import (
	"compress/gzip"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tline(ts time.Time, host, ip, ua, method, uri string, status int) string {
	return fmt.Sprintf("[%s] [router:host-http] [origin:%s] [client: %s] [useragent: %s] %s %s %d", ts.Format("2006-01-02 15:04:05.000000"), host, ip, ua, method, uri, status)
}

func get(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func mustQuery(t *testing.T, m map[string]string) *Query {
	t.Helper()
	q, err := ParseQuery(get(m))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestParseLine(t *testing.T) {
	ts := time.Date(2026, 3, 4, 5, 6, 7, 123456000, time.Local)
	e, ok := ParseLine(tline(ts, "a.example", "1.2.3.4", "Mozilla/5.0 [odd] x", "GET", "/p?q=1", 404))
	if !ok || e.Origin != "a.example" || e.Client != "1.2.3.4" || e.Agent != "Mozilla/5.0 [odd] x" || e.Status != 404 || e.URI != "/p?q=1" || !e.Time.Equal(ts) {
		t.Fatalf("%+v ok=%v", e, ok)
	}
	if _, ok := ParseLine("[2026-03-04 05:06:07.000000] [system:info] hello"); ok {
		t.Fatal("system line parsed as request")
	}
	if _, ok := ParseLine(""); ok {
		t.Fatal("empty")
	}
	e, ok = ParseLine(`{"time":"2026-03-04T05:06:07Z","class":"c","site":"s","origin":"o","client":"::1","useragent":"u","method":"POST","uri":"/","status":500}`)
	if !ok || e.Status != 500 || e.Site != "s" || e.Method != "POST" {
		t.Fatalf("json: %+v", e)
	}
}

func TestParseQueryValidationAndCostBounds(t *testing.T) {
	bad := []map[string]string{
		{"status": "99"}, {"status": "abc"}, {"ip": "999.1.1.1"}, {"ip": "10.0.0.0/99"},
		{"pathregex": "("}, {"pathregex": strings.Repeat("a", MaxPatternLength+1)}, {"path": strings.Repeat("a", MaxPatternLength+1)},
		{"from": "yesterday"}, {"limit": "0"}, {"offset": "-1"}, {"maxscanmb": "0"}, {"maxscansec": "x"},
	}
	for _, m := range bad {
		if _, err := ParseQuery(get(m)); err == nil {
			t.Errorf("accepted %v", m)
		}
	}
	q := mustQuery(t, map[string]string{"limit": "999999", "maxscanmb": "999999", "maxscansec": "99999"})
	if q.Limit != MaxResults || q.MaxScanBytes != MaxScanBytesCap || q.MaxScanTime != MaxScanTimeCap {
		t.Fatalf("caps not applied: %+v", q)
	}
	q = mustQuery(t, map[string]string{"status": "4xx, 503", "method": "get,post", "ip": "10.0.0.0/8, 2001:db8::1"})
	if !q.StatusClass[4] || !q.StatusSet[503] || !q.Methods["GET"] || len(q.Prefixes) != 2 {
		t.Fatalf("%+v", q)
	}
	// a catastrophic pattern for backtracking engines must be cheap (RE2)
	q = mustQuery(t, map[string]string{"pathregex": "(a+)+$"})
	start := time.Now()
	q.Match(&Entry{URI: strings.Repeat("a", 5000) + "!"})
	if time.Since(start) > time.Second {
		t.Fatal("regex too slow")
	}
}

func TestQueryMatch(t *testing.T) {
	now := time.Now()
	e := Entry{Time: now, Origin: "Shop.Example.com", Client: "10.1.2.3", Agent: "curl/8", Method: "GET", URI: "/Admin/login?x=1", Status: 403}
	cases := []struct {
		m    map[string]string
		want bool
	}{
		{map[string]string{"status": "4xx"}, true}, {map[string]string{"status": "5xx"}, false}, {map[string]string{"status": "403"}, true},
		{map[string]string{"method": "post"}, false}, {map[string]string{"host": "shop"}, true}, {map[string]string{"host": "blog"}, false},
		{map[string]string{"ip": "10.0.0.0/8"}, true}, {map[string]string{"ip": "192.168.0.0/16"}, false}, {map[string]string{"ip": "10.1.2.3"}, true},
		{map[string]string{"path": "/admin"}, true}, {map[string]string{"pathregex": `^/admin/\w+\?x=\d$`}, false}, {map[string]string{"pathregex": `^/Admin/\w+\?x=\d$`}, true},
		{map[string]string{"useragent": "CURL"}, true}, {map[string]string{"useragent": "wget"}, false},
		{map[string]string{"from": fmt.Sprint(now.Add(time.Hour).Unix())}, false}, {map[string]string{"to": fmt.Sprint(now.Add(-time.Hour).Unix())}, false},
	}
	for _, c := range cases {
		if got := mustQuery(t, c.m).Match(&e); got != c.want {
			t.Errorf("%v: got %v want %v", c.m, got, c.want)
		}
	}
}

func writeLog(t *testing.T, path string, lines []string, gz bool) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	content := strings.Join(lines, "\n") + "\n"
	if gz {
		f, _ := os.Create(path)
		zw := gzip.NewWriter(f)
		zw.Write([]byte(content))
		zw.Close()
		f.Close()
		return
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) (*Viewer, time.Time) {
	root := t.TempDir()
	base := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	var cur, old, site []string
	for i := 0; i < 100; i++ {
		cur = append(cur, tline(base.Add(time.Duration(i)*time.Second), "a.example", "1.1.1.1", "ua", "GET", fmt.Sprintf("/p/%d", i), 200+(i%2)*204))
	}
	cur = append(cur, "[2026-01-01 00:00:00.000000] [system:info] noise")
	for i := 0; i < 50; i++ {
		old = append(old, tline(base.Add(-48*time.Hour+time.Duration(i)*time.Second), "a.example", "2.2.2.2", "ua", "POST", fmt.Sprintf("/old/%d", i), 500))
	}
	site = append(site, `{"time":"`+base.Add(10*time.Second).UTC().Format(time.RFC3339Nano)+`","class":"host-http","site":"s.example","origin":"s.example","client":"3.3.3.3","useragent":"bot","method":"GET","uri":"/json","status":502}`)
	writeLog(t, filepath.Join(root, "zr_2026-1.log"), cur, false)
	writeLog(t, filepath.Join(root, "zr_2025-12.log.gz"), old, true)
	os.Chtimes(filepath.Join(root, "zr_2025-12.log.gz"), base.Add(-47*time.Hour), base.Add(-47*time.Hour))
	writeLog(t, filepath.Join(root, "sites", "s.example", "s.example.log"), site, false)
	// must be ignored: nested deeper and non-log files
	writeLog(t, filepath.Join(root, "sites", "s.example", "deep", "x.log"), cur, false)
	os.WriteFile(filepath.Join(root, "notes.txt"), []byte("x"), 0o644)
	return NewLogViewer(&ViewerOption{RootFolder: root}), base
}

func TestSearchOrderPagingAndSources(t *testing.T) {
	v, _ := fixture(t)
	res := v.Search(mustQuery(t, map[string]string{"source": "global", "limit": "10"}), nil)
	if len(res.Entries) != 10 || res.Entries[0].URI != "/p/99" || res.Entries[9].URI != "/p/90" || res.NextOffset != 10 {
		t.Fatalf("newest first: %+v", res.Entries)
	}
	res2 := v.Search(mustQuery(t, map[string]string{"source": "global", "limit": "10", "offset": "10"}), nil)
	if res2.Entries[0].URI != "/p/89" {
		t.Fatalf("page 2 starts at %s", res2.Entries[0].URI)
	}
	// spans into the gz file (newest to oldest)
	all := v.Search(mustQuery(t, map[string]string{"source": "global", "limit": "1000"}), nil)
	if len(all.Entries) != 150 || all.Entries[100].URI != "/old/49" || all.Entries[149].URI != "/old/0" || all.Truncated {
		t.Fatalf("got %d entries, truncated=%v", len(all.Entries), all.Truncated)
	}
	if got := v.ListSources(); len(got) != 2 || got[0] != "global" || got[1] != "s.example" {
		t.Fatalf("sources %v", got)
	}
	s := v.Search(mustQuery(t, map[string]string{"source": "s.example"}), nil)
	if len(s.Entries) != 1 || s.Entries[0].Status != 502 || s.Entries[0].Source != "s.example" {
		t.Fatalf("site log json: %+v", s.Entries)
	}
	// everything: global + site (deep dir ignored)
	if n := len(v.Search(mustQuery(t, map[string]string{"limit": "1000"}), nil).Entries); n != 151 {
		t.Fatalf("all sources = %d", n)
	}
}

func TestSearchFiltersAndTimeRange(t *testing.T) {
	v, base := fixture(t)
	r := v.Search(mustQuery(t, map[string]string{"status": "404", "limit": "1000"}), nil)
	if len(r.Entries) != 50 {
		t.Fatalf("status 404: %d", len(r.Entries))
	}
	r = v.Search(mustQuery(t, map[string]string{"status": "5xx", "ip": "2.2.2.0/24", "limit": "1000"}), nil)
	if len(r.Entries) != 50 || r.Entries[0].Method != "POST" {
		t.Fatalf("5xx cidr: %d", len(r.Entries))
	}
	r = v.Search(mustQuery(t, map[string]string{"from": fmt.Sprint(base.Add(90 * time.Second).Unix()), "limit": "1000"}), nil)
	if len(r.Entries) != 10 { // /p/90..99
		t.Fatalf("time range: %d", len(r.Entries))
	}
	r = v.Search(mustQuery(t, map[string]string{"pathregex": `^/p/9\d$`, "limit": "1000"}), nil)
	if len(r.Entries) != 10 {
		t.Fatalf("regex: %d", len(r.Entries))
	}
	geo := func(ip string) string {
		if ip == "2.2.2.2" {
			return "DE"
		}
		return "US"
	}
	r = v.Search(mustQuery(t, map[string]string{"country": "de", "limit": "1000"}), geo)
	if len(r.Entries) != 50 || r.Entries[0].Country != "de" {
		t.Fatalf("country: %d", len(r.Entries))
	}
}

func TestSearchScanBoundsReportTruncation(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-time.Hour)
	var lines []string
	for i := 0; i < 20000; i++ {
		lines = append(lines, tline(base.Add(time.Duration(i)*time.Millisecond), "big.example", "9.9.9.9", strings.Repeat("u", 100), "GET", "/x", 200))
	}
	writeLog(t, filepath.Join(root, "zr_big.log"), lines, false)
	v := NewLogViewer(&ViewerOption{RootFolder: root})
	q := mustQuery(t, map[string]string{"status": "500", "limit": "10"}) // nothing matches: full scan wanted
	q.MaxScanBytes = 256 << 10                                           // far below the ~3.5MB file
	r := v.Search(q, nil)
	if !r.Truncated || r.TruncatedReason == "" || r.ScannedBytes > 256<<10+64<<10 {
		t.Fatalf("expected a truncated scan: %+v", r)
	}
	// time bound
	q = mustQuery(t, map[string]string{"status": "500"})
	q.MaxScanTime = time.Nanosecond
	time.Sleep(time.Millisecond)
	if r := v.Search(q, nil); !r.Truncated || !strings.Contains(r.TruncatedReason, "time") {
		t.Fatalf("time bound: %+v", r)
	}
	// long lines are skipped, not buffered
	long := tline(base, "h", "1.1.1.1", strings.Repeat("z", MaxLineBytes+10), "GET", "/", 200)
	writeLog(t, filepath.Join(root, "zr_long.log"), []string{long, tline(base, "h", "1.1.1.1", "ok", "GET", "/ok", 200)}, false)
	r = v.Search(mustQuery(t, map[string]string{"path": "/ok"}), nil)
	if len(r.Entries) != 1 {
		t.Fatalf("long line handling: %d", len(r.Entries))
	}
}

func TestSearchHandlersAndCSVExport(t *testing.T) {
	v, _ := fixture(t)
	// formula injection in exported CSV
	writeLog(t, filepath.Join(v.option.RootFolder, "zr_evil.log"), []string{tline(time.Now(), "h", "4.4.4.4", "=cmd|' /C calc'!A0", "GET", "/evil", 200)}, false)
	rec := httptest.NewRecorder()
	v.HandleSearchDownload(nil)(rec, httptest.NewRequest("GET", "/api/log/searchExport?format=csv&path="+url.QueryEscape("/evil"), nil))
	body := rec.Body.String()
	if !strings.Contains(body, "'=cmd") || strings.Contains(body, ",=cmd") || rec.Header().Get("X-Truncated") != "false" {
		t.Fatalf("csv: %q hdr=%v", body, rec.Header())
	}
	rec = httptest.NewRecorder()
	v.HandleSearch(nil)(rec, httptest.NewRequest("GET", "/api/log/search?pathregex=(", nil))
	if !strings.Contains(rec.Body.String(), "error") {
		t.Fatal("bad regex must produce an error")
	}
	rec = httptest.NewRecorder()
	v.HandleSearchDownload(nil)(rec, httptest.NewRequest("GET", "/api/log/searchExport?format=json&source=global&limit=5", nil))
	if !strings.Contains(rec.Body.String(), `"entries"`) {
		t.Fatal("json export")
	}
}
