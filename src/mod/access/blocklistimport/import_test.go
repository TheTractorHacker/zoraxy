package blocklistimport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

func newRule(t testing.TB) (*access.Controller, *access.AccessRule) {
	t.Helper()
	tmp := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(tmp, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	lg, _ := logger.NewFmtLogger()
	c, err := access.NewAccessController(&access.Options{
		Logger: *lg, ConfigFolder: filepath.Join(tmp, "access"),
		TrustedProxiesFile: filepath.Join(tmp, "tp.json"), Database: db,
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.GetAccessRuleByID("default")
	if err != nil {
		t.Fatal(err)
	}
	return c, r
}

func mustParse(t testing.TB, s string, keep bool) *Parsed {
	t.Helper()
	p, err := Parse(strings.NewReader(s), 0, "", keep)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNormalize(t *testing.T) {
	good := map[string]string{
		"1.2.3.4":             "1.2.3.4",
		" 1.2.3.4 ":           "1.2.3.4",
		"2001:DB8::1":         "2001:db8::1",
		"::ffff:1.2.3.4":      "1.2.3.4",
		"10.1.2.3/8":          "10.0.0.0/8",
		"192.0.2.9/32":        "192.0.2.9",
		"2001:db8::5/48":      "2001:db8::/48",
		"2001:db8::1/128":     "2001:db8::1",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
	}
	for in, want := range good {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.4/33", "1.2.3.4/-1", "0.0.0.0/0", "::/0",
		"0.0.0.0", "::", "fe80::1%eth0", "10.*.*.*", "1.2.3.4:80", "http://1.2.3.4", "1.2.3.4/abc", "<script>", "::ffff:0.0.0.0/96"} {
		if got, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) accepted as %q", bad, got)
		}
	}
}

func TestParseFormatsAndReport(t *testing.T) {
	in := "\xef\xbb\xbf# header comment\n" +
		"; another comment\n" +
		"\n" +
		"1.1.1.1\n" +
		"  2.2.2.0/24   # trailing note\n" +
		"3.3.3.3,scanner,extra\n" +
		"\"4.4.4.4\",\"quoted comment\"\n" +
		"5.5.5.5;semi comment\n" +
		"1.1.1.1\n" + //dup of line 4
		"2.2.2.77/24\n" + //dup after normalisation of line 5
		"not-an-ip\n" +
		"999.1.1.1\n" +
		"2001:db8::/32\n" +
		"ip,comment\n" + //csv header
		"1.2.3.4\r\n"
	p := mustParse(t, in, true)
	var vals []string
	for _, e := range p.Entries {
		vals = append(vals, e.Value)
	}
	want := "1.1.1.1 2.2.2.0/24 3.3.3.3 4.4.4.4 5.5.5.5 2001:db8::/32 1.2.3.4"
	if strings.Join(vals, " ") != want {
		t.Fatalf("entries = %v", vals)
	}
	if p.DuplicateN != 2 || p.Duplicates[0].Line != 9 || !strings.Contains(p.Duplicates[0].Reason, "line 4") || p.Duplicates[1].Line != 10 {
		t.Fatalf("duplicates = %+v", p.Duplicates)
	}
	if p.InvalidN != 3 {
		t.Fatalf("invalid = %+v", p.Invalid)
	}
	lines := map[int]bool{}
	for _, i := range p.Invalid {
		lines[i.Line] = true
	}
	if !lines[11] || !lines[12] || !lines[14] {
		t.Fatalf("invalid line numbers = %+v", p.Invalid)
	}
	if p.Entries[1].Comment != "trailing note" || p.Entries[2].Comment != "scanner,extra" || p.Entries[3].Comment != "quoted comment" || p.Entries[4].Comment != "semi comment" {
		t.Fatalf("comments = %+v", p.Entries)
	}
	// remote sources ignore line comments
	p2 := mustParse(t, "1.1.1.1 # evil\n", false)
	if p2.Entries[0].Comment != "" {
		t.Fatal("line comment kept")
	}
}

func TestParseCommentSanitised(t *testing.T) {
	p := mustParse(t, "1.1.1.1 <img src=x onerror=alert(1)>hi<script>alert(1)</script>\n", true)
	c := p.Entries[0].Comment
	if strings.ContainsAny(c, "<>") {
		t.Fatalf("markup survived: %q", c)
	}
	long := mustParse(t, "1.1.1.1 "+strings.Repeat("x", 500)+"\n", true)
	if len(long.Entries[0].Comment) > MaxCommentLen {
		t.Fatal("comment not capped")
	}
}

func TestParseLimits(t *testing.T) {
	long := "1.1.1.1\n" + strings.Repeat("a", 3*MaxLineBytes) + "\n2.2.2.2\n"
	p := mustParse(t, long, false)
	if len(p.Entries) != 2 || p.InvalidN != 1 || p.Invalid[0].Line != 2 {
		t.Fatalf("long line handling: %+v", p)
	}
	_, err := Parse(strings.NewReader("1.1.1.1\n2.2.2.2\n3.3.3.3\n"), 2, "", false)
	if !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("err = %v", err)
	}
	// issue lists are capped but counts exact
	var b strings.Builder
	for i := 0; i < MaxIssuesReported+100; i++ {
		b.WriteString("bad\n")
	}
	p = mustParse(t, b.String(), false)
	if p.InvalidN != MaxIssuesReported+100 || len(p.Invalid) != MaxIssuesReported {
		t.Fatalf("caps: %d %d", p.InvalidN, len(p.Invalid))
	}
}

func TestPreviewApplyAndDedupAgainstExisting(t *testing.T) {
	_, rule := newRule(t)
	rule.AddIPToBlackList("1.1.1.1", "manual")
	p := mustParse(t, "1.1.1.1\n2.2.2.2\n2.2.2.2\nbad\n10.0.0.0/8\n", false)

	pre, err := Preview(rule, "blacklist", p, "")
	if err != nil {
		t.Fatal(err)
	}
	if !pre.DryRun || pre.Accepted != 2 || pre.AlreadyPresent != 1 || pre.Duplicates != 1 || pre.Invalid != 1 {
		t.Fatalf("preview: %s", pre)
	}
	if rule.IPListSize(access.IPListBlack) != 1 {
		t.Fatal("dry run modified the list")
	}
	rep, err := Apply(rule, "blacklist", p, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 2 || rule.IPListSize(access.IPListBlack) != 3 {
		t.Fatalf("apply: %s size %d", rep, rule.IPListSize(access.IPListBlack))
	}
	if !rule.IPListHas(access.IPListBlack, "10.0.0.0/8") {
		t.Fatal("cidr missing")
	}
	// the rule enforces the imported entries
	rule.BlacklistEnabled = true
	if !rule.IsIPBlacklisted("10.9.9.9") || !rule.IsIPBlacklisted("2.2.2.2") {
		t.Fatal("imported entries not enforced")
	}
	// manual comment kept
	if rule.IPListSnapshot(access.IPListBlack)["1.1.1.1"] != "manual" {
		t.Fatal("existing entry overwritten")
	}
	// whitelist target works and is independent
	if _, err := Apply(rule, "whitelist", mustParse(t, "9.9.9.9\n", false), ""); err != nil || !rule.IPListHas(access.IPListWhite, "9.9.9.9") || rule.IPListHas(access.IPListBlack, "9.9.9.9") {
		t.Fatalf("whitelist import: %v", err)
	}
	if _, err := Apply(rule, "bogus", p, ""); err == nil {
		t.Fatal("bad list accepted")
	}
	// persisted to disk
	if rule.SaveChanges() != nil {
		t.Fatal("save")
	}
}

func TestLargeImport200k(t *testing.T) {
	_, rule := newRule(t)
	var b strings.Builder
	for i := 0; i < 200_000; i++ {
		fmt.Fprintf(&b, "%d.%d.%d.%d\n", 11+(i>>16)&0x7f, (i>>8)&0xff, i&0xff, 1)
	}
	start := time.Now()
	p := mustParse(t, b.String(), false)
	if len(p.Entries) != 200_000 {
		t.Fatalf("parsed %d", len(p.Entries))
	}
	rep, err := Apply(rule, "blacklist", p, "src1")
	if err != nil || rep.Accepted != 200_000 {
		t.Fatalf("%v %v", rep, err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("200k import took %s", d)
	}
	if rule.IPListSize(access.IPListBlack) != 200_000 {
		t.Fatal("size")
	}
}

func TestSourceTagReplacesOnlyOwnEntries(t *testing.T) {
	_, rule := newRule(t)
	rule.AddIPToBlackList("7.7.7.7", "manual entry")
	rule.AddIPToBlackList("8.8.8.8", "manual entry")
	// other source
	Apply(rule, "blacklist", mustParse(t, "20.0.0.1\n", false), "other")

	Apply(rule, "blacklist", mustParse(t, "1.1.1.1\n2.2.2.2\n8.8.8.8\n", false), "abc")
	snap := rule.IPListSnapshot(access.IPListBlack)
	if !strings.HasPrefix(snap["1.1.1.1"], "[src:abc]") {
		t.Fatalf("tag missing: %q", snap["1.1.1.1"])
	}
	if snap["8.8.8.8"] != "manual entry" {
		t.Fatal("manual entry re-tagged by the import")
	}

	// refresh: 2.2.2.2 gone upstream, 3.3.3.3 new, 8.8.8.8 also upstream
	rep, err := Apply(rule, "blacklist", mustParse(t, "1.1.1.1\n3.3.3.3\n8.8.8.8\n", false), "abc")
	if err != nil || rep.Removed != 1 || rep.Accepted != 1 {
		t.Fatalf("refresh: %v %v", rep, err)
	}
	snap = rule.IPListSnapshot(access.IPListBlack)
	for _, gone := range []string{"2.2.2.2"} {
		if _, ok := snap[gone]; ok {
			t.Fatalf("%s should have been removed", gone)
		}
	}
	for _, kept := range []string{"7.7.7.7", "8.8.8.8", "20.0.0.1", "1.1.1.1", "3.3.3.3"} {
		if _, ok := snap[kept]; !ok {
			t.Fatalf("%s must be kept", kept)
		}
	}
	// A refresh that drops a manual entry upstream never removes it
	Apply(rule, "blacklist", mustParse(t, "1.1.1.1\n", false), "abc")
	if _, ok := rule.IPListSnapshot(access.IPListBlack)["8.8.8.8"]; !ok {
		t.Fatal("manual entry removed by refresh")
	}
	// empty download must not wipe the source
	if _, err := Apply(rule, "blacklist", mustParse(t, "garbage\n", false), "abc"); !errors.Is(err, ErrWouldEmpty) {
		t.Fatalf("empty refresh: %v", err)
	}
	if !rule.IPListHas(access.IPListBlack, "1.1.1.1") {
		t.Fatal("entries lost after refused refresh")
	}
	n, err := RemoveSourceEntries(rule, "blacklist", "abc")
	if err != nil || n != 1 || rule.IPListSize(access.IPListBlack) != 3 {
		t.Fatalf("remove source entries: %d %v size=%d", n, err, rule.IPListSize(access.IPListBlack))
	}
}

// ---------- SSRF / fetcher ----------

func TestIsPublicAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "172.16.5.5", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
		"::1", "fe80::1", "fd00::1", "::", "224.0.0.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1", "198.18.0.1", "255.255.255.255"} {
		if IsPublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s must not be public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "93.184.216.34"} {
		if !IsPublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s must be public", s)
		}
	}
}

func TestValidateURL(t *testing.T) {
	for _, bad := range []string{"http://example.com/x", "ftp://example.com", "file:///etc/passwd", "https://user:pw@example.com/", "https:///x", "//example.com", "example.com", "gopher://x", ""} {
		if _, err := ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) accepted", bad)
		}
	}
	if _, err := ValidateURL("https://example.com/list.txt"); err != nil {
		t.Fatal(err)
	}
}

// newTestFetcher returns a fetcher whose resolver maps names through table
// and whose dialer always connects to the httptest TLS server, recording
// which addresses it was asked to dial.
func newTestFetcher(t *testing.T, srv *httptest.Server, table map[string][]string, dialed *[]string) *Fetcher {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &Fetcher{
		Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			v, ok := table[host]
			if !ok {
				return nil, errors.New("no such host")
			}
			var out []netip.Addr
			for _, s := range v {
				out = append(out, netip.MustParseAddr(s))
			}
			return out, nil
		},
		DialTo: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dialed != nil {
				*dialed = append(*dialed, addr)
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "", MinVersion: tls.VersionTLS12},
	}
}

func tlsServer(t *testing.T, h http.Handler) *httptest.Server {
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// httptest certificates are valid for example.com
const goodHost = "example.com"

func TestFetchSuccessAndPinnedDial(t *testing.T) {
	srv := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("1.1.1.1\n2.2.2.2\n")) }))
	var dialed []string
	f := newTestFetcher(t, srv, map[string][]string{goodHost: {"93.184.216.34"}}, &dialed)
	rc, err := f.Fetch(context.Background(), "https://"+goodHost+"/list.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	p, err := Parse(rc, 0, "", false)
	if err != nil || len(p.Entries) != 2 {
		t.Fatalf("parse: %v %+v", err, p)
	}
	if len(dialed) != 1 || dialed[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v: must connect to the validated address, not re-resolve", dialed)
	}
}

func TestFetchRefusesNonPublicTargets(t *testing.T) {
	var hits atomic.Int32
	srv := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("1.1.1.1\n")) }))
	table := map[string][]string{
		goodHost:         {"93.184.216.34"},
		"loopback.test":  {"127.0.0.1"},
		"private.test":   {"10.1.2.3"},
		"linklocal.test": {"169.254.169.254"},
		"v6loop.test":    {"::1"},
		"ula.test":       {"fd12::1"},
		"mapped.test":    {"::ffff:192.168.0.1"},
		"mixed.test":     {"93.184.216.34", "127.0.0.1"}, //one bad answer poisons the lot
	}
	f := newTestFetcher(t, srv, table, nil)
	for _, h := range []string{"loopback.test", "private.test", "linklocal.test", "v6loop.test", "ula.test", "mapped.test", "mixed.test"} {
		if _, err := f.Fetch(context.Background(), "https://"+h+"/x"); !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("%s: err = %v, want ErrBlockedTarget", h, err)
		}
	}
	// literal IPs in the URL
	for _, u := range []string{"https://127.0.0.1/x", "https://[::1]/x", "https://169.254.169.254/latest/meta-data", "https://10.0.0.1:8443/x", "https://0.0.0.0/"} {
		if _, err := f.Fetch(context.Background(), u); !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("%s: err = %v", u, err)
		}
	}
	// non https
	if _, err := f.Fetch(context.Background(), "http://"+goodHost+"/x"); err == nil {
		t.Error("http accepted")
	}
	if hits.Load() != 0 {
		t.Fatalf("server contacted %d times for refused targets", hits.Load())
	}
}

func TestFetchRefusesRedirectToPrivate(t *testing.T) {
	var mux http.ServeMux
	var hits atomic.Int32
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("1.1.1.1\n")) })
	mux.HandleFunc("/to-private", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://private.test/secret", http.StatusFound)
	})
	mux.HandleFunc("/to-literal", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest", http.StatusFound)
	})
	mux.HandleFunc("/to-http", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+goodHost+"/ok", http.StatusFound)
	})
	mux.HandleFunc("/to-public", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+goodHost+"/ok", http.StatusFound)
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+goodHost+"/loop", http.StatusFound)
	})
	srv := tlsServer(t, &mux)
	f := newTestFetcher(t, srv, map[string][]string{goodHost: {"93.184.216.34"}, "private.test": {"192.168.1.5"}}, nil)

	for _, p := range []string{"/to-private", "/to-literal"} {
		if _, err := f.Fetch(context.Background(), "https://"+goodHost+p); !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("%s: err = %v, want ErrBlockedTarget", p, err)
		}
	}
	if _, err := f.Fetch(context.Background(), "https://"+goodHost+"/to-http"); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Errorf("redirect to http: %v", err)
	}
	if _, err := f.Fetch(context.Background(), "https://"+goodHost+"/loop"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("redirect loop: %v", err)
	}
	rc, err := f.Fetch(context.Background(), "https://"+goodHost+"/to-public")
	if err != nil {
		t.Fatalf("public redirect refused: %v", err)
	}
	rc.Close()
}

func TestFetchSizeLimitStatusAndTimeout(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		for i := 0; i < 100; i++ {
			w.Write([]byte(strings.Repeat("1.2.3.4\n", 100)))
			w.(http.Flusher).Flush()
		}
	})
	mux.HandleFunc("/declared", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.Write([]byte("x"))
	})
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	srv := tlsServer(t, &mux)
	f := newTestFetcher(t, srv, map[string][]string{goodHost: {"93.184.216.34"}}, nil)
	f.MaxBytes = 1000

	rc, err := f.Fetch(context.Background(), "https://"+goodHost+"/big")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(rc, 0, "", false)
	rc.Close()
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("streamed oversize: %v", err)
	}
	if _, err := f.Fetch(context.Background(), "https://"+goodHost+"/declared"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("declared oversize: %v", err)
	}
	if _, err := f.Fetch(context.Background(), "https://"+goodHost+"/404"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404: %v", err)
	}
	f.Timeout = 300 * time.Millisecond
	start := time.Now()
	if _, err := f.Fetch(context.Background(), "https://"+goodHost+"/slow"); err == nil {
		t.Fatal("timeout not enforced")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout too slow")
	}
}

// ---------- Manager / scheduled refresh ----------

func TestManagerScheduledRefreshReplacesOnlyTaggedEntries(t *testing.T) {
	ctrl, rule := newRule(t)
	var body atomic.Value
	body.Store("1.1.1.1\n2.2.2.2\n# comment\n")
	srv := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body.Load().(string))) }))

	dir := t.TempDir()
	mgr, err := NewManager(filepath.Join(dir, "sources.json"), ctrl.GetAccessRuleByID)
	if err != nil {
		t.Fatal(err)
	}
	mgr.Fetcher = newTestFetcher(t, srv, map[string][]string{goodHost: {"93.184.216.34"}}, nil)
	clock := time.Unix(1_700_000_000, 0)
	mgr.now = func() time.Time { return clock }

	rule.AddIPToBlackList("7.7.7.7", "manual")
	// validation of the source
	if _, err := mgr.Add(Source{RuleID: "default", List: "blacklist", URL: "http://" + goodHost + "/l"}); err == nil {
		t.Fatal("http source accepted")
	}
	if _, err := mgr.Add(Source{RuleID: "default", List: "blacklist", URL: "https://" + goodHost + "/l", IntervalMinutes: 3}); err == nil {
		t.Fatal("interval below minimum accepted")
	}
	if _, err := mgr.Add(Source{RuleID: "nope", List: "blacklist", URL: "https://" + goodHost + "/l"}); err == nil {
		t.Fatal("unknown rule accepted")
	}
	src, err := mgr.Add(Source{Name: "<b>feed</b>", RuleID: "default", List: "blacklist", URL: "https://" + goodHost + "/l", IntervalMinutes: 60, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(src.Name, "<") {
		t.Fatal("name not sanitised")
	}

	// first run is due immediately (LastRun = 0)
	if due := mgr.RunDue(context.Background()); len(due) != 1 {
		t.Fatalf("due = %v", due)
	}
	got, _ := mgr.Get(src.ID)
	if got.LastError != "" || got.EntryCount != 2 || got.LastAccepted != 2 {
		t.Fatalf("after first run: %+v", got)
	}
	if rule.IPListSize(access.IPListBlack) != 3 {
		t.Fatalf("size %d", rule.IPListSize(access.IPListBlack))
	}

	// not due again before the interval
	clock = clock.Add(30 * time.Minute)
	if due := mgr.RunDue(context.Background()); len(due) != 0 {
		t.Fatalf("refreshed too early: %v", due)
	}
	// upstream changed; interval elapsed
	body.Store("2.2.2.2\n3.3.3.3\n")
	clock = clock.Add(31 * time.Minute)
	if due := mgr.RunDue(context.Background()); len(due) != 1 {
		t.Fatalf("not refreshed: %v", due)
	}
	snap := rule.IPListSnapshot(access.IPListBlack)
	if _, ok := snap["1.1.1.1"]; ok {
		t.Fatal("stale tagged entry kept")
	}
	if snap["7.7.7.7"] != "manual" || snap["3.3.3.3"] == "" || snap["2.2.2.2"] == "" {
		t.Fatalf("snapshot = %v", snap)
	}

	// failing upstream keeps entries and records the error
	body.Store("<html>error</html>\n")
	clock = clock.Add(2 * time.Hour)
	mgr.RunDue(context.Background())
	got, _ = mgr.Get(src.ID)
	if got.LastError == "" || !rule.IPListHas(access.IPListBlack, "3.3.3.3") {
		t.Fatalf("failed refresh must keep entries and report: %+v", got)
	}

	// disabled sources are never scheduled but can be refreshed by hand
	if err := mgr.Update(src.ID, 60, false, ""); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(24 * time.Hour)
	if due := mgr.RunDue(context.Background()); len(due) != 0 {
		t.Fatalf("disabled source scheduled: %v", due)
	}
	body.Store("5.5.5.5\n")
	if _, err := mgr.Refresh(context.Background(), src.ID); err != nil {
		t.Fatal(err)
	}
	if rule.IPListHas(access.IPListBlack, "3.3.3.3") || !rule.IPListHas(access.IPListBlack, "5.5.5.5") || !rule.IPListHas(access.IPListBlack, "7.7.7.7") {
		t.Fatal("manual refresh result wrong")
	}

	// persistence
	mgr2, err := NewManager(filepath.Join(dir, "sources.json"), ctrl.GetAccessRuleByID)
	if err != nil || len(mgr2.List("")) != 1 || mgr2.List("default")[0].ID != src.ID {
		t.Fatalf("reload: %v", err)
	}

	// removing the source can remove exactly its entries
	n, err := mgr.Remove(src.ID, true)
	if err != nil || n != 1 || rule.IPListSize(access.IPListBlack) != 1 || !rule.IPListHas(access.IPListBlack, "7.7.7.7") {
		t.Fatalf("remove: %d %v", n, err)
	}
}

func TestManagerRefreshBlockedTargetRecorded(t *testing.T) {
	ctrl, _ := newRule(t)
	srv := tlsServer(t, http.NotFoundHandler())
	mgr, _ := NewManager(filepath.Join(t.TempDir(), "s.json"), ctrl.GetAccessRuleByID)
	mgr.Fetcher = newTestFetcher(t, srv, map[string][]string{"internal.test": {"10.0.0.8"}}, nil)
	src, err := mgr.Add(Source{RuleID: "default", List: "whitelist", URL: "https://internal.test/l"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Refresh(context.Background(), src.ID); !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := mgr.Get(src.ID); !strings.Contains(got.LastError, "not allowed") {
		t.Fatalf("error not recorded: %+v", got)
	}
}

func BenchmarkParse200k(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 200_000; i++ {
		fmt.Fprintf(&sb, "%d.%d.%d.%d\n", 11+(i>>16)&0x7f, (i>>8)&0xff, i&0xff, 1)
	}
	s := sb.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Parse(strings.NewReader(s), 0, "", false)
	}
}
