package statistic

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
)

func newTestCollector(t *testing.T, maxEntries int) *Collector {
	t.Helper()
	db, err := database.NewDatabase(t.TempDir()+"/db", dbinc.BackendLevelDB)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewStatisticCollector(CollectorOption{Database: db, MaxEntriesPerStatMap: maxEntries})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitTotal(t *testing.T, c *Collector, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.GetExportSummary().TotalRequest == want {
			time.Sleep(30 * time.Millisecond) // let the rest of the record goroutine finish
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("total = %d, want %d", c.GetExportSummary().TotalRequest, want)
}

func TestPerSiteStatsAndSparkline(t *testing.T) {
	c := newTestCollector(t, 1000)
	for i := 0; i < 5; i++ {
		c.RecordRequest(RequestInfo{IpAddr: "1.1.1.1", Succ: true, StatusCode: 200, Site: "a.example.com", RequestURL: "a.example.com/index.html", RequestMethod: "GET", UserAgent: "ua"})
	}
	c.RecordRequest(RequestInfo{IpAddr: "2.2.2.2", Succ: false, StatusCode: 403, Site: "b.example.com", Blocked: true, RequestURL: "b.example.com/"})
	waitTotal(t, c, 6)
	list := c.GetSiteList()
	if len(list) != 2 || list[0].Site != "a.example.com" || list[0].Total != 5 || list[1].Blocked != 1 {
		t.Fatalf("bad site list: %+v", list)
	}
	var sum int64
	for _, h := range list[0].Hourly {
		sum += h
	}
	if sum != 5 {
		t.Fatalf("hourly sum = %d", sum)
	}
	ex := c.GetSiteExport("a.example.com")
	if ex.StatusCodes["200"] != 5 || ex.RequestClientIp["1.1.1.1"] != 5 || ex.RequestURL["a.example.com/index.html"] != 5 {
		t.Fatalf("bad export %+v", ex)
	}
	if g := c.GetExportSummary(); g.Sites["b.example.com"] == nil || g.BlockedRequest != 1 {
		t.Fatalf("global export lacks sites: %+v", g)
	}
	d := ex.AsDailySummaryExport()
	if d.TotalRequest != 5 || d.StatusCodes["200"] != 5 {
		t.Fatal("AsDailySummaryExport")
	}
}

func TestPerSiteCardinalityCaps(t *testing.T) {
	c := newTestCollector(t, 800) // per site map cap = 100
	ds := c.GetCurrentDailySummary()
	for i := 0; i < MaxSites+50; i++ {
		ri := RequestInfo{Site: fmt.Sprintf("s%d.example", i), Succ: true, IpAddr: "1.1.1.1"}
		c.recordSite(ds, &ri, ri.IpAddr, "", "", time.Now())
	}
	n := 0
	ds.sites.m.Range(func(_, _ interface{}) bool { n++; return true })
	if n > MaxSites {
		t.Fatalf("sites = %d > %d", n, MaxSites)
	}
	if _, ok := ds.sites.m.Load(OtherSiteKey); !ok {
		t.Fatal("overflow bucket missing")
	}
	for i := 0; i < 5000; i++ {
		ri := RequestInfo{Site: "big.example", Succ: true}
		c.recordSite(ds, &ri, fmt.Sprintf("10.0.%d.%d", i/250, i%250), "", "", time.Now())
	}
	v, ok := ds.sites.m.Load("big.example")
	if !ok {
		// folded into _other because the table is full: that is the cap working
		v, _ = ds.sites.m.Load(OtherSiteKey)
	}
	cnt := 0
	v.(*SiteSummary).RequestClient.Range(func(_, _ interface{}) bool { cnt++; return true })
	if cnt > siteMapCap(800) {
		t.Fatalf("client map %d exceeds cap %d", cnt, siteMapCap(800))
	}
}

func TestSitePersistRoundTrip(t *testing.T) {
	c := newTestCollector(t, 1000)
	c.RecordRequest(RequestInfo{IpAddr: "1.1.1.1", Succ: true, StatusCode: 200, Site: "a.example.com"})
	waitTotal(t, c, 1)
	c.SaveSummaryOfDay()
	y, m, d := time.Now().Date()
	s := c.LoadSummaryOfDay(y, m, d)
	if s.TotalRequest != 1 {
		t.Fatal("not persisted")
	}
	e := dailySummaryToExport(s)
	if e.Sites["a.example.com"] == nil || e.Sites["a.example.com"].TotalRequest != 1 {
		t.Fatalf("sites lost: %+v", e.Sites)
	}
}

func TestExclusionFilters(t *testing.T) {
	c := newTestCollector(t, 0)
	if err := c.SetSettings(Settings{ExcludeNetworks: []string{"192.168.1.0/24", "2001:db8::1", " 10.1.2.3 "}, ExcludeBlocked: true}); err != nil {
		t.Fatal(err)
	}
	c.RecordRequest(RequestInfo{IpAddr: "192.168.1.77", Succ: true})
	c.RecordRequest(RequestInfo{IpAddr: "2001:db8::1", Succ: true})
	c.RecordRequest(RequestInfo{IpAddr: "[2001:db8::1],1.2.3.4", Succ: true})
	c.RecordRequest(RequestInfo{IpAddr: "::ffff:10.1.2.3", Succ: true})
	c.RecordRequest(RequestInfo{IpAddr: "8.8.8.8", Succ: false, Blocked: true})
	c.RecordRequest(RequestInfo{IpAddr: "8.8.8.8", Succ: true})
	waitTotal(t, c, 1)
	if err := c.SetSettings(Settings{ExcludeNetworks: []string{"not-an-ip"}}); err == nil {
		t.Fatal("invalid entry accepted")
	}
	if err := c.SetSettings(Settings{QueryMode: "bogus"}); err == nil {
		t.Fatal("invalid mode accepted")
	}
	c.SetSettings(Settings{})
	c.RecordRequest(RequestInfo{IpAddr: "8.8.8.8", Succ: false, Blocked: true})
	waitTotal(t, c, 2)
	if c.GetExportSummary().BlockedRequest != 1 {
		t.Fatal("blocked counter")
	}
}

func TestBuildStatURLAndBlockedTypes(t *testing.T) {
	cases := []struct{ q, mode, want string }{
		{"a=1&token=secret", QueryModeStrip, "h/p"},
		{"", QueryModeFull, "h/p"},
		{"a=1&token=secret", QueryModeFull, "h/p?a=1&token=secret"},
		{"a=1&flag&token=secret", QueryModeMask, "h/p?a=*&flag&token=*"},
		{"a=1", "", "h/p"},
	}
	for _, tc := range cases {
		if got := BuildStatURL("h", "/p", tc.q, tc.mode); got != tc.want {
			t.Errorf("%q %q: got %q want %q", tc.q, tc.mode, got, tc.want)
		}
	}
	for _, ft := range []string{"blacklist", "waf-blocked", "ratelimit", "client-cert-expired", "captcha-required"} {
		if !IsBlockedForwardType(ft) {
			t.Errorf("%s should be blocked", ft)
		}
	}
	if IsBlockedForwardType("host-http") || IsBlockedForwardType("redirect") {
		t.Error("false positive")
	}
	if !skipURLStat("h.com/a.png?x=1") || skipURLStat("h.com/a.html?x=1") || skipURLStat("h.com") {
		t.Error("skipURLStat")
	}
}

func TestSiteStatsRace(t *testing.T) {
	c := newTestCollector(t, 1000)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				c.RecordRequest(RequestInfo{IpAddr: fmt.Sprintf("1.1.%d.%d", g, i), Succ: i%3 != 0, StatusCode: 200, Site: fmt.Sprintf("s%d", i%5)})
				c.GetSiteList()
				c.GetExportSummary()
			}
		}(g)
	}
	wg.Wait()
	waitTotal(t, c, 1600)
}
