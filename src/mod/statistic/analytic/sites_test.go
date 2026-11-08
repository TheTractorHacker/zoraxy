package analytic

import (
	"testing"

	"imuslab.com/zoraxy/mod/statistic"
)

func day(total int64, sites map[string]*statistic.SiteSummaryExport) *statistic.DailySummaryExport {
	return &statistic.DailySummaryExport{
		TotalRequest: total, ForwardTypes: map[string]int{}, RequestOrigin: map[string]int{}, RequestClientIp: map[string]int{},
		Referer: map[string]int{}, UserAgent: map[string]int{}, RequestURL: map[string]int{}, RequestMethods: map[string]int{},
		Downstreams: map[string]int{}, Upstreams: map[string]int{}, Sites: sites,
	}
}

func site(total, errs int64, ips ...string) *statistic.SiteSummaryExport {
	s := &statistic.SiteSummaryExport{TotalRequest: total, ErrorRequest: errs, RequestClientIp: map[string]int{}, StatusCodes: map[string]int{"200": int(total - errs)}}
	for _, ip := range ips {
		s.RequestClientIp[ip] = 1
	}
	return s
}

func TestMergeKeepsSitesAndStatusCodes(t *testing.T) {
	d1 := day(10, map[string]*statistic.SiteSummaryExport{"a": site(10, 1, "1.1.1.1")})
	d2 := day(7, map[string]*statistic.SiteSummaryExport{"a": site(5, 0, "2.2.2.2"), "b": site(2, 2, "3.3.3.3")})
	d1.StatusCodes = map[string]int{"200": 9}
	d2.StatusCodes = map[string]int{"200": 5, "502": 2}
	m := mergeDailySummaryExports([]*statistic.DailySummaryExport{d1, d2})
	if m.TotalRequest != 17 || m.Sites["a"].TotalRequest != 15 || m.Sites["b"].ErrorRequest != 2 || m.StatusCodes["200"] != 14 || m.StatusCodes["502"] != 2 {
		t.Fatalf("%+v", m)
	}
	if len(m.Sites["a"].RequestClientIp) != 2 {
		t.Fatal("client IPs not merged")
	}
}

func TestSiteViewAndRows(t *testing.T) {
	d1 := day(10, map[string]*statistic.SiteSummaryExport{"a": site(10, 1, "1.1.1.1"), "b": site(3, 0, "9.9.9.9")})
	d2 := day(5, map[string]*statistic.SiteSummaryExport{"a": site(5, 0, "1.1.1.1", "2.2.2.2")})
	v := siteView(d1, "a")
	if v.TotalRequest != 10 || v.ErrorRequest != 1 || v.RequestClientIp["1.1.1.1"] != 1 {
		t.Fatalf("view: %+v", v)
	}
	if e := siteView(d1, "nope"); e.TotalRequest != 0 || e.RequestURL == nil {
		t.Fatalf("unknown site must give an empty, non-nil summary: %+v", e)
	}
	if e := siteView(nil, "a"); e.TotalRequest != 0 {
		t.Fatal("nil day")
	}
	res := BuildSiteRows([]*statistic.DailySummaryExport{d1, d2}, []string{"2026_01_01", "2026_01_02"}, nil)
	if len(res.Sites) != 2 || res.Sites[0].Site != "a" || res.Sites[0].Total != 15 || res.Sites[0].Visitors != 2 ||
		res.Sites[0].PerDay[0] != 10 || res.Sites[0].PerDay[1] != 5 || res.Sites[1].PerDay[1] != 0 {
		t.Fatalf("%+v", res)
	}
}
