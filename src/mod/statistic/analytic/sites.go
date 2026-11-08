package analytic

import (
	"encoding/json"
	"net/http"
	"sort"

	"imuslab.com/zoraxy/mod/statistic"
	"imuslab.com/zoraxy/mod/utils"
)

// siteView reduces a day summary to the numbers of one site, in the shape of a
// whole-proxy summary so the stats page can render it unchanged. A site that has
// no data that day yields an empty summary.
func siteView(day *statistic.DailySummaryExport, site string) *statistic.DailySummaryExport {
	if day == nil {
		return (*statistic.SiteSummaryExport)(nil).AsDailySummaryExport()
	}
	return day.Sites[site].AsDailySummaryExport()
}

// SiteRow is one line of the per-site comparison table
type SiteRow struct {
	Site     string
	Total    int64
	Errors   int64
	Blocked  int64
	Visitors int
	PerDay   []int64 //requests per day in the range (sparkline), oldest first
	Hourly   []int64 //requests per hour of today (only when the range includes today)
}

// SitesResult is the response of HandleSiteList
type SitesResult struct {
	Dates []string
	Sites []SiteRow
}

// BuildSiteRows aggregates the per-site data of the given days (dates in the same order)
func BuildSiteRows(days []*statistic.DailySummaryExport, dates []string, today *statistic.Collector) SitesResult {
	rows := map[string]*SiteRow{}
	visitors := map[string]map[string]bool{}
	for di, day := range days {
		for site, se := range day.Sites {
			r := rows[site]
			if r == nil {
				r = &SiteRow{Site: site, PerDay: make([]int64, len(days))}
				rows[site] = r
				visitors[site] = map[string]bool{}
			}
			r.Total += se.TotalRequest
			r.Errors += se.ErrorRequest
			r.Blocked += se.BlockedRequest
			r.PerDay[di] = se.TotalRequest
			for ip := range se.RequestClientIp {
				visitors[site][ip] = true
			}
		}
	}
	out := SitesResult{Dates: dates, Sites: []SiteRow{}}
	for site, r := range rows {
		r.Visitors = len(visitors[site])
		out.Sites = append(out.Sites, *r)
	}
	sort.Slice(out.Sites, func(i, j int) bool {
		if out.Sites[i].Total != out.Sites[j].Total {
			return out.Sites[i].Total > out.Sites[j].Total
		}
		return out.Sites[i].Site < out.Sites[j].Site
	})
	if today != nil {
		hourly := map[string][]int64{}
		for _, e := range today.GetSiteList() {
			hourly[e.Site] = e.Hourly
		}
		for i := range out.Sites {
			out.Sites[i].Hourly = hourly[out.Sites[i].Site]
		}
	}
	return out
}

// HandleSiteList serves GET /api/analytic/sites?start=&end= : the per-site
// comparison table (totals, errors, blocked, visitors, daily sparkline). Without
// start/end only today is returned.
func (d *DataLoader) HandleSiteList(w http.ResponseWriter, r *http.Request) {
	var days []*statistic.DailySummaryExport
	var dates []string
	start, end, err := d.GetStartAndEndDatesFromRequest(r)
	if err != nil {
		today := d.StatisticCollector.GetExportSummary()
		days = []*statistic.DailySummaryExport{today}
		dates = []string{"today"}
	} else {
		days, dates, err = d.GetAllStatisticSummaryInRange(start, end)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		//today lives in memory and may be newer than the persisted copy
		for i, k := range dates {
			if isTodayDate(k) {
				days[i] = d.StatisticCollector.GetExportSummary()
			}
		}
	}
	res := BuildSiteRows(days, dates, d.StatisticCollector)
	js, _ := json.Marshal(res)
	utils.SendJSONResponse(w, string(js))
}
