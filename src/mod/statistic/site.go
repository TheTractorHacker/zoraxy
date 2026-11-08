package statistic

import (
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

/*
	Per-site statistics

	Every proxy rule (keyed by its configured RootOrMatchingDomain, never by the
	raw Host header, so a client can not create new keys) gets a compact
	SiteSummary next to the global DailySummary. The cardinality is bounded twice:

	  - at most MaxSites distinct sites per day; further keys fold into OtherSiteKey
	  - every per-site map is soft-capped (see siteMapCap) with the same
	    "drop the lowest counts" strategy as the global maps
*/

const (
	// MaxSites is the maximum number of distinct sites tracked per day.
	MaxSites = 128
	// OtherSiteKey collects the traffic of sites past MaxSites.
	OtherSiteKey = "_other"
	// defaultSiteMapCap is the per-site, per-dimension cap used when the
	// collector is unbounded (-stats_max_entries=0).
	defaultSiteMapCap = 1000
	minSiteMapCap     = 100
)

// siteMapCap derives the per-site, per-dimension cap from the global cap
func siteMapCap(globalCap int) int {
	if globalCap <= 0 {
		return defaultSiteMapCap
	}
	c := globalCap / 8
	if c < minSiteMapCap {
		c = minSiteMapCap
	}
	return c
}

// SiteSummary is the live (concurrent) per-site counter set of one day
type SiteSummary struct {
	Total   int64
	Error   int64
	Blocked int64
	Hourly  [24]int64 //requests per hour of the (local) day
	HourlyE [24]int64 //error requests per hour

	StatusCodes    *sync.Map
	RequestOrigin  *sync.Map
	RequestClient  *sync.Map
	Referer        *sync.Map
	UserAgent      *sync.Map
	RequestURL     *sync.Map
	RequestMethods *sync.Map

	bounded [7]*boundedCounter
}

// SiteSummaryExport is the persisted / API form of SiteSummary
type SiteSummaryExport struct {
	TotalRequest   int64
	ErrorRequest   int64
	ValidRequest   int64
	BlockedRequest int64
	Hourly         []int64 `json:",omitempty"`
	HourlyErrors   []int64 `json:",omitempty"`

	StatusCodes     map[string]int
	RequestOrigin   map[string]int
	RequestClientIp map[string]int
	Referer         map[string]int
	UserAgent       map[string]int
	RequestURL      map[string]int
	RequestMethods  map[string]int
}

func newSiteSummary() *SiteSummary {
	s := &SiteSummary{
		StatusCodes:    &sync.Map{},
		RequestOrigin:  &sync.Map{},
		RequestClient:  &sync.Map{},
		Referer:        &sync.Map{},
		UserAgent:      &sync.Map{},
		RequestURL:     &sync.Map{},
		RequestMethods: &sync.Map{},
	}
	for i := range s.bounded {
		s.bounded[i] = newBoundedCounter(0)
	}
	return s
}

func (s *SiteSummary) maps() [7]*sync.Map {
	return [7]*sync.Map{s.StatusCodes, s.RequestOrigin, s.RequestClient, s.Referer, s.UserAgent, s.RequestURL, s.RequestMethods}
}

// siteTable holds the per-site summaries of one DailySummary
type siteTable struct {
	m     sync.Map     // site key -> *SiteSummary
	count atomic.Int32 // number of keys in m
}

// get returns (creating on demand) the SiteSummary for key, folding into
// OtherSiteKey once MaxSites distinct sites exist.
func (t *siteTable) get(key string) *SiteSummary {
	if v, ok := t.m.Load(key); ok {
		return v.(*SiteSummary)
	}
	if key != OtherSiteKey && int(t.count.Load()) >= MaxSites-1 {
		return t.get(OtherSiteKey)
	}
	v, loaded := t.m.LoadOrStore(key, newSiteSummary())
	if !loaded {
		t.count.Add(1)
	}
	return v.(*SiteSummary)
}

// recordSite applies one request to the per-site table of ds
func (c *Collector) recordSite(ds *DailySummary, ri *RequestInfo, clientIP string, countryISO string, referer string, now time.Time) {
	if ri.Site == "" || ds.sites == nil {
		return
	}
	s := ds.sites.get(truncateStatKey(ri.Site))
	atomic.AddInt64(&s.Total, 1)
	h := now.Hour()
	atomic.AddInt64(&s.Hourly[h], 1)
	if !ri.Succ {
		atomic.AddInt64(&s.Error, 1)
		atomic.AddInt64(&s.HourlyE[h], 1)
	}
	if ri.Blocked {
		atomic.AddInt64(&s.Blocked, 1)
	}
	capN := siteMapCap(c.Option.MaxEntriesPerStatMap)
	inc := func(i int, m *sync.Map, key string) {
		boundedIncr(m, s.bounded[i], key, capN)
	}
	if ri.StatusCode > 0 {
		inc(0, s.StatusCodes, strconv.Itoa(ri.StatusCode))
	}
	inc(1, s.RequestOrigin, countryISO)
	inc(2, s.RequestClient, clientIP)
	inc(3, s.Referer, truncateStatKey(referer))
	inc(4, s.UserAgent, truncateStatKey(ri.UserAgent))
	if ri.RequestMethod != "" {
		inc(6, s.RequestMethods, ri.RequestMethod)
	}
	if !skipURLStat(ri.RequestURL) {
		inc(5, s.RequestURL, truncateStatKey(ri.RequestURL))
	}
}

func (s *SiteSummary) export() *SiteSummaryExport {
	e := &SiteSummaryExport{
		TotalRequest:    atomic.LoadInt64(&s.Total),
		ErrorRequest:    atomic.LoadInt64(&s.Error),
		BlockedRequest:  atomic.LoadInt64(&s.Blocked),
		Hourly:          make([]int64, 24),
		HourlyErrors:    make([]int64, 24),
		StatusCodes:     SyncMapToMapStringInt(s.StatusCodes),
		RequestOrigin:   SyncMapToMapStringInt(s.RequestOrigin),
		RequestClientIp: SyncMapToMapStringInt(s.RequestClient),
		Referer:         SyncMapToMapStringInt(s.Referer),
		UserAgent:       SyncMapToMapStringInt(s.UserAgent),
		RequestURL:      SyncMapToMapStringInt(s.RequestURL),
		RequestMethods:  SyncMapToMapStringInt(s.RequestMethods),
	}
	e.ValidRequest = e.TotalRequest - e.ErrorRequest
	for i := 0; i < 24; i++ {
		e.Hourly[i] = atomic.LoadInt64(&s.Hourly[i])
		e.HourlyErrors[i] = atomic.LoadInt64(&s.HourlyE[i])
	}
	return e
}

func siteSummaryFromExport(e *SiteSummaryExport) *SiteSummary {
	s := newSiteSummary()
	if e == nil {
		return s
	}
	s.Total, s.Error, s.Blocked = e.TotalRequest, e.ErrorRequest, e.BlockedRequest
	for i := 0; i < 24 && i < len(e.Hourly); i++ {
		s.Hourly[i] = e.Hourly[i]
	}
	for i := 0; i < 24 && i < len(e.HourlyErrors); i++ {
		s.HourlyE[i] = e.HourlyErrors[i]
	}
	src := [7]map[string]int{e.StatusCodes, e.RequestOrigin, e.RequestClientIp, e.Referer, e.UserAgent, e.RequestURL, e.RequestMethods}
	dst := s.maps()
	for i := range src {
		for k, v := range src[i] {
			dst[i].Store(k, v)
		}
		s.bounded[i] = newBoundedCounter(len(src[i]))
	}
	return s
}

func (t *siteTable) export() map[string]*SiteSummaryExport {
	out := map[string]*SiteSummaryExport{}
	if t == nil {
		return out
	}
	t.m.Range(func(k, v interface{}) bool {
		out[k.(string)] = v.(*SiteSummary).export()
		return true
	})
	return out
}

func siteTableFromExport(m map[string]*SiteSummaryExport) *siteTable {
	t := &siteTable{}
	for k, v := range m {
		t.m.Store(k, siteSummaryFromExport(v))
		t.count.Add(1)
	}
	return t
}

// AsDailySummaryExport converts a site export to the global export shape so
// that consumers (the stats page) can render a single site with the code that
// renders the whole proxy. Dimensions that are not tracked per site stay empty.
func (e *SiteSummaryExport) AsDailySummaryExport() *DailySummaryExport {
	if e == nil {
		return &DailySummaryExport{
			ForwardTypes: map[string]int{}, RequestOrigin: map[string]int{}, RequestClientIp: map[string]int{},
			Referer: map[string]int{}, UserAgent: map[string]int{}, RequestURL: map[string]int{},
			RequestMethods: map[string]int{}, StatusCodes: map[string]int{}, Downstreams: map[string]int{}, Upstreams: map[string]int{},
		}
	}
	return &DailySummaryExport{
		TotalRequest:    e.TotalRequest,
		ErrorRequest:    e.ErrorRequest,
		ValidRequest:    e.ValidRequest,
		BlockedRequest:  e.BlockedRequest,
		ForwardTypes:    map[string]int{},
		RequestOrigin:   nz(e.RequestOrigin),
		RequestClientIp: nz(e.RequestClientIp),
		Referer:         nz(e.Referer),
		UserAgent:       nz(e.UserAgent),
		RequestURL:      nz(e.RequestURL),
		RequestMethods:  nz(e.RequestMethods),
		StatusCodes:     nz(e.StatusCodes),
		Downstreams:     map[string]int{},
		Upstreams:       map[string]int{},
	}
}

func nz(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

// Merge adds o into e (used to merge several days)
func (e *SiteSummaryExport) Merge(o *SiteSummaryExport) {
	if o == nil {
		return
	}
	e.TotalRequest += o.TotalRequest
	e.ErrorRequest += o.ErrorRequest
	e.ValidRequest += o.ValidRequest
	e.BlockedRequest += o.BlockedRequest
	for _, p := range []struct {
		d *map[string]int
		s map[string]int
	}{
		{&e.StatusCodes, o.StatusCodes}, {&e.RequestOrigin, o.RequestOrigin},
		{&e.RequestClientIp, o.RequestClientIp}, {&e.Referer, o.Referer},
		{&e.UserAgent, o.UserAgent}, {&e.RequestURL, o.RequestURL},
		{&e.RequestMethods, o.RequestMethods},
	} {
		if *p.d == nil {
			*p.d = map[string]int{}
		}
		for k, v := range p.s {
			(*p.d)[k] += v
		}
	}
}

// SiteListEntry is one row of the per-site overview table
type SiteListEntry struct {
	Site     string
	Total    int64
	Errors   int64
	Blocked  int64
	Visitors int
	Hourly   []int64
}

// GetSiteList returns the per-site overview of today, busiest first
func (c *Collector) GetSiteList() []SiteListEntry {
	ds := c.GetCurrentDailySummary()
	list := []SiteListEntry{}
	if ds == nil {
		return list
	}
	if ds.sites == nil {
		return list
	}
	ds.sites.m.Range(func(k, v interface{}) bool {
		s := v.(*SiteSummary)
		n := 0
		s.RequestClient.Range(func(_, _ interface{}) bool { n++; return true })
		h := make([]int64, 24)
		for i := range h {
			h[i] = atomic.LoadInt64(&s.Hourly[i])
		}
		list = append(list, SiteListEntry{
			Site: k.(string), Total: atomic.LoadInt64(&s.Total), Errors: atomic.LoadInt64(&s.Error),
			Blocked: atomic.LoadInt64(&s.Blocked), Visitors: n, Hourly: h,
		})
		return true
	})
	sort.Slice(list, func(i, j int) bool {
		if list[i].Total != list[j].Total {
			return list[i].Total > list[j].Total
		}
		return list[i].Site < list[j].Site
	})
	return list
}

// GetSiteExport returns the export of one site of today (nil if unknown)
func (c *Collector) GetSiteExport(site string) *SiteSummaryExport {
	ds := c.GetCurrentDailySummary()
	if ds == nil {
		return nil
	}
	if ds.sites == nil {
		return nil
	}
	if v, ok := ds.sites.m.Load(site); ok {
		return v.(*SiteSummary).export()
	}
	return nil
}
