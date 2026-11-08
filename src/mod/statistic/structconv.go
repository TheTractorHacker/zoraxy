package statistic

import (
	"sync"
	"sync/atomic"
)

type DailySummaryExport struct {
	TotalRequest   int64 //Total request of the day
	ErrorRequest   int64 //Invalid request of the day, including error or not found
	ValidRequest   int64 //Valid request of the day
	BlockedRequest int64 `json:",omitempty"` //Requests rejected by Zoraxy itself

	ForwardTypes    map[string]int
	RequestOrigin   map[string]int
	RequestClientIp map[string]int
	Referer         map[string]int
	UserAgent       map[string]int
	RequestURL      map[string]int
	RequestMethods  map[string]int
	Downstreams     map[string]int
	Upstreams       map[string]int
	StatusCodes     map[string]int `json:",omitempty"` //HTTP status code of the responses

	// Sites holds the per-site (per proxy rule) summaries, see site.go
	Sites map[string]*SiteSummaryExport `json:",omitempty"`
}

func SyncMapToMapStringInt(syncMap *sync.Map) map[string]int {
	result := make(map[string]int)
	syncMap.Range(func(key, value interface{}) bool {
		strKey, okKey := key.(string)
		intValue, okValue := value.(int)
		if okKey && okValue {
			result[strKey] = intValue
		}
		return true
	})
	return result
}

func DailySummaryToExport(summary DailySummary) DailySummaryExport {
	return dailySummaryToExport(&summary)
}

// dailySummaryToExport converts a live summary, reading the counters atomically
func dailySummaryToExport(summary *DailySummary) DailySummaryExport {
	export := DailySummaryExport{
		TotalRequest:    atomic.LoadInt64(&summary.TotalRequest),
		ErrorRequest:    atomic.LoadInt64(&summary.ErrorRequest),
		ValidRequest:    atomic.LoadInt64(&summary.ValidRequest),
		BlockedRequest:  atomic.LoadInt64(&summary.BlockedRequest),
		ForwardTypes:    make(map[string]int),
		RequestOrigin:   make(map[string]int),
		RequestClientIp: make(map[string]int),
		Referer:         make(map[string]int),
		UserAgent:       make(map[string]int),
		RequestURL:      make(map[string]int),
		RequestMethods:  make(map[string]int),
		Downstreams:     make(map[string]int),
		Upstreams:       make(map[string]int),
	}

	export.ForwardTypes = SyncMapToMapStringInt(summary.ForwardTypes)
	export.RequestOrigin = SyncMapToMapStringInt(summary.RequestOrigin)
	export.RequestClientIp = SyncMapToMapStringInt(summary.RequestClientIp)
	export.Referer = SyncMapToMapStringInt(summary.Referer)
	export.UserAgent = SyncMapToMapStringInt(summary.UserAgent)
	export.RequestURL = SyncMapToMapStringInt(summary.RequestURL)
	export.RequestMethods = SyncMapToMapStringInt(summary.RequestMethods)
	export.Downstreams = SyncMapToMapStringInt(summary.DownstreamHostnames)
	export.Upstreams = SyncMapToMapStringInt(summary.UpstreamHostnames)
	if summary.StatusCodes != nil {
		export.StatusCodes = SyncMapToMapStringInt(summary.StatusCodes)
	}
	export.Sites = summary.sites.export()
	if len(export.Sites) == 0 {
		export.Sites = nil
	}

	return export
}

func MapStringIntToSyncMap(m map[string]int) *sync.Map {
	syncMap := &sync.Map{}
	for k, v := range m {
		syncMap.Store(k, v)
	}
	return syncMap
}

func DailySummaryExportToSummary(export DailySummaryExport) DailySummary {
	summary := DailySummary{
		TotalRequest:        export.TotalRequest,
		ErrorRequest:        export.ErrorRequest,
		ValidRequest:        export.ValidRequest,
		BlockedRequest:      export.BlockedRequest,
		ForwardTypes:        MapStringIntToSyncMap(export.ForwardTypes),
		RequestOrigin:       MapStringIntToSyncMap(export.RequestOrigin),
		RequestClientIp:     MapStringIntToSyncMap(export.RequestClientIp),
		Referer:             MapStringIntToSyncMap(export.Referer),
		UserAgent:           MapStringIntToSyncMap(export.UserAgent),
		RequestURL:          MapStringIntToSyncMap(export.RequestURL),
		RequestMethods:      MapStringIntToSyncMap(export.RequestMethods),
		DownstreamHostnames: MapStringIntToSyncMap(export.Downstreams),
		UpstreamHostnames:   MapStringIntToSyncMap(export.Upstreams),
		StatusCodes:         MapStringIntToSyncMap(export.StatusCodes),
		sites:               siteTableFromExport(export.Sites),
		bounded: boundedCounters{
			ForwardTypes:        newBoundedCounter(len(export.ForwardTypes)),
			RequestOrigin:       newBoundedCounter(len(export.RequestOrigin)),
			RequestClientIp:     newBoundedCounter(len(export.RequestClientIp)),
			Referer:             newBoundedCounter(len(export.Referer)),
			UserAgent:           newBoundedCounter(len(export.UserAgent)),
			RequestURL:          newBoundedCounter(len(export.RequestURL)),
			RequestMethods:      newBoundedCounter(len(export.RequestMethods)),
			DownstreamHostnames: newBoundedCounter(len(export.Downstreams)),
			UpstreamHostnames:   newBoundedCounter(len(export.Upstreams)),
			StatusCodes:         newBoundedCounter(len(export.StatusCodes)),
		},
	}

	return summary
}

// External object function call
func (c *Collector) GetExportSummary() *DailySummaryExport {
	exportFormatDailySummary := dailySummaryToExport(c.GetCurrentDailySummary())
	return &exportFormatDailySummary
}
