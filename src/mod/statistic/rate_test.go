package statistic

import (
	"testing"
	"time"
)

func TestRateRingWindowAndWraparound(t *testing.T) {
	var r rateRing
	base := time.Unix(60*1000000, 0) // minute-aligned
	// 10 requests in each of the 5 minutes before "now", 2 errors and 1 blocked per minute
	for m := 1; m <= 5; m++ {
		at := base.Add(-time.Duration(m) * time.Minute)
		for i := 0; i < 10; i++ {
			r.add(at, i < 2, i == 0)
		}
	}
	r.add(base, false, false) // the running minute is not part of the average
	got := r.recent(base, 5)
	if got.RequestsPerMin != 10 || got.ErrorsPerMin != 2 || got.BlockedPerMin != 1 || got.ErrorRate < 0.199 || got.ErrorRate > 0.201 {
		t.Fatalf("%+v", got)
	}
	if got.Series[29] != 1 || got.Series[28] != 10 || got.Series[24] != 10 || got.Series[23] != 0 {
		t.Fatalf("series: %v", got.Series)
	}
	// an hour later every bucket is stale
	if later := r.recent(base.Add(61*time.Minute), 5); later.RequestsPerMin != 0 {
		t.Fatalf("stale buckets counted: %+v", later)
	}
	// wrap-around reuse resets the bucket
	r.add(base.Add(time.Hour), false, false)
	if x := r.recent(base.Add(time.Hour+time.Minute), 1); x.RequestsPerMin != 1 {
		t.Fatalf("wraparound: %+v", x)
	}
	if r.recent(base, 0).Minutes != 1 || r.recent(base, 99).Minutes != 30 {
		t.Fatal("window clamp")
	}
}

func TestRecordRequestFeedsRates(t *testing.T) {
	c := newTestCollector(t, 100)
	// the running minute is excluded from the average, so use the series
	c.RecordRequest(RequestInfo{IpAddr: "1.1.1.1", Succ: true})
	c.RecordRequest(RequestInfo{IpAddr: "1.1.1.1", Succ: false, Blocked: true})
	c.SetSettings(Settings{ExcludeNetworks: []string{"9.9.9.9"}})
	c.RecordRequest(RequestInfo{IpAddr: "9.9.9.9", Succ: true}) // excluded: not counted
	s := c.RecentRates(5).Series
	if s[28]+s[29] != 2 {
		t.Fatalf("series tail = %d", s[28]+s[29])
	}
}
