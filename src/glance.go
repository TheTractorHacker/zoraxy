package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/notify"
	"imuslab.com/zoraxy/mod/statistic"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	glance.go

	GET /api/stats/glance: the compact overview shown at the top of the Status page.
	Everything comes from data that already exists in memory (rate ring, uptime log,
	delivery log); the certificate expiries are re-read from disk at most every 10 minutes.
*/

type glanceCertCache struct {
	mu   sync.Mutex
	at   time.Time
	list []notify.CertExpiry
}

var glanceCerts glanceCertCache

func (c *glanceCertCache) get() []notify.CertExpiry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) > 10*time.Minute {
		c.list = notify.ScanCertExpiry(CONF_CERT_STORE)
		c.at = time.Now()
	}
	return c.list
}

type glanceDown struct {
	Name       string
	URL        string
	StatusCode int
}

type glanceCert struct {
	Name     string
	DaysLeft int
}

// glanceUp is one monitored upstream for the health list of the Status page
type glanceUp struct {
	Name       string
	URL        string
	Online     bool
	StatusCode int
	LatencyMs  int64
}

// glanceCertExp is one certificate for the expiry list (soonest first)
type glanceCertExp struct {
	Name     string
	DaysLeft int
	NotAfter int64
}

type GlanceData struct {
	Upstreams      []glanceUp      // every monitored upstream (down ones first, max 40)
	CertList       []glanceCertExp // the certificates that expire first (max 8)
	Rates          statistic.Rates
	BandwidthRx    int64
	BandwidthTx    int64
	BlockedToday   int64
	UpstreamsTotal int
	UpstreamsDown  []glanceDown
	CertsTotal     int
	CertsExpiring  []glanceCert // within 30 days, soonest first (max 5)
	AlertsFailed   int          // failed notification deliveries still in the log
	AlertsRecent   []notify.DeliveryRecord
	WarnDays       int
}

func buildGlance(now time.Time) GlanceData {
	g := GlanceData{Upstreams: []glanceUp{}, CertList: []glanceCertExp{}, UpstreamsDown: []glanceDown{}, CertsExpiring: []glanceCert{}, AlertsRecent: []notify.DeliveryRecord{}, WarnDays: 30}
	if statisticCollector != nil {
		g.Rates = statisticCollector.RecentRates(5)
		g.BlockedToday = statisticCollector.GetExportSummaryBlocked()
	}
	g.BandwidthRx, g.BandwidthTx = getBandwidthToday()

	if uptimeMonitor != nil {
		for _, rec := range uptimeMonitor.LatestRecords() {
			g.UpstreamsTotal++
			if len(g.Upstreams) < 40 {
				g.Upstreams = append(g.Upstreams, glanceUp{rec.Name, rec.URL, rec.Online, rec.StatusCode, rec.Latency})
			}
			if !rec.Online && len(g.UpstreamsDown) < 10 {
				g.UpstreamsDown = append(g.UpstreamsDown, glanceDown{rec.Name, rec.URL, rec.StatusCode})
			}
		}
	}

	certs := glanceCerts.get()
	g.CertsTotal = len(certs)
	sort.SliceStable(g.Upstreams, func(i, j int) bool { return !g.Upstreams[i].Online && g.Upstreams[j].Online })
	for i, c := range certs {
		if i >= 8 {
			break
		}
		g.CertList = append(g.CertList, glanceCertExp{c.Name, int(c.NotAfter.Sub(now).Hours() / 24), c.NotAfter.Unix()})
	}
	for _, c := range certs {
		days := int(c.NotAfter.Sub(now).Hours() / 24)
		if days > g.WarnDays || len(g.CertsExpiring) >= 5 {
			break
		}
		g.CertsExpiring = append(g.CertsExpiring, glanceCert{c.Name, days})
	}

	if notifyManager != nil {
		for _, r := range notifyManager.Deliveries() {
			if r.Status == "failed" {
				g.AlertsFailed++
			}
			if (r.Status == "sent" || r.Status == "failed") && len(g.AlertsRecent) < 5 {
				g.AlertsRecent = append(g.AlertsRecent, r)
			}
		}
	}
	return g
}

func HandleDashboardGlance(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(buildGlance(time.Now()))
	utils.SendJSONResponse(w, string(js))
}
