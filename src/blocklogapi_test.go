package main

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/statistic"
)

func setupBlockAPI(t *testing.T) *blocklog.Log {
	t.Helper()
	tmp := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(tmp, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	oldDB, oldSC, oldBL, oldConf := sysdb, statisticCollector, blockLog, CONF_FOLDER
	sysdb, CONF_FOLDER = db, tmp
	sc, err := statistic.NewStatisticCollector(statistic.CollectorOption{Database: db})
	if err != nil {
		t.Fatal(err)
	}
	statisticCollector = sc
	initBlockLog()
	bl := blockLog
	t.Cleanup(func() {
		bl.Close()
		db.Close()
		sysdb, statisticCollector, blockLog, CONF_FOLDER = oldDB, oldSC, oldBL, oldConf
	})
	return bl
}

func TestBlockedAPI(t *testing.T) {
	bl := setupBlockAPI(t)
	bl.Record(blocklog.Entry{IP: "198.51.100.1", Host: "a.test", Method: "GET", Path: "/wp-login.php", Status: 403, Reason: blocklog.ReasonWAF, Detail: "942100 SQLi [tx 1]"})
	bl.Record(blocklog.Entry{IP: "198.51.100.1", Host: "a.test", Method: "GET", Path: "/x", Status: 429, Reason: blocklog.ReasonRateLimit})
	bl.Record(blocklog.Entry{IP: "198.51.100.2", Host: "b.test", Method: "POST", Path: "/", Status: 403, Reason: blocklog.ReasonBlacklist})

	var ov struct {
		Summary struct {
			Total      int                   `json:"total"`
			Reasons    []blocklog.Count      `json:"reasons"`
			TopIPs     []blocklog.Count      `json:"topIPs"`
			ReasonInfo []blocklog.ReasonInfo `json:"reasonInfo"`
		}
		List blocklog.ListResult
	}
	w := vGet(HandleBlockedOverview, "/api/blocked/overview?host=a.test")
	if err := json.Unmarshal(w.Body.Bytes(), &ov); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	if ov.Summary.Total != 2 || len(ov.List.Items) != 2 || ov.List.Items[0].Reason != blocklog.ReasonRateLimit {
		t.Errorf("host filter: %s", w.Body.String())
	}
	if len(ov.Summary.ReasonInfo) < 10 || ov.Summary.TopIPs[0].Key != "198.51.100.1" {
		t.Errorf("summary: %s", w.Body.String())
	}
	if w := vGet(HandleBlockedList, "/api/blocked/list?reason=blacklist&ip=198.51.100.2"); !strings.Contains(w.Body.String(), `"total":1`) {
		t.Errorf("list: %s", w.Body.String())
	}
	if w := vGet(HandleBlockedSummary, "/api/blocked/summary?q=wp-login"); !strings.Contains(w.Body.String(), `"total":1`) {
		t.Errorf("summary search: %s", w.Body.String())
	}
	for _, bad := range []string{"reason=bogus", "ip=nope", "host=a%20b", "since=-1", "limit=0", "limit=9999", "before=x"} {
		if w := vGet(HandleBlockedList, "/api/blocked/list?"+bad); !strings.Contains(w.Body.String(), `"error"`) {
			t.Errorf("%s accepted: %s", bad, w.Body.String())
		}
	}

	// settings persist, clear needs confirmation
	w = vGet(HandleBlockedSettings, "/api/blocked/settings")
	if !strings.Contains(w.Body.String(), `"Enabled":true`) {
		t.Errorf("settings: %s", w.Body.String())
	}
	if w := vPost(HandleBlockedClear, "/api/blocked/clear", url.Values{}); !strings.Contains(w.Body.String(), "confirmation") {
		t.Errorf("clear without confirm: %s", w.Body.String())
	}
	if w := vPost(HandleBlockedClear, "/api/blocked/clear", url.Values{"confirm": {"yes"}}); !strings.Contains(w.Body.String(), "OK") {
		t.Errorf("clear: %s", w.Body.String())
	}
	if w := vGet(HandleBlockedList, "/api/blocked/list"); !strings.Contains(w.Body.String(), `"total":0`) {
		t.Errorf("after clear: %s", w.Body.String())
	}
}
