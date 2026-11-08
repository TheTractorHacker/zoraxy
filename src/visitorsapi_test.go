package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/statistic"
	"imuslab.com/zoraxy/mod/visitors"
)

func setupVisitorAPI(t *testing.T) *visitors.Tracker {
	t.Helper()
	tmp := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(tmp, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	oldDB, oldSC, oldVT, oldConf := sysdb, statisticCollector, visitorTracker, CONF_FOLDER
	sysdb, CONF_FOLDER = db, tmp
	sc, err := statistic.NewStatisticCollector(statistic.CollectorOption{Database: db})
	if err != nil {
		t.Fatal(err)
	}
	statisticCollector = sc
	initVisitors()
	tr := visitorTracker
	t.Cleanup(func() {
		tr.Close()
		db.Close()
		sysdb, statisticCollector, visitorTracker, CONF_FOLDER = oldDB, oldSC, oldVT, oldConf
	})
	return tr
}

func vGet(h http.HandlerFunc, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", target, nil))
	return w
}

func vPost(h http.HandlerFunc, target string, form url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h(w, r)
	return w
}

func waitRecorded(tr *visitors.Tracker, n uint64) {
	for i := 0; i < 400 && tr.Stats().Recorded < n; i++ {
		time.Sleep(5 * time.Millisecond)
	}
}

func TestVisitorAPI(t *testing.T) {
	tr := setupVisitorAPI(t)
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "2001:db8::5"} {
		tr.Record(visitors.Event{Time: time.Now(), IP: ip, Host: "a.example", Method: "GET", Path: "/p" + string(rune('0'+i)), UA: "=cmd|calc", Country: "fr", Status: 200, Via: visitors.ViaDirect})
	}
	waitRecorded(tr, 3)

	// list + filter + sort
	var res visitors.ListResult
	w := vGet(HandleVisitorList, "/api/visitors/list?sort=ip&dir=asc&size=2&country=FR")
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || res.Total != 3 || len(res.Items) != 2 || res.Items[0].IP != "198.51.100.1" {
		t.Fatalf("list: %v %s", err, w.Body.String())
	}

	// validation
	for _, bad := range []string{
		"/api/visitors/list?sort=password", "/api/visitors/list?via=evil", "/api/visitors/list?country=FRA",
		"/api/visitors/list?size=100000", "/api/visitors/list?page=-1", "/api/visitors/list?since=abc",
		"/api/visitors/list?host=a%20b%3Cscript%3E", "/api/visitors/recent?after=x", "/api/visitors/recent?limit=0",
		"/api/visitors/detail?ip=not-an-ip", "/api/visitors/export?format=xml", "/api/visitors/export?scope=secrets",
	} {
		h := HandleVisitorList
		switch {
		case strings.Contains(bad, "/recent"):
			h = HandleVisitorRecent
		case strings.Contains(bad, "/detail"):
			h = HandleVisitorDetail
		case strings.Contains(bad, "/export"):
			h = HandleVisitorExport
		}
		if w := vGet(h, bad); !strings.Contains(w.Body.String(), `"error"`) {
			t.Errorf("%s accepted: %s", bad, w.Body.String())
		}
	}

	// detail
	w = vGet(HandleVisitorDetail, "/api/visitors/detail?ip=2001:db8:0:0:0:0:0:5")
	if !strings.Contains(w.Body.String(), `"2001:db8::5"`) {
		t.Fatalf("detail should normalise IPv6: %s", w.Body.String())
	}
	if w := vGet(HandleVisitorDetail, "/api/visitors/detail?ip=203.0.113.1"); !strings.Contains(w.Body.String(), "unknown visitor") {
		t.Fatalf("unknown ip: %s", w.Body.String())
	}

	// recent (live tail by sequence)
	w = vGet(HandleVisitorRecent, "/api/visitors/recent?after=2")
	var rec struct {
		Visits []visitors.Visit
		Seq    uint64
	}
	json.Unmarshal(w.Body.Bytes(), &rec)
	if len(rec.Visits) != 1 || rec.Seq != 3 {
		t.Fatalf("recent after=2: %s", w.Body.String())
	}

	// export: csv with formula injection neutralised, attachment headers
	w = vGet(HandleVisitorExport, "/api/visitors/export?format=csv")
	if !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("export headers: %v", w.Header())
	}
	if strings.Contains(w.Body.String(), ",=cmd") || !strings.Contains(w.Body.String(), "'=cmd|calc") {
		t.Fatalf("csv formula injection: %s", w.Body.String())
	}
	w = vGet(HandleVisitorExport, "/api/visitors/export?scope=visits&format=json")
	if !strings.HasPrefix(strings.TrimSpace(w.Body.String()), "[") {
		t.Fatalf("visits json: %s", w.Body.String())
	}

	// summary
	if w := vGet(HandleVisitorSummary, "/api/visitors/summary"); !strings.Contains(w.Body.String(), `"ips":3`) {
		t.Fatalf("summary: %s", w.Body.String())
	}

	// delete / purge need POST (viewers are blocked from POST by the router) and validate input
	if w := vGet(HandleVisitorDelete, "/api/visitors/delete?ip=198.51.100.1"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("delete via GET: %d", w.Code)
	}
	if w := vPost(HandleVisitorDelete, "/api/visitors/delete", url.Values{"ip": {"junk"}}); !strings.Contains(w.Body.String(), "invalid ip") {
		t.Fatalf("delete junk: %s", w.Body.String())
	}
	if w := vPost(HandleVisitorDelete, "/api/visitors/delete", url.Values{"ip": {"198.51.100.1"}}); !strings.Contains(w.Body.String(), "OK") {
		t.Fatalf("delete: %s", w.Body.String())
	}
	if v, _ := tr.Get("198.51.100.1"); v != nil {
		t.Fatal("not deleted")
	}
	if w := vPost(HandleVisitorPurge, "/api/visitors/purge", url.Values{}); !strings.Contains(w.Body.String(), "confirmation") {
		t.Fatalf("purge without confirm: %s", w.Body.String())
	}
	vPost(HandleVisitorPurge, "/api/visitors/purge", url.Values{"confirm": {"yes"}})
	if tr.Stats().IPs != 0 {
		t.Fatal("purge failed")
	}
}

func TestVisitorSettingsAPI(t *testing.T) {
	tr := setupVisitorAPI(t)
	w := httptest.NewRecorder()
	HandleVisitorSettings(w, httptest.NewRequest("POST", "/api/visitors/settings", strings.NewReader(`{"Enabled":true,"MaxIPs":5,"MaxAgeDays":7,"MaxVisits":300,"KeepQuery":true}`)))
	var out struct{ Settings visitors.Settings }
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Settings.MaxIPs != 100 || out.Settings.MaxAgeDays != 7 || out.Settings.MaxVisits != 300 || !out.Settings.KeepQuery {
		t.Fatalf("settings not clamped/applied: %s", w.Body.String())
	}
	// persisted: a fresh tracker picks them up
	tr.Close()
	initVisitors()
	if s := visitorTracker.Settings(); s.MaxAgeDays != 7 || !s.KeepQuery {
		t.Fatalf("settings not persisted: %+v", s)
	}
	// unknown fields and garbage are refused
	w = httptest.NewRecorder()
	HandleVisitorSettings(w, httptest.NewRequest("POST", "/api/visitors/settings", strings.NewReader(`{"Evil":1}`)))
	if !strings.Contains(w.Body.String(), "invalid JSON") {
		t.Fatalf("unknown field accepted: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	HandleVisitorSettings(w, httptest.NewRequest("DELETE", "/api/visitors/settings", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method: %d", w.Code)
	}
}

// the exclusion list of the statistics page also applies to the visitor list
func TestVisitorHonoursStatisticExclusions(t *testing.T) {
	tr := setupVisitorAPI(t)
	s := statistic.DefaultSettings()
	s.ExcludeNetworks = []string{"192.0.2.0/24"}
	s.ExcludeBlocked = true
	if err := statisticCollector.SetSettings(s); err != nil {
		t.Fatal(err)
	}
	ev := func(ip string, blocked bool) visitors.Event {
		return visitors.Event{Time: time.Now(), IP: ip, Host: "a", Path: "/", Status: 200, Blocked: blocked}
	}
	tr.Record(ev("192.0.2.9", false))   // excluded network
	tr.Record(ev("198.51.100.9", true)) // blocked while "exclude blocked" is on
	tr.Record(ev("198.51.100.10", false))
	waitRecorded(tr, 1)
	time.Sleep(40 * time.Millisecond)
	if st := tr.Stats(); st.IPs != 1 {
		t.Fatalf("expected only 198.51.100.10, got %d IPs", st.IPs)
	}
}
