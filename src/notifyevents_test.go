package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/notify"
	"imuslab.com/zoraxy/mod/statistic"
)

func setupNotifyGlueTest(t *testing.T) (events func() []string) {
	t.Helper()
	tmp := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(tmp, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	oldDB, oldMgr, oldLog := sysdb, notifyManager, SystemWideLogger
	sysdb = db
	sysdb.NewTable(knownIPTable)
	lg, _ := logger.NewFmtLogger()
	SystemWideLogger = lg
	// a command-less manager whose events we observe through a local channel sink
	mgr, err := notify.NewManager(filepath.Join(tmp, "notify.json"), false, nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	notifyManager = mgr
	t.Cleanup(func() { sysdb, notifyManager, SystemWideLogger = oldDB, oldMgr, oldLog })
	return func() []string {
		mgr.Dispatcher.Wait()
		out := []string{}
		for _, d := range mgr.Deliveries() {
			out = append(out, d.Event+"|"+d.Subject+"|"+d.Status)
		}
		return out
	}
}

func recv(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

func loginReq(user, ip string) *http.Request {
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(url.Values{"username": {user}, "password": {"x"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ip + ":4000"
	return r
}

func TestLoginNotificationsFailureAndNewIP(t *testing.T) {
	events := setupNotifyGlueTest(t)
	// subscribe a recording webhook-less channel: use a local ntfy that refuses (we only read the delivery log)
	if _, err := notifyManager.SaveChannel(notify.ChannelConfig{Name: "rec", Type: notify.ChanNtfy, Enabled: true, AllowPrivate: true,
		Settings: map[string]string{"server": recv(t), "topic": "t"}}); err != nil {
		t.Fatal(err)
	}
	ok := notifyLoginWrap(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`"ok"`)) })
	bad := notifyLoginWrap(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"error":"Invalid username or password"}`)) })

	ok(httptest.NewRecorder(), loginReq("admin", "198.51.100.1")) // learning: silent
	ok(httptest.NewRecorder(), loginReq("admin", "198.51.100.1")) // known: silent
	ok(httptest.NewRecorder(), loginReq("admin", "203.0.113.9"))  // new address
	bad(httptest.NewRecorder(), loginReq("admin", "203.0.113.50"))
	deadline := time.Now().Add(5 * time.Second)
	var got []string
	for time.Now().Before(deadline) {
		got = events()
		if len(got) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, notify.EventAdminLoginNew+"|admin") || !strings.Contains(joined, notify.EventAdminLoginFail+"|admin") || strings.Count(joined, notify.EventAdminLoginNew) != 1 {
		t.Fatalf("delivery log: %v", got)
	}
}

func TestUpdaterAvailableAnnouncedOncePerTag(t *testing.T) {
	events := setupNotifyGlueTest(t)
	notifyManager.SaveChannel(notify.ChannelConfig{Name: "rec", Type: notify.ChanNtfy, Enabled: true, AllowPrivate: true,
		Settings: map[string]string{"server": recv(t), "topic": "t"}})
	h := notifyUpdaterCheckWrap(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":{"update_available":true,"channel":"stable","current":{"version":"3.3.5"},"latest":{"tag":"v3.3.6.1","url":"https://example/r"}}}`))
	})
	for i := 0; i < 3; i++ {
		h(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/updater/check", nil))
	}
	time.Sleep(300 * time.Millisecond)
	n := 0
	for _, e := range events() {
		if strings.HasPrefix(e, notify.EventUpdateAvail+"|v3.3.6.1") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("announced %d times", n)
	}
}

func TestStatSettingsAPIExcludeMyIP(t *testing.T) {
	tmp := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(tmp, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	oldDB, oldSC := sysdb, statisticCollector
	sysdb = db
	sc, err := statistic.NewStatisticCollector(statistic.CollectorOption{Database: db})
	if err != nil {
		t.Fatal(err)
	}
	statisticCollector = sc
	t.Cleanup(func() { sysdb, statisticCollector = oldDB, oldSC })

	r := httptest.NewRequest("POST", "/api/stats/excludeMyIP", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	w := httptest.NewRecorder()
	HandleStatExcludeMyIP(w, r)
	HandleStatExcludeMyIP(httptest.NewRecorder(), r) // idempotent
	if got := sc.GetSettings().ExcludeNetworks; len(got) != 1 || got[0] != "203.0.113.7/32" {
		t.Fatalf("exclude list: %v", got)
	}
	// persisted and restored
	sc.SetSettings(statistic.DefaultSettings())
	loadStatSettings()
	if got := sc.GetSettings().ExcludeNetworks; len(got) != 1 {
		t.Fatalf("not restored: %v", got)
	}
	body := `{"ExcludeNetworks":["10.0.0.0/8","bogus"],"QueryMode":"mask"}`
	w = httptest.NewRecorder()
	HandleStatSettings(w, httptest.NewRequest("POST", "/api/stats/settings", strings.NewReader(body)))
	if !strings.Contains(w.Body.String(), "error") {
		t.Fatalf("invalid CIDR accepted: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	HandleStatSettings(w, httptest.NewRequest("POST", "/api/stats/settings", strings.NewReader(`{"ExcludeNetworks":["10.0.0.0/8"],"ExcludeBlocked":true,"QueryMode":"mask"}`)))
	if s := sc.GetSettings(); !s.ExcludeBlocked || s.QueryMode != "mask" || len(s.ExcludeNetworks) != 1 {
		t.Fatalf("settings: %+v (%s)", s, w.Body.String())
	}
}
