package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/notify"
	"imuslab.com/zoraxy/mod/utils"
	"imuslab.com/zoraxy/mod/visitors"
)

/*
	Visitors API (who visited, when and where)

	GET  /api/visitors/summary                         headline numbers + filter choices
	GET  /api/visitors/list     filters + sort,dir,page,size   one page of client IPs
	GET  /api/visitors/recent   filters + after,limit  individual recent visits (live tail: after=<last seq>)
	GET  /api/visitors/detail?ip=                      one IP: hosts, paths, daily timeline, recent visits
	GET  /api/visitors/export   filters + scope=visitors|visits, format=csv|json
	GET  /api/visitors/settings
	POST /api/visitors/settings                        JSON body, see visitors.Settings
	POST /api/visitors/delete   ip=                    erase one IP
	POST /api/visitors/purge    confirm=yes            erase everything

	Filters: q, host, country (ISO), via (direct|cloudflare|proxy), blocked=1, since (hours back, 0 = all)
*/

const visitorSettingsTable = "visitors"

var (
	countryCodeRe = regexp.MustCompile(`^[A-Za-z]{2}$`)
	hostNameRe    = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]{1,253}$`)
)

// initVisitors creates the visitor tracker (conf/visitors.json.gz) and connects it to the statistics filters
func initVisitors() {
	if sysdb == nil {
		return
	}
	sysdb.NewTable(visitorSettingsTable)
	s := visitors.DefaultSettings()
	if sysdb.KeyExists(visitorSettingsTable, "settings") {
		sysdb.Read(visitorSettingsTable, "settings", &s)
	}
	visitorTracker = visitors.New(CONF_FOLDER+"/visitors.json.gz", s)
	if statisticCollector != nil {
		// the "exclude my IP / network" list and the "exclude blocked requests" switch of the statistics apply here too
		visitorTracker.SetExcluder(statisticCollector.ExcludesIP)
		visitorTracker.SetExcludeBlocked(statisticCollector.ExcludesBlocked)
	}
	visitorTracker.OnNewCountry = func(country, ip, host string) {
		notify.Emit(notify.Event{Event: notify.EventVisitorNewCountry, Source: "visitors", Subject: country,
			Extra: map[string]string{"ip": ip, "host": host}})
	}
	visitorTracker.Start()
}

func parseVisitorFilter(r *http.Request) (visitors.Filter, error) {
	q := r.URL.Query()
	f := visitors.Filter{Q: strings.TrimSpace(q.Get("q"))}
	if len(f.Q) > 100 {
		return f, fmt.Errorf("search text too long")
	}
	if h := strings.ToLower(strings.TrimSpace(q.Get("host"))); h != "" {
		if !hostNameRe.MatchString(h) {
			return f, fmt.Errorf("invalid host")
		}
		f.Host = h
	}
	if c := strings.TrimSpace(q.Get("country")); c != "" {
		if !countryCodeRe.MatchString(c) {
			return f, fmt.Errorf("invalid country code")
		}
		f.Country = strings.ToUpper(c)
	}
	switch v := q.Get("via"); v {
	case "", visitors.ViaDirect, visitors.ViaCloudflare, visitors.ViaProxy:
		f.Via = v
	default:
		return f, fmt.Errorf("invalid via")
	}
	f.BlockedOnly = q.Get("blocked") == "1" || q.Get("blocked") == "true"
	if h := q.Get("since"); h != "" {
		hours, err := strconv.Atoi(h)
		if err != nil || hours < 0 || hours > 24*3650 {
			return f, fmt.Errorf("invalid since")
		}
		if hours > 0 {
			f.Since = time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
		}
	}
	return f, nil
}

func visitorsReady(w http.ResponseWriter) bool {
	if visitorTracker == nil {
		utils.SendErrorResponse(w, "visitor tracking is not available")
		return false
	}
	return true
}

func intParam(r *http.Request, name string, def, min, max int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("invalid %s", name)
	}
	return n, nil
}

func visitorJSON(w http.ResponseWriter, v interface{}) {
	js, _ := json.Marshal(v)
	utils.SendJSONResponse(w, string(js))
}

func HandleVisitorSummary(w http.ResponseWriter, r *http.Request) {
	if !visitorsReady(w) {
		return
	}
	visitorJSON(w, map[string]interface{}{
		"Summary": visitorTracker.Summary(time.Now()),
		"Stats":   visitorTracker.Stats(),
	})
}

func HandleVisitorList(w http.ResponseWriter, r *http.Request) {
	if !visitorsReady(w) {
		return
	}
	f, err := parseVisitorFilter(r)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	sortKey := r.URL.Query().Get("sort")
	if !visitors.ValidSort(sortKey) {
		utils.SendErrorResponse(w, "invalid sort")
		return
	}
	page, err := intParam(r, "page", 0, 0, 1000000)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	size, err := intParam(r, "size", 50, 1, 500)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	visitorJSON(w, visitorTracker.List(visitors.ListQuery{Filter: f, Sort: sortKey, Desc: r.URL.Query().Get("dir") != "asc", Page: page, Size: size}))
}

func HandleVisitorRecent(w http.ResponseWriter, r *http.Request) {
	if !visitorsReady(w) {
		return
	}
	f, err := parseVisitorFilter(r)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	after, err := intParam(r, "after", 0, 0, int(^uint32(0)>>1))
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	limit, err := intParam(r, "limit", 200, 1, 2000)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	st := visitorTracker.Stats()
	visitorJSON(w, map[string]interface{}{"Visits": visitorTracker.Recent(uint64(after), limit, f), "Seq": st.Seq})
}

func validIPParam(w http.ResponseWriter, ip string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		utils.SendErrorResponse(w, "invalid ip")
		return "", false
	}
	return a.String(), true
}

func HandleVisitorDetail(w http.ResponseWriter, r *http.Request) {
	if !visitorsReady(w) {
		return
	}
	ip, ok := validIPParam(w, r.URL.Query().Get("ip"))
	if !ok {
		return
	}
	v, recent := visitorTracker.Get(ip)
	if v == nil {
		utils.SendErrorResponse(w, "unknown visitor")
		return
	}
	if len(recent) > 200 {
		recent = recent[:200]
	}
	visitorJSON(w, map[string]interface{}{"Visitor": v, "Recent": recent})
}

func HandleVisitorExport(w http.ResponseWriter, r *http.Request) {
	if !visitorsReady(w) {
		return
	}
	f, err := parseVisitorFilter(r)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	scope := r.URL.Query().Get("scope")
	if scope != "" && scope != "visitors" && scope != "visits" {
		utils.SendErrorResponse(w, "invalid scope")
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "csv" && format != "json" {
		utils.SendErrorResponse(w, "invalid format")
		return
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	setDownload := func(ext, ctype string) {
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Content-Disposition", `attachment; filename="visitors-`+scope+"-"+stamp+"."+ext+`"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
	}
	if scope == "" {
		scope = "visitors"
	}
	if scope == "visits" {
		items := visitorTracker.Recent(0, 0, f)
		if format == "json" {
			setDownload("json", "application/json")
			json.NewEncoder(w).Encode(items)
			return
		}
		setDownload("csv", "text/csv; charset=utf-8")
		visitors.WriteVisitsCSV(w, items)
		return
	}
	items := visitorTracker.All(f)
	if format == "json" {
		setDownload("json", "application/json")
		json.NewEncoder(w).Encode(items)
		return
	}
	setDownload("csv", "text/csv; charset=utf-8")
	visitors.WriteVisitorsCSV(w, items)
}

func HandleVisitorSettings(w http.ResponseWriter, r *http.Request) {
	if !visitorsReady(w) {
		return
	}
	if r.Method == http.MethodPost {
		var s visitors.Settings
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			utils.SendErrorResponse(w, "invalid JSON body")
			return
		}
		applied := visitorTracker.SetSettings(s)
		if err := sysdb.Write(visitorSettingsTable, "settings", applied); err != nil {
			utils.SendErrorResponse(w, "unable to save the settings")
			return
		}
	} else if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	visitorJSON(w, map[string]interface{}{"Settings": visitorTracker.Settings(), "Stats": visitorTracker.Stats()})
}

func HandleVisitorDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !visitorsReady(w) {
		return
	}
	ip, ok := validIPParam(w, r.PostFormValue("ip"))
	if !ok {
		return
	}
	if !visitorTracker.Delete(ip) {
		utils.SendErrorResponse(w, "unknown visitor")
		return
	}
	utils.SendOK(w)
}

func HandleVisitorPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !visitorsReady(w) {
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		utils.SendErrorResponse(w, "confirmation missing")
		return
	}
	visitorTracker.Purge()
	utils.SendOK(w)
}

// RegisterVisitorAPIs registers the visitor list endpoints
func RegisterVisitorAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/visitors/summary", HandleVisitorSummary)
	authRouter.HandleFunc("/api/visitors/list", HandleVisitorList)
	authRouter.HandleFunc("/api/visitors/recent", HandleVisitorRecent)
	authRouter.HandleFunc("/api/visitors/detail", HandleVisitorDetail)
	authRouter.HandleFunc("/api/visitors/export", HandleVisitorExport)
	authRouter.HandleFunc("/api/visitors/settings", HandleVisitorSettings)
	authRouter.HandleFunc("/api/visitors/delete", HandleVisitorDelete)
	authRouter.HandleFunc("/api/visitors/purge", HandleVisitorPurge)
}
