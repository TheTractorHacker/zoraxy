package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/aicrawler"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/offline"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	aicrawlerapi.go

	Admin APIs of the AI crawler policy (mod/aicrawler, page "AI crawlers" under Security). Admin session and CSRF
	protection come with the router. Everything is off until the admin turns it on.

	  GET  /api/aicrawler/get              config, registry, groups, range status, sites, counters, informational posture
	  POST /api/aicrawler/set              config (JSON, the whole configuration)
	  POST /api/aicrawler/ranges/refresh   ids (optional, comma separated): fetch the published IP range lists NOW
	                                       (explicit admin action; never at start-up, never on a timer)
	  GET  /api/aicrawler/preview          site, ua: what the policy would do, plus the generated robots.txt / llms.txt
*/

var (
	aiCrawlerEngine *aicrawler.Engine
	aiCrawlerOnce   sync.Once

	aiRangesMu      sync.Mutex
	aiRangesLast    time.Time
	aiRangesFetcher *aicrawler.Fetcher
)

const aiRangesMinInterval = 20 * time.Second

func getAICrawlerEngine() *aicrawler.Engine {
	aiCrawlerOnce.Do(func() {
		e := aicrawler.New(CONF_FOLDER+"/aicrawler.json", CONF_FOLDER+"/aicrawler_ranges.json")
		if err := e.Load(); err != nil && SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("aicrawler", "Unable to load the AI crawler policy, starting disabled", err)
		}
		aiCrawlerEngine = e
	})
	return aiCrawlerEngine
}

func RegisterAICrawlerAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/aicrawler/get", HandleAICrawlerGet)
	authRouter.HandleFunc("/api/aicrawler/set", HandleAICrawlerSet)
	authRouter.HandleFunc("/api/aicrawler/ranges/refresh", HandleAICrawlerRefresh)
	authRouter.HandleFunc("/api/aicrawler/preview", HandleAICrawlerPreview)
}

type aiSiteInfo struct {
	Key         string `json:"key"`
	LegacyBlock bool   `json:"legacyBlock"` // the older all-or-nothing AI crawlers switch of the proxy rule
	BotPolicy   string `json:"botPolicy"`
}

func aiSites() ([]aiSiteInfo, int) {
	sites := []aiSiteInfo{}
	legacy := 0
	if dynamicProxyRouter != nil {
		for _, ep := range dynamicProxyRouter.GetProxyEndpointsAsMap() {
			if ep == nil || ep.ProxyType != 1 { // host rules only
				continue
			}
			sites = append(sites, aiSiteInfo{Key: ep.RootOrMatchingDomain, LegacyBlock: ep.BlockAICrawlers, BotPolicy: ep.BotPolicy})
			if ep.BlockAICrawlers {
				legacy++
			}
		}
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Key < sites[j].Key })
	return sites, legacy
}

func HandleAICrawlerGet(w http.ResponseWriter, r *http.Request) {
	eng := getAICrawlerEngine()
	sites, legacy := aiSites()
	cfg := eng.Config()
	if cfg.Sites == nil {
		cfg.Sites = map[string]*aicrawler.SiteCfg{}
	}
	ranges := eng.Ranges.Status()
	reg := aicrawler.Registry()
	type regRow struct {
		aicrawler.Entry
		Verifiable bool `json:"verifiable"`
		RangesLoad bool `json:"rangesLoaded"` // data for at least one of its range lists is loaded
	}
	rows := make([]regRow, 0, len(reg))
	for _, e := range reg {
		row := regRow{Entry: e, Verifiable: e.Verify.Verifiable()}
		for _, id := range e.Verify.RangeSources {
			if eng.Ranges.Has(id) {
				row.RangesLoad = true
			}
		}
		rows = append(rows, row)
	}
	js, _ := json.Marshal(map[string]interface{}{
		"Config": cfg, "RegistryVersion": aicrawler.RegistryVersion, "Registry": rows, "Groups": aicrawler.Groups(),
		"Ranges": ranges, "Sites": sites, "Stats": eng.Stats(), "Posture": eng.Posture(legacy), "DefaultRateLimit": aicrawler.DefaultRateLimit,
	})
	utils.SendJSONResponse(w, string(js))
}

func HandleAICrawlerSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	if len(raw) > 2<<20 {
		utils.SendErrorResponse(w, "config too large")
		return
	}
	cfg := aicrawler.DefaultConfig()
	dec := json.NewDecoder(strings.NewReader(raw))
	if err := dec.Decode(&cfg); err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	if err := getAICrawlerEngine().SetConfig(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleAICrawlerRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	if offline.Enabled() {
		utils.SendErrorResponse(w, "Offline mode is on: nothing is fetched")
		return
	}
	var ids []string
	if v, _ := utils.PostPara(r, "ids"); v != "" {
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
	}
	aiRangesMu.Lock()
	if time.Since(aiRangesLast) < aiRangesMinInterval {
		aiRangesMu.Unlock()
		utils.SendErrorResponse(w, "Please wait a few seconds before refreshing again")
		return
	}
	aiRangesLast = time.Now()
	if aiRangesFetcher == nil {
		aiRangesFetcher = aicrawler.NewFetcher()
	}
	f := aiRangesFetcher
	aiRangesMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	res := getAICrawlerEngine().Ranges.Refresh(ctx, f, ids)
	js, _ := json.Marshal(map[string]interface{}{"Results": res, "Ranges": getAICrawlerEngine().Ranges.Status()})
	utils.SendJSONResponse(w, string(js))
}

func HandleAICrawlerPreview(w http.ResponseWriter, r *http.Request) {
	eng := getAICrawlerEngine()
	site, _ := utils.GetPara(r, "site")
	ua, _ := utils.GetPara(r, "ua")
	cfg := eng.Config()
	out := map[string]interface{}{"Robots": "", "RobotsAppend": ""}
	if site != "" {
		out["Robots"] = cfg.RobotsFile(site)
		out["RobotsAppend"] = cfg.RobotsAppend(site)
	} else {
		out["Robots"] = cfg.RobotsFile("")
		out["RobotsAppend"] = cfg.RobotsAppend("")
	}
	if ua != "" {
		if entry, action, ok := eng.Preview(site, ua); ok {
			out["Match"] = map[string]interface{}{"id": entry.ID, "name": entry.Name, "group": entry.Group, "action": action, "verifiable": entry.Verify.Verifiable()}
		} else {
			out["Match"] = nil
		}
	}
	js, _ := json.Marshal(out)
	utils.SendJSONResponse(w, string(js))
}
