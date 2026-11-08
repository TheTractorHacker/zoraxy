package main

import (
	"net/http"

	"imuslab.com/zoraxy/mod/info/logger"
)

// initSiteLogs attaches the optional per-site request logs (disabled by default)
// to the system logger. The config lives in conf/sitelog.json.
func initSiteLogs() {
	if SystemWideLogger == nil {
		return
	}
	sites, err := logger.NewSiteLogs(SystemWideLogger.LogFolder, logger.LoadSiteLogConfig(CONF_FOLDER+"/sitelog.json"))
	if err != nil {
		SystemWideLogger.PrintAndLog("sitelog", "Per-site logs disabled", err)
		return
	}
	sites.StartJanitor()
	SystemWideLogger.Sites = sites
}

func HandleSiteLogConfig(w http.ResponseWriter, r *http.Request) {
	var sites *logger.SiteLogs
	if SystemWideLogger != nil {
		sites = SystemWideLogger.Sites
	}
	logger.HandleSiteLogConfig(CONF_FOLDER+"/sitelog.json", sites)(w, r)
}

// logSearchGeo resolves a client IP into a lower-case country code for the log search country filter
func logSearchGeo(ip string) string {
	if geodbStore == nil {
		return ""
	}
	info, err := geodbStore.ResolveCountryCodeFromIP(ip)
	if err != nil || info == nil {
		return ""
	}
	return info.CountryIsoCode
}
