package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/statistic"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Statistics filter settings API

	GET  /api/stats/settings       current settings and the caller's IP
	POST /api/stats/settings       JSON body {ExcludeNetworks:[], ExcludeBlocked:bool, QueryMode:"strip|mask|full"}
	POST /api/stats/excludeMyIP    add the caller's current IP to the exclusion list
*/

const statSettingsTable = "statsettings"

// loadStatSettings restores the persisted filter settings into the collector
func loadStatSettings() {
	if sysdb == nil || statisticCollector == nil {
		return
	}
	sysdb.NewTable(statSettingsTable)
	s := statistic.DefaultSettings()
	if sysdb.KeyExists(statSettingsTable, "v") {
		sysdb.Read(statSettingsTable, "v", &s)
	}
	if err := statisticCollector.SetSettings(s); err != nil {
		SystemWideLogger.PrintAndLog("statistic", "Ignoring invalid saved statistic settings", err)
		statisticCollector.SetSettings(statistic.DefaultSettings())
	}
}

func saveStatSettings(s statistic.Settings) error {
	if err := statisticCollector.SetSettings(s); err != nil {
		return err
	}
	return sysdb.Write(statSettingsTable, "v", statisticCollector.GetSettings())
}

// callerIP is the address the admin panel request came from
func callerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return strings.TrimSpace(host)
}

func HandleStatSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var s statistic.Settings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&s); err != nil {
			utils.SendErrorResponse(w, "invalid JSON body")
			return
		}
		if err := saveStatSettings(s); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
	}
	js, _ := json.Marshal(map[string]interface{}{
		"Settings": statisticCollector.GetSettings(),
		"YourIP":   callerIP(r),
	})
	utils.SendJSONResponse(w, string(js))
}

func HandleStatExcludeMyIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	norm, err := statistic.NormalizeNetwork(callerIP(r))
	if err != nil {
		utils.SendErrorResponse(w, "unable to determine your IP address")
		return
	}
	s := statisticCollector.GetSettings()
	for _, n := range s.ExcludeNetworks {
		if n == norm {
			utils.SendOK(w)
			return
		}
	}
	s.ExcludeNetworks = append(s.ExcludeNetworks, norm)
	if err := saveStatSettings(s); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
