package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/uptime"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	uptimesettings.go

	Global "which HTTP status codes count as up" setting of the uptime monitor.
	GET  /api/utm/healthyStatus                 -> {"status":"","default":"any"}
	POST /api/utm/healthyStatus  status=<spec>  (empty = any answer except gateway errors)
	A rule can override it (ProxyEndpoint.UptimeHealthyStatus). See mod/uptime/statusspec.go.
*/

const uptimeSettingsTable = "uptime"

func loadUptimeSettings() {
	if sysdb == nil {
		return
	}
	sysdb.NewTable(uptimeSettingsTable)
	var spec string
	if sysdb.Read(uptimeSettingsTable, "healthyStatus", &spec) == nil {
		if err := uptime.SetDefaultHealthyStatus(spec); err != nil {
			SystemWideLogger.PrintAndLog("uptime", "Ignoring invalid saved healthy status list", err)
		}
	}
}

func HandleUptimeHealthyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		spec, _ := utils.PostPara(r, "status")
		spec = strings.TrimSpace(spec)
		if err := uptime.SetDefaultHealthyStatus(spec); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		sysdb.NewTable(uptimeSettingsTable)
		if err := sysdb.Write(uptimeSettingsTable, "healthyStatus", uptime.DefaultHealthyStatus()); err != nil {
			utils.SendErrorResponse(w, "unable to save the setting")
			return
		}
		if uptimeMonitor != nil {
			go uptimeMonitor.ExecuteUptimeCheck()
		}
		utils.SendOK(w)
		return
	}
	js, _ := json.Marshal(map[string]string{"status": uptime.DefaultHealthyStatus()})
	utils.SendJSONResponse(w, string(js))
}
