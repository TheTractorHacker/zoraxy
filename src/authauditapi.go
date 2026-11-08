package main

import (
	"encoding/json"
	"net/http"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	authauditapi.go

	Authentication audit (upstream #1109 follow-up), logic in mod/dynamicproxy/authaudit.go
	  GET  /api/authaudit/get            rows (effective provider + weaknesses per proxy rule), lint setting and violations
	  POST /api/authaudit/autotag        optional ep (one rule); replaces the auth:* tags by auth:<provider>
	  POST /api/authaudit/setRequire     enable (bool): lint "every rule must have authentication" (report only)

	The lint never blocks or changes a rule, it only lists the offenders.
*/

func RegisterAuthAuditAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/authaudit/get", HandleAuthAuditGet)
	authRouter.HandleFunc("/api/authaudit/autotag", HandleAuthAuditAutoTag)
	authRouter.HandleFunc("/api/authaudit/setRequire", HandleAuthAuditSetRequire)
}

func authAuditRequireAll() bool {
	v := false
	if sysdb != nil {
		sysdb.Read("settings", "authAuditRequireAll", &v)
	}
	return v
}

func HandleAuthAuditGet(w http.ResponseWriter, r *http.Request) {
	rows := dynamicProxyRouter.AuditAllAuth()
	require := authAuditRequireAll()
	violations := []string{}
	for _, row := range rows {
		if !row.Disabled && row.Method == "none" {
			violations = append(violations, row.Name)
		}
	}
	if !require {
		violations = []string{}
	}
	js, _ := json.Marshal(map[string]interface{}{"Rows": rows, "RequireAll": require, "Violations": violations})
	utils.SendJSONResponse(w, string(js))
}

func HandleAuthAuditAutoTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	only, _ := utils.PostPara(r, "ep")
	changed := 0
	for _, row := range dynamicProxyRouter.AuditAllAuth() {
		if only != "" && row.Name != only {
			continue
		}
		want := dynamicproxy.RetagAuth(row.Tags, row.WantedTag)
		if equalStrings(want, row.Tags) {
			continue
		}
		if err := applyNetworkingChange(row.Name, func(e *dynamicproxy.ProxyEndpoint) error {
			e.Tags = dynamicproxy.RetagAuth(e.Tags, row.WantedTag)
			return nil
		}); err != nil {
			utils.SendErrorResponse(w, row.Name+": "+err.Error())
			return
		}
		changed++
	}
	js, _ := json.Marshal(map[string]int{"Changed": changed})
	utils.SendJSONResponse(w, string(js))
}

func HandleAuthAuditSetRequire(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	enable, err := utils.PostBool(r, "enable")
	if err != nil {
		utils.SendErrorResponse(w, "enable missing")
		return
	}
	if err := sysdb.Write("settings", "authAuditRequireAll", enable); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
