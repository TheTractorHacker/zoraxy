package main

import (
	"encoding/json"
	"net/http"

	"imuslab.com/zoraxy/mod/dynamicproxy/redirection"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	redirect_advanced.go

	GET  /api/redirect/advancedregex                 -> {"enabled":bool,"timeoutMs":int}
	POST /api/redirect/advancedregex  enable=bool    -> switch the redirect rule regex engine to the backtracking one
	POST /api/redirect/advancedregex/check pattern=  -> {"valid":bool,"error":"..."} compile check for the editor

	Only has an effect while the plain "regex" redirect option is enabled. Default off (RE2).
*/

func initRedirectAdvancedRegex() {
	enabled := false
	if sysdb != nil {
		sysdb.Read("redirect", "regexAdvanced", &enabled)
	}
	redirectTable.AdvancedRegex = enabled
}

func handleRedirectAdvancedRegex(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		enable, err := utils.PostBool(r, "enable")
		if err != nil {
			utils.SendErrorResponse(w, "enable not given")
			return
		}
		redirectTable.AdvancedRegex = enable
		if err := sysdb.Write("redirect", "regexAdvanced", enable); err != nil {
			utils.SendErrorResponse(w, "unable to save settings")
			return
		}
		if enable {
			SystemWideLogger.PrintAndLog("redirect", "Advanced (backtracking) regex engine enabled for redirect rules", nil)
		}
		utils.SendOK(w)
		return
	}
	js, _ := json.Marshal(map[string]interface{}{
		"enabled":   redirectTable.AdvancedRegex,
		"timeoutMs": redirection.AdvancedRegexTimeout.Milliseconds(),
	})
	utils.SendJSONResponse(w, string(js))
}

func handleRedirectAdvancedRegexCheck(w http.ResponseWriter, r *http.Request) {
	pattern, _ := utils.PostPara(r, "pattern")
	res := map[string]interface{}{"valid": true}
	if err := redirection.ValidateAdvancedRegex(pattern); err != nil {
		res = map[string]interface{}{"valid": false, "error": err.Error()}
	}
	js, _ := json.Marshal(res)
	utils.SendJSONResponse(w, string(js))
}
