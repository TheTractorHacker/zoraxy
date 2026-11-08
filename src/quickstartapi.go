package main

/*
	quickstartapi.go

	Tells the admin UI whether the Quick Start page is still needed.

	GET  /api/quickstart                 -> {"dismissed":bool,"configured":bool,"show":bool,"rules":int,"proxyRunning":bool}
	POST /api/quickstart  dismissed=bool -> same document. "Show Quick Start again" posts dismissed=false.

	An instance counts as set up ("configured") when at least one HTTP proxy rule exists and the proxy listener is
	running. Quick Start is shown on instances that are neither configured nor dismissed. The dismissal is stored in the
	settings table, so it follows the instance instead of the browser.
*/

import (
	"encoding/json"
	"net/http"

	"imuslab.com/zoraxy/mod/utils"
)

const quickStartDismissKey = "quickstartDismissed"

type quickStartState struct {
	Dismissed    bool `json:"dismissed"`
	Configured   bool `json:"configured"`
	Show         bool `json:"show"`
	Rules        int  `json:"rules"`
	ProxyRunning bool `json:"proxyRunning"`
}

// quickStartDecide is the pure decision, kept separate for testing
func quickStartDecide(dismissed bool, rules int, running bool) quickStartState {
	configured := rules > 0 && running
	return quickStartState{
		Dismissed:    dismissed,
		Configured:   configured,
		Show:         !dismissed && !configured,
		Rules:        rules,
		ProxyRunning: running,
	}
}

func currentQuickStartState() quickStartState {
	dismissed := false
	if sysdb != nil {
		sysdb.Read("settings", quickStartDismissKey, &dismissed)
	}
	rules, running := 0, false
	if dynamicProxyRouter != nil {
		running = dynamicProxyRouter.Running
		dynamicProxyRouter.ProxyEndpoints.Range(func(_, _ interface{}) bool {
			rules++
			return true
		})
	}
	return quickStartDecide(dismissed, rules, running)
}

func HandleQuickStartState(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		d, err := utils.PostBool(r, "dismissed")
		if err != nil {
			utils.SendErrorResponse(w, "dismissed (true/false) is required")
			return
		}
		if sysdb == nil {
			utils.SendErrorResponse(w, "database not available")
			return
		}
		if err := sysdb.Write("settings", quickStartDismissKey, d); err != nil {
			utils.SendErrorResponse(w, "unable to save")
			return
		}
	}
	js, _ := json.Marshal(currentQuickStartState())
	utils.SendJSONResponse(w, string(js))
}
