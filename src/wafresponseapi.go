package main

import (
	"net/http"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	wafresponseapi.go

	API of response inspection (outbound leak detection). The settings travel in the
	existing policy / profile / endpoint "extra" JSON (field Response); events in the
	existing /api/waf/events (kind=response, group=...).
*/

func RegisterWAFResponseAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/waf/response/signatures", HandleWAFResponseSignatures)
}

// HandleWAFResponseSignatures lists the built-in response inspection signatures and limits
func HandleWAFResponseSignatures(w http.ResponseWriter, r *http.Request) {
	sendWAFJSON(w, map[string]interface{}{
		"signatures":     waf.ResponseSignatures(),
		"groups":         waf.ResponseGroups,
		"default_window": waf.DefaultResponseWindowKiB,
		"max_window":     waf.MaxResponseWindowKiB,
	})
}
