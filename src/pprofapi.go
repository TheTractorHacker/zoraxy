package main

import (
	"net/http"
	"net/http/pprof"
	"strings"
)

/*
	pprofapi.go

	Admin-only Go profiling endpoints (upstream #770, high CPU under load).
	The index used to be registered alone, so the links on it (profile, heap, goroutine...) were
	404. The sub paths are served below /api/info/pprof/ and need the same admin login as every
	other management API; viewer accounts are refused by the role guard.
*/

const pprofAPIPrefix = "/api/info/pprof/"

func handlePprof(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, pprofAPIPrefix)
	switch name {
	case "":
		//pprof.Index only renders its listing when the path does not start with /debug/pprof/
		pprof.Index(w, r)
	case "cmdline":
		pprof.Cmdline(w, r)
	case "profile":
		pprof.Profile(w, r)
	case "symbol":
		pprof.Symbol(w, r)
	case "trace":
		pprof.Trace(w, r)
	default:
		if strings.Contains(name, "/") || pprof.Handler(name) == nil {
			http.NotFound(w, r)
			return
		}
		pprof.Handler(name).ServeHTTP(w, r)
	}
}
