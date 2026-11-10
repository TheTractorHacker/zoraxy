package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/apitoken"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/cluster"
	"imuslab.com/zoraxy/mod/confhistory"
)

/*
	history.go

	Glue between Zoraxy and mod/confhistory (change history and undo).
	Design, what is captured and the restore flow: DEVELOPMENT.md, "Change history".
*/

var historyMgr *confhistory.Manager

// initHistory opens the history store and finishes an interrupted restore. It
// must run right after sys.db is open and before any module reads its
// configuration files.
func initHistory() {
	opt := confhistory.Options{
		ConfDir: CONF_FOLDER,
		DB:      sysdb,
		Reload:  historyReload,
		Validate: func(rel string, data []byte) error {
			if strings.HasPrefix(rel, "access/") && strings.HasSuffix(rel, ".json") {
				var rule access.AccessRule
				return json.Unmarshal(data, &rule)
			}
			//the same schema checks a Fleet / cluster apply runs on proxy rules, the WAF and trusted proxies
			return validateClusterPayload(&cluster.Payload{Files: []cluster.FileEntry{{Path: rel, Data: data}}})
		},
		Managed: func(rel string) string {
			if clusterMgr == nil {
				return ""
			}
			return clusterMgr.HubManagedReason(rel)
		},
		Actor: func(r *http.Request) string {
			if name, ok := historyActor(r); ok {
				return name
			}
			return ""
		},
		Logf: func(format string, a ...any) {
			if SystemWideLogger != nil {
				SystemWideLogger.Println(fmt.Sprintf(format, a...))
			}
		},
	}
	m, err := confhistory.New(opt)
	if err != nil {
		//History must never keep the proxy from starting
		if SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("history", "Change history is unavailable", err)
		}
		return
	}
	historyMgr = m
	m.BootGuard()
}

// startHistory records the baseline once the modules are up and confirms a
// pending restore after a stable start. Call it next to startCluster().
func startHistory() {
	if historyMgr == nil {
		return
	}
	go historyMgr.Start()
	time.AfterFunc(historyMgr.HealthyAfter(), historyMgr.MarkHealthy)
}

// stopHistory stores a snapshot that is still waiting for its debounce window.
func stopHistory() {
	if historyMgr != nil {
		historyMgr.Flush()
	}
}

// historyReload restarts Zoraxy so it loads restored files. Same mechanism as
// the cluster apply: restart in place after a short delay so the HTTP
// response of the restore request can be delivered first.
func historyReload() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	go func() {
		SystemWideLogger.Println("Configuration restored from history. Restarting in 3 seconds...")
		time.Sleep(3 * time.Second)
		ShutdownSeq()
		restartSelf(exe)
	}()
	return nil
}

// historyActor names the admin behind an admin API request.
func historyActor(r *http.Request) (string, bool) {
	if authAgent != nil {
		if name, err := authAgent.GetUserName(nil, r); err == nil && name != "" {
			return name, true
		}
	}
	if !requireAuth { //-noauth: every request is the admin
		return "admin", true
	}
	return "", false
}

// historyWrap records configuration changes made through the admin API.
func historyWrap(next http.Handler) http.Handler {
	if historyMgr == nil {
		return next
	}
	return historyMgr.Middleware(func(w http.ResponseWriter, r *http.Request) (string, bool) {
		return historyActor(r)
	})(next)
}

// historyWrapV1 records changes made through the token authenticated REST API.
func historyWrapV1(next http.Handler) http.Handler {
	if historyMgr == nil {
		return next
	}
	return historyMgr.Middleware(func(w http.ResponseWriter, r *http.Request) (string, bool) {
		name := apitoken.TokenName(r)
		if name == "" || name == "-" {
			return "", false
		}
		return "token " + name, true
	})(next)
}

// historyBefore takes a snapshot before a risky operation (in-app update).
func historyBefore(trigger, summary string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if historyMgr != nil && r.Method == http.MethodPost {
			actor, _ := historyActor(r)
			if _, _, err := historyMgr.Capture(confhistory.CaptureInfo{Actor: actor, Trigger: trigger, Summary: summary}); err != nil && SystemWideLogger != nil {
				SystemWideLogger.PrintAndLog("history", "Snapshot before "+trigger+" failed", err)
			}
		}
		h(w, r)
	}
}

// RegisterHistoryAPIs registers the admin APIs (session + CSRF like all others).
func RegisterHistoryAPIs(authRouter *auth.RouterDef) {
	if historyMgr == nil {
		return
	}
	historyMgr.Register(authRouter.HandleFunc)
}
