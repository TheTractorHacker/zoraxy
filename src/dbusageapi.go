package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/database/dbinc"
)

/*
	dbusageapi.go

	GET /api/system/dbusage  (admin only, see mod/auth/router.go viewerDeniedPrefixes)

	Read only visibility of what the system database (sys.db) holds, so an admin
	can see which table makes it grow. It never writes, deletes or compacts anything.
	Used by the "Database" card of System > Settings.
*/

// dbUsageBudget caps how long one request may keep its read transaction open
const dbUsageBudget = 5 * time.Second

// dbUsageLargeBytes is the size above which the UI shows the compaction hint
const dbUsageLargeBytes = 200 << 20

// RegisterDatabaseUsageAPIs registers the admin only database usage endpoint
func RegisterDatabaseUsageAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/system/dbusage", HandleDatabaseUsage)
}

type dbUsageResponse struct {
	Supported  bool         `json:"supported"` //false for backends other than BoltDB
	Backend    string       `json:"backend"`
	Path       string       `json:"path"`       //absolute path of the database file
	LargeBytes int64        `json:"largeBytes"` //size above which compaction is suggested
	Usage      *dbinc.Usage `json:"usage,omitempty"`
	Error      string       `json:"error,omitempty"`
}

// HandleDatabaseUsage reports file size, free space inside the file and per table sizes
func HandleDatabaseUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	//Defence in depth: the router already refuses viewer accounts for this prefix
	if authAgent != nil && authAgent.RequestRole(r) == auth.RoleViewer {
		http.Error(w, "403 - Admin only", http.StatusForbidden)
		return
	}
	resp := dbUsageResponse{Backend: "unknown", LargeBytes: dbUsageLargeBytes}
	if p, err := filepath.Abs(*path_database); err == nil {
		resp.Path = p
	} else {
		resp.Path = *path_database
	}
	if sysdb == nil {
		resp.Error = "database not ready"
	} else {
		resp.Backend = sysdb.BackendType.String()
		u, err := sysdb.Usage(dbUsageBudget)
		switch {
		case errors.Is(err, dbinc.ErrUsageUnsupported):
			//other backends: nothing to list
		case err != nil:
			resp.Error = err.Error()
		default:
			resp.Supported = true
			resp.Usage = u
			resp.Backend = u.Backend
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}
