package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/notify"
	"imuslab.com/zoraxy/mod/posture"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	posture_api.go

	Security overview APIs (admin session + CSRF, see mod/posture for the logic):
	  GET  /api/security/posture            checks, score, available fixes. Read only. ?refresh=1 skips the 10 s cache
	  POST /api/security/posture/preview    {"actions":["waf.baseline", ...]}              exact changes, no side effects
	  POST /api/security/posture/apply      {"actions":[{"id":"waf.baseline","hash":"<from preview>"}]}
	  POST /api/security/posture/undo       {"action":"waf.baseline"}
	  POST /api/security/posture/settings   {"notify":true}   raise one notification when the score drops
	The read only token API serves GET /api/v1/security/posture (same body).
*/

var postureMonitorOnce sync.Once

// RegisterPostureAPIs registers the security overview APIs on the admin router
func RegisterPostureAPIs(authRouter *auth.RouterDef) {
	getPostureEngine()
	authRouter.HandleFunc("/api/security/posture", HandlePostureGet)
	authRouter.HandleFunc("/api/security/posture/preview", HandlePosturePreview)
	authRouter.HandleFunc("/api/security/posture/apply", HandlePostureApply)
	authRouter.HandleFunc("/api/security/posture/undo", HandlePostureUndo)
	authRouter.HandleFunc("/api/security/posture/settings", HandlePostureSettings)
	postureMonitorOnce.Do(func() { go postureMonitorLoop() })
}

func postureJSON(w http.ResponseWriter, v interface{}) {
	js, err := json.Marshal(v)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(js))
}

func postureActor(w http.ResponseWriter, r *http.Request) posture.Actor {
	name := "admin"
	if authAgent != nil {
		if n, err := authAgent.GetUserName(w, r); err == nil && n != "" {
			name = n
		}
	}
	return posture.Actor{Name: name, IP: callerIP(r)}
}

func postureBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		utils.SendErrorResponse(w, "invalid JSON body")
		return false
	}
	return true
}

type postureView struct {
	posture.Overview
	Settings struct {
		Notify bool `json:"notify"`
	} `json:"settings"`
	Role string `json:"role,omitempty"`
}

// HandlePostureGet returns the checks, the score and the available fixes. It never changes anything.
func HandlePostureGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	e := getPostureEngine()
	v := postureView{Overview: e.Overview(r.URL.Query().Get("refresh") == "1")}
	v.Settings.Notify = postureNotifyEnabled()
	if clusterMgr != nil {
		v.Role = clusterMgr.Role()
	}
	postureJSON(w, v)
}

// HandlePosturePreview lists the exact changes of the named actions. Nothing is changed.
func HandlePosturePreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Actions []string `json:"actions"`
	}
	if !postureBody(w, r, &req) {
		return
	}
	if len(req.Actions) == 0 {
		utils.SendErrorResponse(w, "no action selected")
		return
	}
	out, err := getPostureEngine().Preview(req.Actions)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	postureJSON(w, map[string]interface{}{"previews": out})
}

// HandlePostureApply applies the confirmed actions (each with the hash of its preview) and reports every result.
func HandlePostureApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Actions []posture.ApplyRequest `json:"actions"`
	}
	if !postureBody(w, r, &req) {
		return
	}
	if len(req.Actions) == 0 {
		utils.SendErrorResponse(w, "no action selected")
		return
	}
	res, err := getPostureEngine().Apply(req.Actions, postureActor(w, r))
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	postureJSON(w, map[string]interface{}{"results": res})
}

// HandlePostureUndo restores what an earlier apply replaced.
func HandlePostureUndo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
	}
	if !postureBody(w, r, &req) {
		return
	}
	res, err := getPostureEngine().Undo(req.Action, postureActor(w, r))
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	postureJSON(w, map[string]interface{}{"results": []posture.ActionResult{res}})
}

// HandlePostureSettings switches the "notify me when the score drops" option.
func HandlePostureSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Notify bool `json:"notify"`
	}
	if !postureBody(w, r, &req) {
		return
	}
	if err := sysdb.Write(postureTable, "notify", req.Notify); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	who := postureActor(w, r)
	if authAgent != nil {
		v := "off"
		if req.Notify {
			v = "on"
		}
		authAgent.Audit(who.Name, "posture.settings", "notify", who.IP, "notify on score drop: "+v)
	}
	if req.Notify { // start the comparison from the state now
		postureBaselineStore{}.Save(baselineOf(getPostureEngine().Overview(true).Report))
	}
	utils.SendOK(w)
}

func baselineOf(rep posture.Report) posture.Baseline {
	b := posture.Baseline{Score: rep.Score.Value}
	for _, c := range rep.Checks {
		if c.Status == posture.StatusFail {
			b.Failing = append(b.Failing, c.ID)
		}
	}
	return b
}

func emitPostureNotification(subject, detail string) {
	if notifyManager == nil {
		return
	}
	notifyManager.Emit(notify.Event{Event: notify.EventPosture, Source: "security", Subject: subject, Extra: map[string]string{"detail": detail}})
}

// postureMonitorLoop re-evaluates the posture every half hour while "notify" is enabled
func postureMonitorLoop() {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for range t.C {
		if sysdb == nil || !postureNotifyEnabled() {
			continue
		}
		postureMonitor.Observe(getPostureEngine().Overview(true).Report)
	}
}
