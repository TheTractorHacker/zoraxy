package updater

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The handlers below are registered by the application behind its admin-auth
// router; the application wide CSRF middleware protects the POST endpoints.
// Mutations additionally insist on the POST method here.

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return false
	}
	return true
}

func actorOf(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	return "admin@" + h
}

func formBool(r *http.Request, key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(r.FormValue(key)))
	switch v {
	case "true", "1", "on", "yes":
		return true
	case "false", "0", "off", "no":
		return false
	}
	return def
}

// HandleInfo returns settings, preflight and the running version. It makes no
// network request.
func (m *Manager) HandleInfo(w http.ResponseWriter, r *http.Request) {
	var size int64
	m.cacheMu.Lock()
	if m.cacheRes != nil {
		size = m.cacheRes.AssetSize
	}
	m.cacheMu.Unlock()
	cur, _ := m.current()
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":  m.Settings(),
		"preflight": m.RunPreflight(size),
		"current":   cur,
		"repo":      m.cfg.Repo,
		"status":    m.Status(),
	})
}

// HandleCheck queries GitHub for the latest release on the selected channel.
func (m *Manager) HandleCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := m.Check(ctx, r.URL.Query().Get("force") == "true")
	if err != nil {
		var rl *RateLimitError
		if errors.As(err, &rl) {
			body := map[string]string{"error": rl.Error(), "code": "rate_limited"}
			if !rl.ResetAt.IsZero() {
				body["retry_at"] = rl.ResetAt.UTC().Format(time.RFC3339)
			}
			writeJSON(w, http.StatusTooManyRequests, body)
			return
		}
		writeErr(w, http.StatusBadGateway, "Update check failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "preflight": m.RunPreflight(res.AssetSize)})
}

// HandleStatus returns the pollable progress of the running / last operation.
func (m *Manager) HandleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.Status())
}

// HandleHistory returns the update history, newest first.
func (m *Manager) HandleHistory(w http.ResponseWriter, r *http.Request) {
	h := m.History()
	for i, j := 0, len(h)-1; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	if h == nil {
		h = []HistoryEntry{}
	}
	writeJSON(w, http.StatusOK, h)
}

// HandleStart starts "app" or "db" update. Params: action, backup, confirm=true.
func (m *Manager) HandleStart(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	if !formBool(r, "confirm", false) {
		writeErr(w, http.StatusBadRequest, "confirmation required")
		return
	}
	opts := RunOptions{Backup: formBool(r, "backup", m.Settings().BackupFirst), Actor: actorOf(r)}
	pf := m.RunPreflight(0)
	var err error
	switch r.FormValue("action") {
	case "app":
		if pf.AppBlocked != "" {
			writeErr(w, http.StatusConflict, pf.AppBlocked)
			return
		}
		err = m.StartApp(opts)
	case "db":
		if pf.DBBlocked != "" {
			writeErr(w, http.StatusConflict, pf.DBBlocked)
			return
		}
		err = m.StartDB(opts)
	default:
		writeErr(w, http.StatusBadRequest, "action must be app or db")
		return
	}
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

// HandleRollback restores the previous binary. Params: confirm=true.
func (m *Manager) HandleRollback(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	if !formBool(r, "confirm", false) {
		writeErr(w, http.StatusBadRequest, "confirmation required")
		return
	}
	pf := m.RunPreflight(0)
	if pf.Method == "docker" {
		writeErr(w, http.StatusConflict, "Rollback is disabled in Docker.")
		return
	}
	if !pf.RollbackOK {
		writeErr(w, http.StatusConflict, "There is no previous binary to roll back to.")
		return
	}
	if err := m.StartRollback(RunOptions{Actor: actorOf(r)}); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

// HandleSetChannel sets the channel (param: channel=stable|beta).
func (m *Manager) HandleSetChannel(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	if m.Busy() {
		writeErr(w, http.StatusConflict, errBusy.Error())
		return
	}
	if err := m.SetChannel(r.FormValue("channel")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m.Settings())
}

// HandleSetBackup sets the "back up first" default (param: enabled=true|false).
func (m *Manager) HandleSetBackup(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	v := strings.ToLower(r.FormValue("enabled"))
	if _, err := strconv.ParseBool(v); err != nil {
		writeErr(w, http.StatusBadRequest, "enabled must be true or false")
		return
	}
	if err := m.SetBackupFirst(formBool(r, "enabled", true)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m.Settings())
}

// HandleSetToken stores or removes the optional GitHub token (param: token; empty removes it).
// The token is never returned by any endpoint.
func (m *Manager) HandleSetToken(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	if err := m.SetGitHubToken(r.FormValue("token")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m.Settings())
}
