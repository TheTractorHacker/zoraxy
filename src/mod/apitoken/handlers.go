package apitoken

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Management handlers. Register them on the cookie authenticated admin router
// (CSRF protected); they must never be reachable with a Bearer token.

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// HandleList returns every token without secrets.
func (m *Manager) HandleList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, m.List())
}

// HandleCreate (POST): name, scope, expires (unix seconds, optional), cidrs
// (comma or newline separated, optional). The response carries the clear
// text token exactly once.
func (m *Manager) HandleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid form")
		return
	}
	var expires int64
	if s := strings.TrimSpace(r.Form.Get("expires")); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			writeErr(w, http.StatusBadRequest, "invalid expiry")
			return
		}
		expires = v
	}
	cidrs := strings.FieldsFunc(r.Form.Get("cidrs"), func(c rune) bool {
		return c == ',' || c == '\n' || c == '\r' || c == ' '
	})
	tok, info, err := m.Create(r.Form.Get("name"), r.Form.Get("scope"), expires, cidrs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]interface{}{"token": tok, "info": info})
}

// HandleRevoke (POST): id
func (m *Manager) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := m.Revoke(r.FormValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, "OK")
}

// HandleDelete (POST): id. Removes the record entirely.
func (m *Manager) HandleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := m.Delete(r.FormValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, "OK")
}
