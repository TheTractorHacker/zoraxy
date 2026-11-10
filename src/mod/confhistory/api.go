package confhistory

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// APIPrefix is the admin API prefix (the capture middleware skips it).
const APIPrefix = "/api/history/"

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}

func needMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		jsonErr(w, http.StatusMethodNotAllowed, "use "+method)
		return false
	}
	return true
}

func formBool(r *http.Request, k string) bool {
	switch strings.ToLower(strings.TrimSpace(r.FormValue(k))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func formID(r *http.Request, k string) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue(k)), 10, 64)
	return id, err == nil && id > 0
}

func parseTime(s string, endOfDay bool) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		if endOfDay {
			t = t.Add(24*time.Hour - time.Second)
		}
		return t.Unix()
	}
	return 0
}

func (m *Manager) actorOf(r *http.Request) string {
	if m.opt.Actor != nil {
		if a := m.opt.Actor(r); a != "" {
			return a
		}
	}
	return "admin"
}

// HandleList: GET /api/history/list
func (m *Manager) HandleList(w http.ResponseWriter, r *http.Request) {
	if !needMethod(w, r, http.MethodGet) {
		return
	}
	page, _ := strconv.Atoi(r.FormValue("page"))
	size, _ := strconv.Atoi(r.FormValue("pageSize"))
	res, err := m.List(Filter{
		Object: strings.TrimSpace(r.FormValue("object")), Actor: strings.TrimSpace(r.FormValue("actor")),
		From: parseTime(r.FormValue("from"), false), To: parseTime(r.FormValue("to"), true), Page: page, PageSize: size,
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{
		"items": res.Items, "total": res.Total, "totalAll": m.Count(), "page": res.Page, "pageSize": res.PageSize,
		"settings": m.Settings(), "areas": m.reg.Areas(), "lastRestore": m.LastRestore(),
		"restorePending": m.pendingInfo(), "storeBytes": m.StoreBytes(), "latest": m.Latest(),
		"healthyAfterSeconds": int(m.opt.HealthyAfter.Seconds()),
	})
}

func (m *Manager) pendingInfo() any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.readPending(); p != nil {
		return map[string]any{"from": p.From, "pre": p.Pre, "phase": p.Phase, "scope": p.Scope}
	}
	return nil
}

// HandleGet: GET /api/history/get?id=
func (m *Manager) HandleGet(w http.ResponseWriter, r *http.Request) {
	if !needMethod(w, r, http.MethodGet) {
		return
	}
	id, ok := formID(r, "id")
	if !ok {
		jsonErr(w, http.StatusBadRequest, "id required")
		return
	}
	meta, err := m.Get(id)
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"version": meta, "previous": m.Previous(id)})
}

// DiffExport is the downloadable, masked comparison of two versions.
type DiffExport struct {
	Format string     `json:"format"`
	From   int64      `json:"from"`
	To     int64      `json:"to"`
	Note   string     `json:"note"`
	Files  []FileDiff `json:"files"`
}

// HandleDiff: GET /api/history/diff?from=&to=[&download=1]. Without from the
// predecessor of to is used.
func (m *Manager) HandleDiff(w http.ResponseWriter, r *http.Request) {
	if !needMethod(w, r, http.MethodGet) {
		return
	}
	to, ok := formID(r, "to")
	if !ok {
		to, ok = formID(r, "id")
	}
	if !ok {
		jsonErr(w, http.StatusBadRequest, "to (version id) required")
		return
	}
	var from int64
	if strings.TrimSpace(r.FormValue("from")) != "" {
		if from, ok = formID(r, "from"); !ok && strings.TrimSpace(r.FormValue("from")) != "0" {
			jsonErr(w, http.StatusBadRequest, "invalid from")
			return
		}
	} else {
		from = m.Previous(to)
	}
	files, err := m.Diff(from, to)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "does not exist") {
			code = http.StatusNotFound
		}
		jsonErr(w, code, err.Error())
		return
	}
	if files == nil {
		files = []FileDiff{}
	}
	out := DiffExport{Format: "zoraxy-history-diff", From: from, To: to,
		Note: "Secret values are masked. This export contains no restorable data.", Files: files}
	if formBool(r, "download") {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="zoraxy-history-diff-%d-%d.json"`, from, to))
	}
	jsonOut(w, http.StatusOK, out)
}

// HandleRestore: POST /api/history/restore (id, scope, dryrun, confirm)
func (m *Manager) HandleRestore(w http.ResponseWriter, r *http.Request) {
	if !needMethod(w, r, http.MethodPost) {
		return
	}
	id, ok := formID(r, "id")
	if !ok {
		jsonErr(w, http.StatusBadRequest, "id required")
		return
	}
	res, err := m.Restore(RestoreRequest{ID: id, Scope: r.FormValue("scope"), DryRun: formBool(r, "dryrun"),
		Actor: m.actorOf(r), Confirm: r.FormValue("confirm")})
	if err != nil {
		code := http.StatusConflict
		switch {
		case res == nil:
			code = http.StatusBadRequest
			if strings.Contains(err.Error(), "does not exist") {
				code = http.StatusNotFound
			}
		case errors.Is(err, ErrNothingToRestore):
			code = http.StatusConflict
		}
		body := map[string]any{"error": err.Error()}
		if res != nil {
			body["plan"] = res
		}
		jsonOut(w, code, body)
		return
	}
	jsonOut(w, http.StatusOK, res)
}

// HandleSettings: GET returns, POST changes the retention settings.
func (m *Manager) HandleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		jsonOut(w, http.StatusOK, m.Settings())
		return
	}
	if !needMethod(w, r, http.MethodPost) {
		return
	}
	s := m.Settings()
	atoi := func(k string, dst *int) bool {
		if v := strings.TrimSpace(r.FormValue(k)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				jsonErr(w, http.StatusBadRequest, k+" must be a number")
				return false
			}
			*dst = n
		}
		return true
	}
	if !atoi("keepCount", &s.KeepCount) || !atoi("keepDays", &s.KeepDays) || !atoi("maxMiB", &s.MaxMiB) {
		return
	}
	if v := r.FormValue("enabled"); v != "" {
		s.Enabled = formBool(r, "enabled")
	}
	if err := m.SetSettings(s); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOut(w, http.StatusOK, m.Settings())
}

// HandleSnapshot: POST /api/history/snapshot (note) takes a manual version.
func (m *Manager) HandleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !needMethod(w, r, http.MethodPost) {
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	sum := "Manual snapshot"
	if note != "" {
		sum += ": " + note
	}
	meta, created, err := m.Capture(CaptureInfo{Actor: m.actorOf(r), Trigger: "manual", Summary: sum})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"version": meta, "created": created})
}

// Register adds every history endpoint with the given registrar (for example
// authRouter.HandleFunc).
func (m *Manager) Register(handle func(string, func(http.ResponseWriter, *http.Request)) error) {
	handle(APIPrefix+"list", m.HandleList)
	handle(APIPrefix+"get", m.HandleGet)
	handle(APIPrefix+"diff", m.HandleDiff)
	handle(APIPrefix+"restore", m.HandleRestore)
	handle(APIPrefix+"settings", m.HandleSettings)
	handle(APIPrefix+"snapshot", m.HandleSnapshot)
}
