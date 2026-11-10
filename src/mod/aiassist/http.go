package aiassist

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

// EventLookup finds events by id.
type EventLookup interface {
	WAFEvent(txid string) (*waf.Event, bool)
	BlockEntry(seq uint64) (*blocklog.Entry, bool)
}

// Router is satisfied by the admin API router (session + CSRF are applied by it and by the
// CSRF middleware in front of the admin UI).
type Router interface {
	HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) error
}

// RegisterHandlers registers /api/ai/*. The handlers are cheap when the assistant is off.
func (s *Service) RegisterHandlers(rt Router) {
	_ = rt.HandleFunc("/api/ai/status", s.hStatus)
	_ = rt.HandleFunc("/api/ai/settings", s.hSettings)
	_ = rt.HandleFunc("/api/ai/settings/save", s.hSave)
	_ = rt.HandleFunc("/api/ai/test", s.hTest)
	_ = rt.HandleFunc("/api/ai/preview", s.hPreview)
	_ = rt.HandleFunc("/api/ai/preview/ack", s.hAck)
	_ = rt.HandleFunc("/api/ai/explain", s.hExplain)
	_ = rt.HandleFunc("/api/ai/suggest", s.hSuggest)
	_ = rt.HandleFunc("/api/ai/rule", s.hRule)
	_ = rt.HandleFunc("/api/ai/audit", s.hAudit)
}

func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeErr(w, errors.New("internal error"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	w.Write(b)
}

func needPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		writeErr(w, errors.New("Method not supported"))
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	return true
}

func (s *Service) hStatus(w http.ResponseWriter, r *http.Request) {
	st := s.store.Load()
	writeJSON(w, map[string]any{"enabled": st.Enabled, "explain": st.Enabled && st.FeatureExplain,
		"suggest": st.Enabled && st.FeatureSuggest, "audit": st.Enabled && st.FeatureAudit && s.AuditAvailable(), "audit_available": s.AuditAvailable()})
}

func (s *Service) hSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"settings": s.View(), "usage": s.Usage(), "audit_available": s.AuditAvailable(),
		"defaults": map[string]any{"anthropic_endpoint": DefaultAnthropicEndpoint, "anthropic_model": DefaultAnthropicModel}})
}

func (s *Service) hSave(w http.ResponseWriter, r *http.Request) {
	if !needPost(w, r) {
		return
	}
	var in SettingsUpdate
	dec := json.NewDecoder(strings.NewReader(r.PostFormValue("settings")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeErr(w, errors.New("invalid settings"))
		return
	}
	v, err := s.Save(in)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"settings": v, "usage": s.Usage()})
}

func (s *Service) hTest(w http.ResponseWriter, r *http.Request) {
	if !needPost(w, r) {
		return
	}
	msg, err := s.Test(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": msg, "usage": s.Usage()})
}

func (s *Service) eventFromRequest(r *http.Request) (EventInput, error) {
	if s.deps.Events == nil {
		return EventInput{}, errors.New("events are not available")
	}
	id := strings.TrimSpace(r.PostFormValue("id"))
	switch r.PostFormValue("kind") {
	case "waf":
		if e, ok := s.deps.Events.WAFEvent(id); ok {
			return EventInput{WAF: e}, nil
		}
	case "blocked":
		if n, err := strconv.ParseUint(id, 10, 64); err == nil {
			if e, ok := s.deps.Events.BlockEntry(n); ok {
				return EventInput{Block: e}, nil
			}
		}
	default:
		return EventInput{}, errors.New("unknown event kind")
	}
	return EventInput{}, errors.New("event not found (it may have been rotated out of the log)")
}

func (s *Service) hPreview(w http.ResponseWriter, r *http.Request) {
	if !needPost(w, r) {
		return
	}
	var pv *PreviewView
	var err error
	switch r.PostFormValue("feature") {
	case FeatureExplain:
		var in EventInput
		if in, err = s.eventFromRequest(r); err == nil {
			pv, err = s.PreviewExplain(in)
		}
	case FeatureSuggest:
		pv, err = s.PreviewSuggest()
	case featureRule:
		pv, err = s.PreviewRule(r.PostFormValue("text"))
	case FeatureAudit:
		pv, err = s.PreviewAudit()
	default:
		err = errors.New("unknown feature")
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, pv)
}

func (s *Service) hAck(w http.ResponseWriter, r *http.Request) {
	if !needPost(w, r) {
		return
	}
	if err := s.Ack(r.PostFormValue("feature")); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Service) hExplain(w http.ResponseWriter, r *http.Request) {
	if !needPost(w, r) {
		return
	}
	in, err := s.eventFromRequest(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	out, err := s.Explain(r.Context(), in)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Service) hSuggest(w http.ResponseWriter, r *http.Request) {
	if !needPost(w, r) {
		return
	}
	p, err := s.Suggest(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"proposals": p, "appliable": ValidateProposal != nil})
}

func (s *Service) hRule(w http.ResponseWriter, r *http.Request) {
	if !needPost(w, r) {
		return
	}
	p, err := s.RuleFromText(r.Context(), r.PostFormValue("text"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"proposals": []Proposal{*p}, "appliable": ValidateProposal != nil})
}

func (s *Service) hAudit(w http.ResponseWriter, r *http.Request) {
	if !needPost(w, r) {
		return
	}
	p, err := s.Audit(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, p)
}
