package abuse

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	Admin API (behind the managed router, session + CSRF) and the remote API
	for external tools (fail2ban actions, scripts, #898). The remote API is
	disabled until an admin generates a token; it only accepts POST with
	"Authorization: Bearer <token>" and can only ban / unban / list.
*/

type listResponse struct {
	Active bool
	Bans   []Ban
}

// HandleList returns the active bans (GET)
func (m *Manager) HandleList(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(listResponse{Active: m.Active(), Bans: m.List()})
	utils.SendJSONResponse(w, string(js))
}

// HandleGetConfig returns the configuration (GET). The token hash is never returned.
func (m *Manager) HandleGetConfig(w http.ResponseWriter, r *http.Request) {
	c := m.Config()
	hasToken := c.RemoteTokenHash != ""
	c.RemoteTokenHash = ""
	js, _ := json.Marshal(struct {
		Config
		RemoteTokenSet bool
		AllKinds       []Kind
	}{c, hasToken, AllKinds})
	utils.SendJSONResponse(w, string(js))
}

// HandleSetConfig replaces the configuration from a JSON body in the "config" field (POST)
func (m *Manager) HandleSetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	cur := m.Config()
	next := DefaultConfig()
	if err := json.Unmarshal([]byte(raw), &next); err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	next.RemoteTokenHash = cur.RemoteTokenHash //only changed by HandleToken
	if err := m.SetConfig(next); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleBan bans an address (POST ip, optional seconds, reason, scope)
func (m *Manager) HandleBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m.doBan(w, r, "manual")
}

// HandleUnban removes a ban (POST ip, optional scope)
func (m *Manager) HandleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m.doUnban(w, r)
}

func (m *Manager) doBan(w http.ResponseWriter, r *http.Request, source string) {
	ip, _ := utils.PostPara(r, "ip")
	reason, _ := utils.PostPara(r, "reason")
	scope, _ := utils.PostPara(r, "scope")
	var secs int64
	if s, _ := utils.PostPara(r, "seconds"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			utils.SendErrorResponse(w, "invalid seconds")
			return
		}
		secs = v
	}
	if reason == "" {
		reason = source + " ban"
	}
	b, err := m.ManualBan(ip, scope, reason, source, secs)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	m.Flush()
	js, _ := json.Marshal(b)
	utils.SendJSONResponse(w, string(js))
}

func (m *Manager) doUnban(w http.ResponseWriter, r *http.Request) {
	ip, _ := utils.PostPara(r, "ip")
	scope, _ := utils.PostPara(r, "scope")
	if !m.Unban(ip, scope) {
		utils.SendErrorResponse(w, "no such ban")
		return
	}
	m.Flush()
	utils.SendOK(w)
}

// HandleToken generates (POST action=generate) or revokes (action=revoke) the remote API token.
// The token is returned once and only its SHA-256 is stored.
func (m *Manager) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	action, _ := utils.PostPara(r, "action")
	c := m.Config()
	switch action {
	case "generate":
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			utils.SendErrorResponse(w, "no entropy")
			return
		}
		tok := hex.EncodeToString(buf)
		c.RemoteTokenHash = hashToken(tok)
		if err := m.SetConfig(c); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		js, _ := json.Marshal(map[string]string{"token": tok})
		utils.SendJSONResponse(w, string(js))
	case "revoke":
		c.RemoteTokenHash = ""
		if err := m.SetConfig(c); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		utils.SendOK(w)
	default:
		utils.SendErrorResponse(w, "action must be generate or revoke")
	}
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

// TokenValid compares a presented token in constant time
func (m *Manager) TokenValid(presented string) bool {
	want := m.cfg.Load().RemoteTokenHash
	if want == "" || presented == "" {
		return false
	}
	got := hashToken(presented)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// HandleRemote is the token authenticated API: POST /api/abuse/remote/{ban,unban,list}
// (list also accepts GET). No session, no CSRF: the bearer token is the credential.
func (m *Manager) HandleRemote(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		tok := ""
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
		if !m.TokenValid(tok) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "401 - Unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		switch action {
		case "list":
			m.HandleList(w, r)
		case "ban":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			m.doBan(w, r, "remote")
		case "unban":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			m.doUnban(w, r)
		}
	}
}
