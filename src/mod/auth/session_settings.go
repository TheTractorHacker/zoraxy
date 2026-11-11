package auth

/*
	session_settings.go

	Admin login session lifetime (configurable), stored in sysdb table "settings", key "adminSession".

	Defaults are exactly the values that were hard coded before: 60 minutes, 7 days with "remember me",
	no sliding expiry. Nothing changes until an admin saves other values.

	The lifetime is stamped into the session ("exp", unix seconds) and checked on the server as well as
	being sent as the cookie Max-Age, so a copied cookie does not outlive the configured lifetime.
	Sessions that were issued before this feature have no "exp"; they keep the browser side expiry they got
	at login and are not touched.
*/

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

const (
	sessionSettingsTable = "settings"
	sessionSettingsKey   = "adminSession"

	SessionMinMinutes  = 5
	SessionMaxMinutes  = 43200 //30 days
	SessionMinRemember = 1
	SessionMaxRemember = 365

	//Upper bound of securecookie's own timestamp check. Its default (30 days) would silently reject
	//a "remember me" lifetime above that; the real lifetime is enforced by "exp" and the cookie Max-Age.
	sessionStoreMaxAge = (SessionMaxRemember + 1) * 24 * 3600

	sessionRefreshEvery = 5 * time.Minute //sliding expiry: re-issue the cookie at most this often
)

// SessionSettings is the admin session lifetime configuration
type SessionSettings struct {
	LifetimeMinutes int  //session lifetime without "remember me"
	RememberDays    int  //session lifetime with "remember me"
	SlidingExtend   bool //an active admin gets a fresh expiry (at most every few minutes)
}

// DefaultSessionSettings is the behaviour before this setting existed
func DefaultSessionSettings() SessionSettings {
	return SessionSettings{LifetimeMinutes: 60, RememberDays: 7, SlidingExtend: false}
}

// Validate checks the ranges (minutes 5..43200, remember days 1..365)
func (s SessionSettings) Validate() error {
	if s.LifetimeMinutes < SessionMinMinutes || s.LifetimeMinutes > SessionMaxMinutes {
		return fmt.Errorf("session lifetime must be between %d and %d minutes", SessionMinMinutes, SessionMaxMinutes)
	}
	if s.RememberDays < SessionMinRemember || s.RememberDays > SessionMaxRemember {
		return fmt.Errorf("remember me lifetime must be between %d and %d days", SessionMinRemember, SessionMaxRemember)
	}
	return nil
}

// Lifetime is the session lifetime for a login with or without "remember me"
func (s SessionSettings) Lifetime(remember bool) time.Duration {
	if remember {
		return time.Duration(s.RememberDays) * 24 * time.Hour
	}
	return time.Duration(s.LifetimeMinutes) * time.Minute
}

// refreshEvery is how old a session must be before sliding expiry re-issues it
func (s SessionSettings) refreshEvery(remember bool) time.Duration {
	d := s.Lifetime(remember) / 4
	if d > sessionRefreshEvery {
		d = sessionRefreshEvery
	}
	return d
}

// HumanDuration renders minutes the way an admin reads them ("1 hour", "2 days 3 hours")
func HumanDuration(minutes int) string {
	unit := func(n int, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.Itoa(n) + " " + one + "s"
	}
	d, h, m := minutes/1440, minutes%1440/60, minutes%60
	var parts []string
	if d > 0 {
		parts = append(parts, unit(d, "day"))
	}
	if h > 0 {
		parts = append(parts, unit(h, "hour"))
	}
	if m > 0 || len(parts) == 0 {
		parts = append(parts, unit(m, "minute"))
	}
	return strings.Join(parts, " ")
}

type sessionConf struct {
	mu sync.RWMutex
	s  SessionSettings
}

// loadSessionSettings reads the stored settings (defaults when absent or invalid)
func (a *AuthAgent) loadSessionSettings() {
	s := DefaultSessionSettings()
	var stored SessionSettings
	if a.Database != nil && a.Database.Read(sessionSettingsTable, sessionSettingsKey, &stored) == nil && stored.Validate() == nil {
		s = stored
	}
	a.sessConf.mu.Lock()
	a.sessConf.s = s
	a.sessConf.mu.Unlock()
}

// SessionSettings returns the settings applied to new logins
func (a *AuthAgent) SessionSettings() SessionSettings {
	a.sessConf.mu.RLock()
	defer a.sessConf.mu.RUnlock()
	return a.sessConf.s
}

// SetSessionSettings validates, stores and applies new settings. New logins use them at once, sessions
// that exist keep the expiry they were issued with (sliding expiry re-issues with the new lifetime).
func (a *AuthAgent) SetSessionSettings(s SessionSettings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := a.Database.Write(sessionSettingsTable, sessionSettingsKey, s); err != nil {
		return err
	}
	a.sessConf.mu.Lock()
	a.sessConf.s = s
	a.sessConf.mu.Unlock()
	return nil
}

func (a *AuthAgent) timeNow() time.Time {
	if a.nowFn != nil {
		return a.nowFn()
	}
	return time.Now()
}

// stampSession writes the expiry bookkeeping of a session issued (or re-issued) now and returns its cookie Max-Age
func (a *AuthAgent) stampSession(values map[interface{}]interface{}, remember bool) int {
	life := a.SessionSettings().Lifetime(remember)
	now := a.timeNow()
	values["iat"] = now.Unix()
	values["exp"] = now.Add(life).Unix()
	return int(life / time.Second)
}

// sessionExpired reports whether the server side expiry of a session has passed (false for sessions without one)
func (a *AuthAgent) sessionExpired(values map[interface{}]interface{}) bool {
	exp, ok := values["exp"].(int64)
	return ok && a.timeNow().Unix() >= exp
}

// RefreshSession implements the sliding expiry. Call it for a request that is user activity and passed
// the authentication check; it re-issues the cookie with a fresh expiry at most every few minutes.
// Without SlidingExtend, or for a session without an expiry stamp, it does nothing.
func (a *AuthAgent) RefreshSession(w http.ResponseWriter, r *http.Request) {
	set := a.SessionSettings()
	if !set.SlidingExtend {
		return
	}
	session, err := a.SessionStore.Get(r, a.SessionName)
	if err != nil || session.IsNew {
		return
	}
	if auth, _ := session.Values["authenticated"].(bool); !auth {
		return
	}
	iat, ok1 := session.Values["iat"].(int64)
	_, ok2 := session.Values["exp"].(int64)
	if !ok1 || !ok2 || a.sessionExpired(session.Values) {
		return
	}
	remember, _ := session.Values["rememberMe"].(bool)
	if a.timeNow().Sub(time.Unix(iat, 0)) < set.refreshEvery(remember) {
		return
	}
	session.Options = newSessionOptions(r, a.stampSession(session.Values, remember))
	session.Save(r, w)
}

// IsActivityRequest tells user activity from background polling: page and component loads and every
// change (non GET) count, GET requests of the API (what an open page polls) do not, so an idle
// browser tab does not keep a session alive forever.
func IsActivityRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	return !strings.HasPrefix(r.URL.Path, "/api/")
}

type sessionSettingsView struct {
	Settings       SessionSettings
	Defaults       SessionSettings
	LifetimeText   string //effective lifetime without "remember me"
	RememberText   string //effective lifetime with "remember me"
	MinMinutes     int
	MaxMinutes     int
	MinRememberDay int
	MaxRememberDay int
}

func (a *AuthAgent) sessionSettingsView() sessionSettingsView {
	s := a.SessionSettings()
	return sessionSettingsView{
		Settings: s, Defaults: DefaultSessionSettings(),
		LifetimeText: HumanDuration(s.LifetimeMinutes), RememberText: HumanDuration(s.RememberDays * 1440),
		MinMinutes: SessionMinMinutes, MaxMinutes: SessionMaxMinutes, MinRememberDay: SessionMinRemember, MaxRememberDay: SessionMaxRemember,
	}
}

// HandleSessionSettingsGet returns the settings (GET)
func (a *AuthAgent) HandleSessionSettingsGet(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(a.sessionSettingsView())
	utils.SendJSONResponse(w, string(js))
}

// HandleSessionSettingsSet stores new settings (POST minutes, days, sliding; admin only)
func (a *AuthAgent) HandleSessionSettingsSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	actor, ok := a.currentAdmin(w, r)
	if !ok {
		return
	}
	minutes, err := utils.PostInt(r, "minutes")
	if err != nil {
		utils.SendErrorResponse(w, "minutes must be a whole number")
		return
	}
	days, err := utils.PostInt(r, "days")
	if err != nil {
		utils.SendErrorResponse(w, "days must be a whole number")
		return
	}
	sliding, _ := utils.PostBool(r, "sliding")
	s := SessionSettings{LifetimeMinutes: minutes, RememberDays: days, SlidingExtend: sliding}
	if err := a.SetSessionSettings(s); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	a.Audit(actor, "session.settings", "", clientAddr(r),
		fmt.Sprintf("minutes=%d days=%d sliding=%v", s.LifetimeMinutes, s.RememberDays, s.SlidingExtend))
	utils.SendOK(w)
}
