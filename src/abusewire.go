package main

import (
	"net/http"
	"net/netip"
	"sync"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/netutils"
)

/*
	abusewire.go

	Wires the automatic abuse banning engine (mod/abuse, "fail2ban built in")
	into the system. Disabled until enabled in Access > Auto-ban.
*/

var (
	abuseManager *abuse.Manager
	abuseOnce    sync.Once
)

// getAbuseManager lazily creates and loads the engine (config in <conf>/abuse/)
func getAbuseManager() *abuse.Manager {
	abuseOnce.Do(func() {
		m := abuse.New(CONF_FOLDER + "/abuse")
		if err := m.Load(); err != nil && SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("abuse", "Unable to load abuse ban config, starting disabled", err)
		}
		//Never ban this server or the configured trusted proxies (CDN / upstream load balancers)
		m.Protect = func(a netip.Addr) bool {
			if accessController == nil {
				return false
			}
			s := a.String()
			return s == accessController.ServerPublicIP || accessController.IsTrustedProxy(s)
		}
		m.Start()
		abuseManager = m
	})
	return abuseManager
}

func stopAbuseManager() {
	if abuseManager != nil {
		abuseManager.Stop()
	}
}

// RegisterAbuseAPIs registers the admin (session + CSRF) APIs of the auto-ban list
func RegisterAbuseAPIs(authRouter *auth.RouterDef) {
	m := getAbuseManager()
	authRouter.HandleFunc("/api/abuse/list", m.HandleList)
	authRouter.HandleFunc("/api/abuse/config", m.HandleGetConfig)
	authRouter.HandleFunc("/api/abuse/setConfig", m.HandleSetConfig)
	authRouter.HandleFunc("/api/abuse/ban", m.HandleBan)
	authRouter.HandleFunc("/api/abuse/unban", m.HandleUnban)
	authRouter.HandleFunc("/api/abuse/token", m.HandleToken)
}

// registerAbuseRemoteAPI mounts the token authenticated API (outside CSRF, bearer token only)
func registerAbuseRemoteAPI(mux *http.ServeMux) {
	m := getAbuseManager()
	mux.HandleFunc("/api/abuse/remote/ban", m.HandleRemote("ban"))
	mux.HandleFunc("/api/abuse/remote/unban", m.HandleRemote("unban"))
	mux.HandleFunc("/api/abuse/remote/list", m.HandleRemote("list"))
}

// abuseLoginGuard / abuseLoginFailed connect the admin login to the engine
func abuseLoginGuard(r *http.Request) bool {
	m := getAbuseManager()
	if !m.Active() {
		return true
	}
	_, banned := m.IsBanned(netutils.GetRequesterIPUntrusted(r), "")
	return !banned
}

func abuseLoginFailed(r *http.Request, username string) {
	getAbuseManager().Report(netutils.GetRequesterIPUntrusted(r), "", abuse.KindLoginFail, "")
}
