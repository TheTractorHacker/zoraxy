package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Basic auth extensions (upstream #621 #1006), see mod/dynamicproxy/basicauth_ext.go
	  GET  /api/basicauth/lists/get            all lists: usernames only (never hashes) and the proxy rules using them
	  POST /api/basicauth/lists/set            name, users (JSON [{Username, Password}], empty Password keeps the stored hash)
	  POST /api/basicauth/lists/delete         name (refused while a proxy rule still uses it)
	  GET  /api/basicauth/endpoint?ep=         assigned lists and scope prefixes of a proxy rule
	  POST /api/basicauth/endpoint             ep, lists (JSON array), scope (JSON array of path prefixes)
*/

var (
	credLists     *dynamicproxy.CredentialLists
	credListsOnce sync.Once
)

func getCredentialLists() *dynamicproxy.CredentialLists {
	credListsOnce.Do(func() {
		l, err := dynamicproxy.NewCredentialLists(CONF_FOLDER + "/basicauth_lists.json")
		if err != nil {
			if SystemWideLogger != nil {
				SystemWideLogger.PrintAndLog("basic-auth", "Unable to load credential lists, starting with none", err)
			}
			l, _ = dynamicproxy.NewCredentialLists("")
		}
		credLists = l
	})
	return credLists
}

func RegisterBasicAuthExtAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/basicauth/lists/get", HandleCredListsGet)
	authRouter.HandleFunc("/api/basicauth/lists/set", HandleCredListsSet)
	authRouter.HandleFunc("/api/basicauth/lists/delete", HandleCredListsDelete)
	authRouter.HandleFunc("/api/basicauth/endpoint", HandleBasicAuthEndpoint)
}

func credListUsage() map[string][]string {
	used := map[string][]string{}
	if dynamicProxyRouter == nil {
		return used
	}
	for name, ep := range dynamicProxyRouter.GetProxyEndpointsAsMap() {
		if ep.AuthenticationProvider == nil {
			continue
		}
		for _, ln := range ep.AuthenticationProvider.BasicAuthListNames {
			used[ln] = append(used[ln], name)
		}
	}
	return used
}

func HandleCredListsGet(w http.ResponseWriter, r *http.Request) {
	type item struct {
		Name   string
		Users  []string
		UsedBy []string
	}
	used := credListUsage()
	out := []item{}
	for _, n := range getCredentialLists().Names() {
		u := getCredentialLists().Usernames(n)
		if u == nil {
			u = []string{}
		}
		ub := used[n]
		if ub == nil {
			ub = []string{}
		}
		out = append(out, item{n, u, ub})
	}
	js, _ := json.Marshal(out)
	utils.SendJSONResponse(w, string(js))
}

func HandleCredListsSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	name, err := utils.PostPara(r, "name")
	if err != nil {
		utils.SendErrorResponse(w, "name missing")
		return
	}
	raw, err := utils.PostPara(r, "users")
	if err != nil {
		utils.SendErrorResponse(w, "users missing")
		return
	}
	var users []*dynamicproxy.BasicAuthUnhashedCredentials
	if err := json.Unmarshal([]byte(raw), &users); err != nil {
		utils.SendErrorResponse(w, "users must be a JSON array")
		return
	}
	if err := getCredentialLists().Set(name, users, func(p string) string {
		return auth.HashPasswordWithProfile(p, auth.ProfileBasicAuth)
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleCredListsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	name, err := utils.PostPara(r, "name")
	if err != nil {
		utils.SendErrorResponse(w, "name missing")
		return
	}
	if ub := credListUsage()[name]; len(ub) > 0 {
		utils.SendErrorResponse(w, "list is still used by: "+strings.Join(ub, ", "))
		return
	}
	if err := getCredentialLists().Delete(name); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleBasicAuthEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		ep, err := utils.GetPara(r, "ep")
		if err != nil {
			utils.SendErrorResponse(w, "Target proxy rule not defined")
			return
		}
		target, err := dynamicProxyRouter.LoadProxy(ep)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		lists, scope := []string{}, []string{}
		if target.AuthenticationProvider != nil {
			lists = append(lists, target.AuthenticationProvider.BasicAuthListNames...)
			scope = append(scope, target.AuthenticationProvider.BasicAuthScopePrefixes...)
		}
		js, _ := json.Marshal(map[string]interface{}{"Lists": lists, "Scope": scope})
		utils.SendJSONResponse(w, string(js))
		return
	}
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	var lists, scope []string
	if raw, err := utils.PostPara(r, "lists"); err == nil && json.Unmarshal([]byte(raw), &lists) != nil {
		utils.SendErrorResponse(w, "lists must be a JSON array")
		return
	}
	if raw, err := utils.PostPara(r, "scope"); err == nil && json.Unmarshal([]byte(raw), &scope) != nil {
		utils.SendErrorResponse(w, "scope must be a JSON array")
		return
	}
	if err := dynamicproxy.ValidateBasicAuthExtras(scope, lists, getCredentialLists()); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		if e.AuthenticationProvider == nil {
			e.AuthenticationProvider = &dynamicproxy.AuthenticationProvider{}
		}
		e.AuthenticationProvider.BasicAuthListNames = lists
		e.AuthenticationProvider.BasicAuthScopePrefixes = scope
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
