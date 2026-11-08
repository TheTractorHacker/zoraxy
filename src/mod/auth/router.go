package auth

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
)

type RouterOption struct {
	AuthAgent     *AuthAgent
	RequireAuth   bool                                     //This router require authentication
	DeniedHandler func(http.ResponseWriter, *http.Request) //Things to do when request is rejected
	TargetMux     *http.ServeMux
}

type RouterDef struct {
	option    RouterOption
	endpoints map[string]func(http.ResponseWriter, *http.Request)
}

func NewManagedHTTPRouter(option RouterOption) *RouterDef {
	return &RouterDef{
		option:    option,
		endpoints: map[string]func(http.ResponseWriter, *http.Request){},
	}
}

/*
Viewer role enforcement.

A "viewer" account is read-only: every method other than GET / HEAD / OPTIONS is refused,
except the POST endpoints below that only read data. A few GET endpoints expose secrets or
a shell-like capability and are admin-only as well. The allow-list is explicit: anything new
is refused for viewers until it is added here on purpose.
*/
var viewerReadOnlyPOST = map[string]bool{}

var viewerDeniedPrefixes = []string{
	"/api/conf/export",   //full configuration including secrets
	"/api/info/pprof",    //heap / goroutine dumps
	"/api/users/",        //account management
	"/api/abuse/config",  //auto-ban settings
	"/api/ech/export",    //ECH private key
	"/api/proxy/script/", //Lua script source (may hold secrets); editing is admin only
	"/web.ssh/",          //terminal
	"/plugin.ui/",        //plugin UIs can mutate
}

func isMutatingMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// ViewerAllowed reports whether a viewer may perform a request
func ViewerAllowed(method, path string) bool {
	for _, p := range viewerDeniedPrefixes {
		if len(path) >= len(p) && path[:len(p)] == p || path+"/" == p {
			return false
		}
	}
	if isMutatingMethod(method) {
		return viewerReadOnlyPOST[path]
	}
	return true
}

// RoleGuard refuses the request (and returns false) when the logged-in account is a
// viewer and the request is not allowed for viewers.
func (a *AuthAgent) RoleGuard(w http.ResponseWriter, r *http.Request) bool {
	if a.RequestRole(r) == RoleViewer && !ViewerAllowed(r.Method, r.URL.Path) {
		http.Error(w, "403 - Read-only account (viewer role)", http.StatusForbidden)
		return false
	}
	return true
}

// Endpoints lists the registered endpoint paths (used by tests / audits)
func (router *RouterDef) Endpoints() []string {
	out := make([]string, 0, len(router.endpoints))
	for e := range router.endpoints {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func (router *RouterDef) HandleFunc(endpoint string, handler func(http.ResponseWriter, *http.Request)) error {
	//Check if the endpoint already registered
	if _, exist := router.endpoints[endpoint]; exist {
		fmt.Println("WARNING! Duplicated registering of web endpoint: " + endpoint)
		return errors.New("endpoint register duplicated")
	}

	authAgent := router.option.AuthAgent

	wrapped := func(w http.ResponseWriter, r *http.Request) {
		//Check authentication of the user
		if router.option.RequireAuth {
			authAgent.HandleCheckAuth(w, r, func(w http.ResponseWriter, r *http.Request) {
				if !authAgent.RoleGuard(w, r) {
					return
				}
				handler(w, r)
			})
		} else {
			handler(w, r)
		}
	}

	//OK. Register handler
	if router.option.TargetMux == nil {
		http.HandleFunc(endpoint, wrapped)
	} else {
		router.option.TargetMux.HandleFunc(endpoint, wrapped)
	}

	router.endpoints[endpoint] = handler

	return nil
}
