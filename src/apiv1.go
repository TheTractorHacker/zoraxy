package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"imuslab.com/zoraxy/mod/apitoken"
	"imuslab.com/zoraxy/mod/auth"
)

/*
	apiv1.go

	Stable REST API (/api/v1/...) authenticated with Bearer API tokens, see
	mod/apitoken and web/openapi.yaml.

	Design rules:
	  - /api/v1/ is mounted on the entry mux, OUTSIDE the cookie + CSRF stack.
	    Token auth is only ever evaluated for this prefix.
	  - Every route is a thin wrapper that translates JSON into the form
	    parameters of the existing admin handler and runs that handler (through
	    the cluster edit guard, using the legacy /api path).
	  - Token management (/api/apitoken/*) is registered on the normal admin
	    router: cookie session + CSRF, never reachable with a token.
*/

//go:embed web/openapi.yaml
var apiV1OpenAPI []byte

//go:embed web/apidocs.html
var apiV1DocsPage []byte

const apiV1Prefix = "/api/v1/"

var apiTokenManager *apitoken.Manager

// RegisterAPIv1 sets up the token manager and registers the token management
// endpoints on the cookie authenticated admin router.
func RegisterAPIv1(authRouter *auth.RouterDef) {
	mgr, err := apitoken.NewManager(sysdb, SystemWideLogger)
	if err != nil {
		SystemWideLogger.PrintAndLog("apitoken", "Unable to initialise API tokens, REST API disabled", err)
		return
	}
	apiTokenManager = mgr
	authRouter.HandleFunc("/api/apitoken/list", mgr.HandleList)
	authRouter.HandleFunc("/api/apitoken/create", mgr.HandleCreate)
	authRouter.HandleFunc("/api/apitoken/revoke", mgr.HandleRevoke)
	authRouter.HandleFunc("/api/apitoken/delete", mgr.HandleDelete)
}

// mountAPIv1 mounts the /api/v1/ tree on the management entry mux.
func mountAPIv1(entry *http.ServeMux) {
	if apiTokenManager == nil {
		return
	}
	entry.Handle(apiV1Prefix, newAPIv1Handler(apiTokenManager, defaultV1Backend(), clusterGuard))
}

func clusterGuard(next http.Handler) http.Handler {
	if clusterMgr == nil {
		return next
	}
	return clusterMgr.GuardLocalEdits(next)
}

// v1Backend are the existing admin handlers the v1 API wraps.
type v1Backend struct {
	ProxyList, ProxyAdd, ProxyEdit, ProxyDelete, ProxyToggle http.HandlerFunc
	AccessList, RedirectList, CertList, StatsSummary, WAF    http.HandlerFunc
	StatsBlocked                                             http.HandlerFunc
}

func defaultV1Backend() v1Backend {
	return v1Backend{
		ProxyList:    func(w http.ResponseWriter, r *http.Request) { ReverseProxyList(w, r) },
		ProxyAdd:     func(w http.ResponseWriter, r *http.Request) { ReverseProxyHandleAddEndpoint(w, r) },
		ProxyEdit:    func(w http.ResponseWriter, r *http.Request) { ReverseProxyHandleEditEndpoint(w, r) },
		ProxyDelete:  func(w http.ResponseWriter, r *http.Request) { DeleteProxyEndpoint(w, r) },
		ProxyToggle:  func(w http.ResponseWriter, r *http.Request) { ReverseProxyToggleRuleSet(w, r) },
		AccessList:   func(w http.ResponseWriter, r *http.Request) { handleListAccessRules(w, r) },
		RedirectList: func(w http.ResponseWriter, r *http.Request) { handleListRedirectionRules(w, r) },
		CertList:     func(w http.ResponseWriter, r *http.Request) { tlsCertManager.HandleListCertificate(w, r) },
		StatsSummary: func(w http.ResponseWriter, r *http.Request) { statisticCollector.HandleTodayStatLoad(w, r) },
		WAF:          func(w http.ResponseWriter, r *http.Request) { HandleWAFCoverage(w, r) },
		StatsBlocked: func(w http.ResponseWriter, r *http.Request) { HandleBlockedOverview(w, r) },
	}
}

func jsonOut(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// bodyToForm converts a flat JSON object into the form values the legacy
// handlers expect. Scalars are stringified, arrays are comma joined and nested
// objects are passed as JSON text.
func bodyToForm(r *http.Request) (url.Values, error) {
	form := url.Values{}
	if r.Body == nil {
		return form, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, fmt.Errorf("request body too large")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return form, nil
	}
	var obj map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("body must be a JSON object")
	}
	for k, v := range obj {
		switch t := v.(type) {
		case nil:
		case string:
			form.Set(k, t)
		case bool:
			form.Set(k, fmt.Sprint(t))
		case json.Number:
			form.Set(k, t.String())
		case []interface{}:
			parts := []string{}
			for _, e := range t {
				parts = append(parts, fmt.Sprint(e))
			}
			form.Set(k, strings.Join(parts, ","))
		default:
			b, _ := json.Marshal(t)
			form.Set(k, string(b))
		}
	}
	return form, nil
}

// runLegacy runs an existing admin handler with the given form values as if
// the admin UI had called legacyPath, then maps the {"error":..} convention
// to HTTP status codes.
func runLegacy(w http.ResponseWriter, r *http.Request, guard func(http.Handler) http.Handler, legacyPath string,
	h http.HandlerFunc, read bool, form url.Values, okStatus int) {
	var inner *http.Request
	if read {
		u := *r.URL
		u.Path = legacyPath
		u.RawQuery = form.Encode()
		inner = httptest.NewRequest(http.MethodGet, u.String(), nil)
	} else {
		inner = httptest.NewRequest(http.MethodPost, legacyPath, strings.NewReader(form.Encode()))
		inner.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	inner.RemoteAddr = r.RemoteAddr
	inner = inner.WithContext(r.Context())
	rec := httptest.NewRecorder()
	guard(h).ServeHTTP(rec, inner)

	body := rec.Body.Bytes()
	code := rec.Code
	var errObj struct {
		Error string `json:"error"`
	}
	if code == http.StatusOK && json.Unmarshal(body, &errObj) == nil && errObj.Error != "" {
		code = http.StatusBadRequest
		if strings.Contains(strings.ToLower(errObj.Error), "not found") {
			code = http.StatusNotFound
		}
	} else if code == http.StatusOK {
		code = okStatus
	}
	if ct := rec.Header().Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(code)
	w.Write(body)
}

type v1Route struct {
	Pattern string // "METHOD /path/{param}"
	Handler http.HandlerFunc
}

func v1Routes(b v1Backend, guard func(http.Handler) http.Handler) []v1Route {
	read := func(legacyPath string, h http.HandlerFunc, defaults url.Values) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			form := url.Values{}
			for k, v := range defaults {
				form[k] = v
			}
			for k, v := range r.URL.Query() {
				form[k] = v
			}
			runLegacy(w, r, guard, legacyPath, h, true, form, http.StatusOK)
		}
	}
	write := func(legacyPath string, h http.HandlerFunc, ok int, inject func(r *http.Request, f url.Values)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			form, err := bodyToForm(r)
			if err != nil {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if inject != nil {
				inject(r, form)
			}
			runLegacy(w, r, guard, legacyPath, h, false, form, ok)
		}
	}
	toggle := func(enable string) http.HandlerFunc {
		return write("/api/proxy/toggle", b.ProxyToggle, http.StatusOK, func(r *http.Request, f url.Values) {
			f.Set("ep", r.PathValue("rootname"))
			f.Set("enable", enable)
		})
	}
	return []v1Route{
		{"GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
			jsonOut(w, http.StatusOK, map[string]string{"status": "ok", "version": SYSTEM_VERSION})
		}},
		{"GET /api/v1/proxy-rules", read("/api/proxy/list", b.ProxyList, url.Values{"type": {"host"}})},
		{"POST /api/v1/proxy-rules", write("/api/proxy/add", b.ProxyAdd, http.StatusCreated, func(r *http.Request, f url.Values) {
			if f.Get("type") == "" {
				f.Set("type", "host")
			}
		})},
		{"GET /api/v1/proxy-rules/{rootname}", getProxyRule(b, guard)},
		{"PATCH /api/v1/proxy-rules/{rootname}", write("/api/proxy/edit", b.ProxyEdit, http.StatusOK, func(r *http.Request, f url.Values) {
			f.Set("rootname", r.PathValue("rootname"))
		})},
		{"DELETE /api/v1/proxy-rules/{rootname}", write("/api/proxy/del", b.ProxyDelete, http.StatusOK, func(r *http.Request, f url.Values) {
			f.Set("ep", r.PathValue("rootname"))
		})},
		{"POST /api/v1/proxy-rules/{rootname}/enable", toggle("true")},
		{"POST /api/v1/proxy-rules/{rootname}/disable", toggle("false")},
		{"GET /api/v1/access-rules", read("/api/access/list", b.AccessList, nil)},
		{"GET /api/v1/redirects", read("/api/redirect/list", b.RedirectList, nil)},
		{"GET /api/v1/certificates", read("/api/cert/list", b.CertList, url.Values{"date": {"true"}})},
		{"GET /api/v1/stats/summary", read("/api/stats/summary", b.StatsSummary, nil)},
		{"GET /api/v1/stats/blocked", read("/api/blocked/overview", b.StatsBlocked, nil)},
		{"GET /api/v1/waf/coverage", read("/api/waf/coverage", b.WAF, nil)},
	}
}

// getProxyRule serves one rule from the (credential sanitised) list output, so
// password hashes are never exposed to tokens.
func getProxyRule(b v1Backend, guard func(http.Handler) http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		inner := httptest.NewRequest(http.MethodGet, "/api/proxy/list?type=host", nil)
		inner.RemoteAddr = r.RemoteAddr
		guard(b.ProxyList).ServeHTTP(rec, inner)
		var rules []map[string]interface{}
		if json.Unmarshal(rec.Body.Bytes(), &rules) != nil {
			jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "unable to load proxy rules"})
			return
		}
		want := strings.ToLower(strings.TrimSpace(r.PathValue("rootname")))
		for _, rule := range rules {
			if d, _ := rule["RootOrMatchingDomain"].(string); strings.ToLower(d) == want {
				jsonOut(w, http.StatusOK, rule)
				return
			}
		}
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "proxy rule not found"})
	}
}

// newAPIv1Handler builds the full /api/v1/ handler: public docs plus the
// token authenticated route table.
func newAPIv1Handler(mgr *apitoken.Manager, b v1Backend, guard func(http.Handler) http.Handler) http.Handler {
	api := http.NewServeMux()
	for _, rt := range v1Routes(b, guard) {
		api.HandleFunc(rt.Pattern, rt.Handler)
	}
	authed := mgr.Middleware(historyWrapV1(api))

	root := http.NewServeMux()
	root.Handle(apiV1Prefix, authed)
	// Static documentation is public (it contains no secrets).
	root.HandleFunc("GET /api/v1/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Write(apiV1OpenAPI)
	})
	root.HandleFunc("GET /api/v1/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		var doc interface{}
		if err := yaml.Unmarshal(apiV1OpenAPI, &doc); err != nil {
			http.Error(w, "spec unavailable", http.StatusInternalServerError)
			return
		}
		jsonOut(w, http.StatusOK, doc)
	})
	root.HandleFunc("GET /api/v1/docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
		w.Write(apiV1DocsPage)
	})
	return root
}

// v1RoutePatterns lists the registered "METHOD /path" patterns (tests).
func v1RoutePatterns() []string {
	out := []string{}
	for _, rt := range v1Routes(v1Backend{}, func(h http.Handler) http.Handler { return h }) {
		out = append(out, rt.Pattern)
	}
	sort.Strings(out)
	return out
}
