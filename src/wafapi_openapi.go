package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	wafapi_openapi.go

	Admin APIs of the API protection (waf/apiguard*.go): limits, method / content
	type allow-list and the optional OpenAPI spec, at the three layers of the
	central WAF: policy, profile and proxy rule. They are separate from the
	policy / profile / endpoint save APIs on purpose: a client that does not know
	about API protection can keep saving those without ever touching it.
*/

func RegisterWAFAPIProtectionAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/waf/api/get", HandleWAFAPIGet)
	authRouter.HandleFunc("/api/waf/api/set", HandleWAFAPISet)
	authRouter.HandleFunc("/api/waf/api/spec", HandleWAFAPISpec)
}

type wafAPIView struct {
	Config    *waf.APIConfig         `json:"config"`
	Effective *waf.APIConfig         `json:"effective,omitempty"` // merged result for the endpoint scope
	Defaults  waf.APILimits          `json:"defaults"`
	Spec      *waf.SpecSummary       `json:"spec,omitempty"`
	SpecErr   string                 `json:"spec_error,omitempty"`
	MaxSpec   int                    `json:"max_spec_bytes"`
	Kinds     []waf.APIViolationInfo `json:"violations"`
}

func apiScopeConfig(scope, name string) (*waf.APIConfig, error) {
	st := dynamicProxyRouter.WAFState()
	switch scope {
	case "policy":
		return st.Policy.API, nil
	case "profile":
		p, ok := st.Profile(name)
		if !ok {
			return nil, errProfileMissing
		}
		return p.API, nil
	case "endpoint":
		if name == "/" {
			if dynamicProxyRouter.Root == nil {
				return nil, errors.New("default site is not configured")
			}
			return dynamicProxyRouter.Root.WAFAPI, nil
		}
		ep, err := dynamicProxyRouter.LoadProxy(name)
		if err != nil {
			return nil, err
		}
		return ep.WAFAPI, nil
	}
	return nil, errors.New("invalid scope (policy, profile or endpoint)")
}

// HandleWAFAPIGet returns the API protection settings of one layer.
// GET scope=policy|profile|endpoint, name (profile name or proxy rule root, "/" = default site)
func HandleWAFAPIGet(w http.ResponseWriter, r *http.Request) {
	scope := strings.ToLower(r.URL.Query().Get("scope"))
	name := r.URL.Query().Get("name")
	cfg, err := apiScopeConfig(scope, name)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	v := wafAPIView{Config: cfg, Defaults: waf.DefaultAPILimits(), MaxSpec: waf.MaxOpenAPISpecBytes, Kinds: waf.APIViolations()}
	if cfg != nil && cfg.OpenAPI != nil && strings.TrimSpace(cfg.OpenAPI.Spec) != "" {
		if rt, err := waf.CompileOpenAPI(cfg.OpenAPI.Spec); err != nil {
			v.SpecErr = err.Error()
		} else {
			s := rt.Summary
			v.Spec = &s
		}
	}
	if scope == "endpoint" {
		ep := dynamicProxyRouter.Root
		if name != "/" {
			ep, _ = dynamicProxyRouter.LoadProxy(name)
		}
		if ep != nil {
			v.Effective = dynamicProxyRouter.WAFState().ResolveAPI(ep.WAFSetting())
			if v.Effective != nil && v.Effective.OpenAPI != nil {
				v.Effective.OpenAPI = &waf.OpenAPIConfig{AllowUnknownPaths: v.Effective.OpenAPI.AllowUnknownPaths} // never echo inherited specs
			}
		}
	}
	sendWAFJSON(w, v)
}

// HandleWAFAPISet replaces the API protection settings of one layer.
// POST scope=policy|profile|endpoint, name, config (JSON APIConfig; empty = clear)
func HandleWAFAPISet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	scope, _ := utils.PostPara(r, "scope")
	scope = strings.ToLower(strings.TrimSpace(scope))
	name, _ := utils.PostPara(r, "name")
	raw, _ := utils.PostPara(r, "config")
	if int64(len(raw)) > waf.MaxOpenAPISpecBytes*2+(1<<20) {
		utils.SendErrorResponse(w, "configuration too large")
		return
	}
	var cfg *waf.APIConfig
	if strings.TrimSpace(raw) != "" {
		cfg = &waf.APIConfig{}
		if err := json.Unmarshal([]byte(raw), cfg); err != nil {
			utils.SendErrorResponse(w, "Invalid configuration: "+err.Error())
			return
		}
		cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
		if err := cfg.Validate(); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		if cfg.IsEmpty() {
			cfg = nil
		}
	}
	var err error
	switch scope {
	case "policy":
		err = mutateWAFCentral(func(p *waf.Policy, _ *[]waf.Profile) error {
			p.API = cfg
			return nil
		})
	case "profile":
		err = mutateWAFCentral(func(p *waf.Policy, profiles *[]waf.Profile) error {
			if cur, ok := dynamicProxyRouter.WAFState().Profile(name); ok && cur.BuiltIn {
				return errBuiltinProfile
			}
			for i := range *profiles {
				if strings.EqualFold((*profiles)[i].Name, strings.TrimSpace(name)) {
					(*profiles)[i].API = cfg
					return nil
				}
			}
			return errProfileMissing
		})
	case "endpoint":
		if name == "" {
			utils.SendErrorResponse(w, "Target proxy rule not defined")
			return
		}
		err = applyWAFEndpoint(name, func(ep *dynamicproxy.ProxyEndpoint, _ *waf.State) error {
			ep.WAFAPI = cfg
			return nil
		})
	default:
		err = errors.New("invalid scope (policy, profile or endpoint)")
	}
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleWAFAPISpec checks an OpenAPI document without saving it. POST spec (JSON or YAML text).
// Returns the summary (paths / operations) or the error.
func HandleWAFAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	spec, err := utils.PostPara(r, "spec")
	if err != nil {
		utils.SendErrorResponse(w, "spec not defined")
		return
	}
	rt, err := waf.CompileOpenAPI(spec)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	sendWAFJSON(w, rt.Summary)
}
