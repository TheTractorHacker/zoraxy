package dynamicproxy

import (
	"fmt"
	"html"
	"imuslab.com/zoraxy/mod/pathmatch"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	waf_inspect.go

	Glue between the proxy request chain and the self-contained waf package.
	The only call-site in the request chain is wafInspect(), which is a nil
	check when the WAF is disabled for the endpoint.
*/

// wafRuntime is the resolved WAF of one endpoint: the compiled instance (nil
// when the WAF is off) plus the central state it was resolved against.
type wafRuntime struct {
	inst  *waf.Instance
	state *waf.State
	res   waf.Resolved
	resp  *waf.ResponseGuard // response inspection, nil when off, see waf_response.go
	api   *waf.Guard         // API protection (waf_api.go), nil when off
}

var emptyWAFState = waf.EmptyState()

// WAFSetting returns the endpoint's central WAF choice
func (pe *ProxyEndpoint) WAFSetting() waf.Setting {
	return waf.Setting{Source: pe.WAFSource, Profile: pe.WAFProfile, Extra: pe.WAFExtra, Custom: pe.WAF, API: pe.WAFAPI}
}

func buildWAFRuntime(set waf.Setting, st *waf.State) (*wafRuntime, error) {
	if st == nil {
		st = emptyWAFState
	}
	res := st.Resolve(set)
	inst, err := waf.Default.Get(res.Config)
	if err != nil {
		return nil, err
	}
	guard, err := buildAPIGuard(set, st)
	if err != nil {
		return nil, err
	}
	rt := &wafRuntime{inst: inst, state: st, res: res, api: guard}
	if res.Config != nil {
		rt.resp = waf.Default.NewResponseGuard(res.Config.Response, res.Mode)
	}
	return rt, nil
}

// InitializeWAF resolves the endpoint's WAF against the default (empty, disabled)
// central policy. Kept for callers outside a router; PrepareProxyRoute uses the
// router's central state.
func (pe *ProxyEndpoint) InitializeWAF() error { return pe.initializeWAF(nil) }

// initializeWAF compiles (or fetches from the shared cache) the WAF for this
// endpoint. An error is returned if the configuration or custom rules are
// invalid; the previous runtime is then left untouched.
func (pe *ProxyEndpoint) initializeWAF(st *waf.State) error {
	rt, err := buildWAFRuntime(pe.WAFSetting(), st)
	if err != nil {
		return err
	}
	pe.wafRT.Store(rt)
	return nil
}

// WAFState returns the central WAF policy and profiles in effect
func (router *Router) WAFState() *waf.State {
	if st := router.wafState.Load(); st != nil {
		return st
	}
	return emptyWAFState
}

// SetWAFState installs the state without touching endpoints (startup, before
// any endpoint is loaded).
func (router *Router) SetWAFState(st *waf.State) { router.wafState.Store(st) }

func (router *Router) allWAFEndpoints() []*ProxyEndpoint {
	var eps []*ProxyEndpoint
	if router.Root != nil {
		eps = append(eps, router.Root)
	}
	router.ProxyEndpoints.Range(func(_, v interface{}) bool {
		if ep, ok := v.(*ProxyEndpoint); ok && ep != router.Root {
			eps = append(eps, ep)
		}
		return true
	})
	return eps
}

// syncEndpointWAF re-resolves an endpoint that was prepared against an older state
func (router *Router) syncEndpointWAF(ep *ProxyEndpoint) {
	st := router.WAFState()
	if rt := ep.wafRT.Load(); rt != nil && rt.state == st {
		return
	}
	ep.initializeWAF(st)
}

// ApplyWAFState validates a new central state and, only if everything compiles,
// swaps it in for every endpoint. Nothing changes on error. Compiled instances
// are shared through the hash cache, so endpoints whose effective config did
// not change keep their instance; no proxy restart is needed.
func (router *Router) ApplyWAFState(st *waf.State) error {
	router.wafMu.Lock()
	defer router.wafMu.Unlock()

	for _, cfg := range st.ValidationConfigs() {
		if _, err := waf.Default.Get(cfg); err != nil {
			return err
		}
	}
	eps := router.allWAFEndpoints()
	built := make(map[*ProxyEndpoint]*wafRuntime, len(eps))
	for _, ep := range eps {
		rt, err := buildWAFRuntime(ep.WAFSetting(), st)
		if err != nil {
			return fmt.Errorf("endpoint %s: %w", ep.RootOrMatchingDomain, err)
		}
		built[ep] = rt
	}
	router.wafState.Store(st)
	for ep, rt := range built {
		ep.wafRT.Store(rt)
	}
	// Endpoints added while compiling were prepared against the old state
	for _, ep := range router.allWAFEndpoints() {
		router.syncEndpointWAF(ep)
	}
	return nil
}

// WAFCoverageEntry describes the effective WAF of one endpoint
type WAFCoverageEntry struct {
	Endpoint string
	IsRoot   bool
	Source   string // inherit, off, detection_only, block, profile, custom
	Origin   string // global, endpoint, profile:X, custom
	Profile  string
	Mode     string // effective mode
	Warning  string `json:",omitempty"`

	// Graduated response (waf_challenge.go): effective challenge band of the endpoint and whether it can be served
	ChallengeThreshold int  `json:",omitempty"` // 0 = no challenge band
	ChallengeReady     bool `json:",omitempty"` // a CAPTCHA provider is configured on the endpoint; without one the challenge band blocks
	// API protection (waf_api.go)
	APIMode    string `json:",omitempty"` // log or block, empty = off
	APIWarning string `json:",omitempty"` // e.g. the OpenAPI spec cannot be used
}

// WAFCoverage lists every endpoint with its effective WAF mode and origin
func (router *Router) WAFCoverage() []WAFCoverageEntry {
	var out []WAFCoverageEntry
	st := router.WAFState()
	for _, ep := range router.allWAFEndpoints() {
		res := st.Resolve(ep.WAFSetting())
		e := WAFCoverageEntry{Endpoint: ep.RootOrMatchingDomain, IsRoot: ep == router.Root, Source: res.Source, Origin: res.Label, Mode: res.Mode, Warning: res.Warning}
		if res.Source == waf.SourceProfile {
			e.Profile = ep.WAFProfile
		}
		e.ChallengeReady = router.wafChallengeAvailable(ep)
		if res.Config.ChallengeEnabled() && res.Mode == waf.ModeBlock {
			e.ChallengeThreshold = res.Config.ChallengeThreshold
		}
		if rt := ep.wafRT.Load(); rt != nil && rt.api != nil {
			e.APIMode, e.APIWarning = rt.api.Mode(), rt.api.SpecError()
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out
}

// wafInspect runs the request through the WAF of the endpoint.
// Returns true if the request was blocked and a response has been written.
func (router *Router) wafInspect(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if sep == nil {
		return false
	}
	rt := sep.wafRT.Load()
	if rt == nil || (rt.inst == nil && rt.api == nil) {
		return false
	}
	clientIP := router.GetClientIPForEndpoint(r, sep)
	if router.wafChallengeVerify(w, r, sep, rt.res.Config, clientIP) {
		return true
	}
	if rt.res.Bypass && rt.state.BypassReason(r, clientIP) != "" {
		return false
	}
	if rt.api != nil && router.apiInspect(w, r, sep, rt, clientIP) {
		return true
	}
	if rt.inst == nil {
		return false
	}
	detail, wafRule := "", 0
	challenged := false
	info := waf.RequestInfo{
		OnEvent:  func(ev waf.Event) { detail, wafRule = ev.BlockSummary(), ev.BlockRuleID() },
		Endpoint: sep.RootOrMatchingDomain,
		ClientIP: clientIP,
		Source:   rt.res.Label,
		OnBlock: func(w http.ResponseWriter, r *http.Request, txID string) {
			// Same 403 page (and template override) as the other access blocks.
			// Rule details are logged server side only, never sent to the client.
			serveWAFBlockPage(w, r, router, txID)
		},
	}
	// Graduated response: the challenge band needs a CAPTCHA provider on the endpoint, else it blocks
	if rt.res.Config.ChallengeEnabled() && router.wafChallengeAvailable(sep) {
		info.ChallengeValid = func(r *http.Request) bool {
			// outside the protected paths of this site a challenge is treated as already passed
			return !sep.EffectiveCaptchaConfig().ChallengeAllowedOnPath(pathmatch.RequestTarget(r)) || router.wafChallengeValid(r, sep, clientIP)
		}
		info.OnChallenge = func(w http.ResponseWriter, r *http.Request, txID string) {
			challenged = true
			router.wafServeChallenge(w, r, sep, detail)
		}
	}
	blocked := rt.inst.Inspect(w, r, info)
	if blocked && !challenged {
		router.logRequestRule(r, false, http.StatusForbidden, "waf-blocked", r.Host, "", sep, detail, wafRuleKey(wafRule))
	}
	return blocked
}

// serveWAFBlockPage writes the 403 page (honouring templates/forbidden.html in
// the web root) with the transaction ID so an admin can find the audit event.
func serveWAFBlockPage(w http.ResponseWriter, r *http.Request, router *Router, txID string) {
	page, name := ErrorTemplateForbidden.getTemplateContent()
	if router != nil && router.Option != nil && router.Option.WebDirectory != "" {
		if custom, err := os.ReadFile(filepath.Join(router.Option.WebDirectory, "templates", name)); err == nil {
			page = custom
		}
	}
	body := string(page)
	marker := `<div style="text-align:center;font-size:small;opacity:.7;padding:1em">Request ID: ` + html.EscapeString(txID) + `</div>`
	if i := strings.LastIndex(strings.ToLower(body), "</body>"); i >= 0 {
		body = body[:i] + marker + body[i:]
	} else {
		body += marker
	}
	w.Header().Set("X-Request-Id", txID)
	router.writeForbiddenPage(w, r, http.StatusForbidden, []byte(body), false)
}

// wafRuleKey is the machine key of a WAF block in the blocked-request log ("waf:941100")
func wafRuleKey(id int) string {
	if id == 0 {
		return "waf"
	}
	return "waf:" + strconv.Itoa(id)
}
