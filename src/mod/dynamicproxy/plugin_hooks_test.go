package dynamicproxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/dynamicproxy/redirection"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/plugins"
	zp "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

/*
	End-to-end tests of the plugin hook stages through ProxyHandler.ServeHTTP
	with an httptest server standing in for the plugin process.
*/

type hookE2E struct {
	handler  *ProxyHandler
	mgr      *plugins.Manager
	upstream *upstreamRecorder
}

type upstreamRecorder struct {
	mu      sync.Mutex
	hits    int32
	lastReq *http.Request
	lastBdy []byte
}

func (u *upstreamRecorder) last() (*http.Request, []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastReq, u.lastBdy
}

func newHookE2E(t *testing.T, mutate func(ep *ProxyEndpoint)) *hookE2E {
	t.Helper()
	rec := &upstreamRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&rec.hits, 1)
		b, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.lastReq, rec.lastBdy = r, b
		rec.mu.Unlock()
		w.Header().Set("X-Powered-By", "upstream")
		w.WriteHeader(200)
		w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)

	lg, _ := logger.NewFmtLogger()
	mgr := &plugins.Manager{
		LoadedPlugins: map[string]*plugins.Plugin{},
		Options:       &plugins.ManagerOptions{PluginGroups: map[string][]string{}, Logger: lg},
	}

	router := newTestRateLimitRouter(t, false)
	router.Option.Logger = lg
	router.Option.WebDirectory = t.TempDir()
	router.Option.PluginManager = mgr
	rt, err := redirection.NewRuleTable(t.TempDir(), false, false, lg)
	if err != nil {
		t.Fatal(err)
	}
	router.Option.RedirectRuleTable = rt
	router.ProxyEndpoints = &sync.Map{}
	router.loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{Logger: lg})

	ep := &ProxyEndpoint{
		RootOrMatchingDomain:   "hooks.test",
		ProxyType:              ProxyTypeHost,
		ActiveOrigins:          []*loadbalance.Upstream{{OriginIpOrDomain: strings.TrimPrefix(upstream.URL, "http://")}},
		DisableLogging:         true,
		AuthenticationProvider: &AuthenticationProvider{AuthMethod: AuthMethodNone},
		Tags:                   []string{"filters"},
	}
	if mutate != nil {
		mutate(ep)
	}
	prepared, err := router.PrepareProxyRoute(ep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := router.AddProxyRouteToRuntime(prepared); err != nil {
		t.Fatalf("add: %v", err)
	}
	return &hookE2E{handler: &ProxyHandler{Parent: router}, mgr: mgr, upstream: rec}
}

// addPlugin registers a fake filter plugin in the tag group "filters"
func (e *hookE2E) addPlugin(t *testing.T, id string, hooks *zp.HookSettings, h func(fr *zp.FilterRequest) *zp.FilterVerdict, grouped bool) *int32 {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		var fr zp.FilterRequest
		json.NewDecoder(r.Body).Decode(&fr)
		json.NewEncoder(w).Encode(h(&fr))
	}))
	t.Cleanup(srv.Close)
	_, ps, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(ps)
	e.mgr.LoadedPlugins[id] = &plugins.Plugin{
		Spec:         &zp.IntroSpect{ID: id, Name: id, Type: zp.PluginType_Router, Hooks: hooks},
		Enabled:      true,
		AssignedPort: port,
	}
	if grouped {
		e.mgr.Options.PluginGroups["filters"] = append(e.mgr.Options.PluginGroups["filters"], id)
	}
	e.mgr.UpdateTagsToPluginMaps()
	return &calls
}

func (e *hookE2E) do(r *http.Request) *httptest.ResponseRecorder {
	r.RemoteAddr = "198.51.100.9:50000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36")
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w
}

func hooksFor(stages ...zp.HookStage) *zp.HookSettings {
	return &zp.HookSettings{Version: 1, Stages: stages, FilterRequestPath: "/filter"}
}

func TestPluginHooks_VerdictsEndToEnd(t *testing.T) {
	e := newHookE2E(t, nil)
	newPath := "/rewritten"
	e.addPlugin(t, "ua", hooksFor(zp.HookStagePreAuth), func(fr *zp.FilterRequest) *zp.FilterVerdict {
		ua := fr.HeaderValue("User-Agent")
		switch {
		case strings.Contains(ua, "badbot"):
			return zp.Deny(403, "bots not welcome").WithReason("ua")
		case strings.Contains(ua, "rewrite"):
			return &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Path: &newPath,
				RequestHeaders: &zp.HeaderOps{Set: map[string]string{"X-Bot-Score": "1"}, Remove: []string{"Cookie"}}}}
		case strings.Contains(ua, "evil"):
			return zp.ModifyRequestHeaders(zp.HeaderOps{Set: map[string]string{"Host": "evil.com"}})
		}
		return zp.Allow()
	}, true)

	// allow
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://hooks.test/hello", nil)
	r.RemoteAddr = "198.51.100.9:50000"
	r.Header.Set("User-Agent", "Mozilla")
	e.handler.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "upstream-ok" {
		t.Fatalf("allow: %d %q", w.Code, w.Body.String())
	}

	// deny: never reaches upstream
	before := atomic.LoadInt32(&e.upstream.hits)
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "http://hooks.test/hello", nil)
	r.RemoteAddr = "198.51.100.9:50000"
	r.Header.Set("User-Agent", "badbot/1.0")
	e.handler.ServeHTTP(w, r)
	if w.Code != 403 || w.Body.String() != "bots not welcome" || atomic.LoadInt32(&e.upstream.hits) != before {
		t.Fatalf("deny: %d %q hits=%d", w.Code, w.Body.String(), e.upstream.hits)
	}

	// modify: path + headers reach the upstream, host unchanged
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "http://hooks.test/original?q=1", nil)
	r.RemoteAddr = "198.51.100.9:50000"
	r.Header.Set("User-Agent", "rewrite-me")
	r.Header.Set("Cookie", "secret=1")
	e.handler.ServeHTTP(w, r)
	up, _ := e.upstream.last()
	if w.Code != 200 || up.URL.Path != "/rewritten" || up.Header.Get("X-Bot-Score") != "1" || up.Header.Get("Cookie") != "" {
		t.Fatalf("modify: code=%d path=%q hdr=%v", w.Code, up.URL.Path, up.Header)
	}

	// forbidden modification (host change) is rejected: request continues unchanged (fail open)
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "http://hooks.test/keep", nil)
	r.RemoteAddr = "198.51.100.9:50000"
	r.Header.Set("User-Agent", "evil")
	e.handler.ServeHTTP(w, r)
	up, _ = e.upstream.last()
	if w.Code != 200 || up.URL.Path != "/keep" {
		t.Fatalf("invalid verdict must not change the request: %d %q", w.Code, up.URL.Path)
	}
}

func TestPluginHooks_PreAuthRunsBeforeWAFAndAuth_PostAuthAfter(t *testing.T) {
	e := newHookE2E(t, func(ep *ProxyEndpoint) {
		ep.WAF = &waf.Config{Mode: waf.ModeBlock}
		ep.AuthenticationProvider = &AuthenticationProvider{
			AuthMethod:           AuthMethodBasic,
			BasicAuthCredentials: []*BasicAuthCredentials{{Username: "admin", PasswordHash: "deadbeef"}},
		}
	})
	preCalls := e.addPlugin(t, "pre", hooksFor(zp.HookStagePreAuth), func(fr *zp.FilterRequest) *zp.FilterVerdict {
		if strings.Contains(fr.Request.URL, "/teapot") {
			return zp.Deny(418, "pre")
		}
		return zp.Allow()
	}, true)
	postCalls := e.addPlugin(t, "post", hooksFor(zp.HookStagePostAuth), func(fr *zp.FilterRequest) *zp.FilterVerdict {
		return zp.Deny(409, "post")
	}, true)

	get := func(target string, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://hooks.test"+target, nil)
		if auth {
			r.SetBasicAuth("admin", "wrong")
		}
		return e.do(r)
	}

	// pre_auth deny wins over the unauthenticated 401
	if w := get("/teapot", false); w.Code != 418 {
		t.Fatalf("pre_auth must run before auth, got %d", w.Code)
	}
	// pre_auth deny wins over the WAF 403 for an attack
	if w := get("/teapot?id=1%27%20OR%20%271%27%3D%271", false); w.Code != 418 {
		t.Fatalf("pre_auth must run before the WAF, got %d", w.Code)
	}
	if atomic.LoadInt32(postCalls) != 0 {
		t.Fatal("post_auth must not run when pre_auth denied")
	}
	// pre_auth allows: the WAF still blocks the attack, auth still challenges
	if w := get("/x?id=1%27%20OR%20%271%27%3D%271", false); w.Code != 403 {
		t.Fatalf("WAF should still run after pre_auth allow, got %d", w.Code)
	}
	if w := get("/x", false); w.Code != 401 {
		t.Fatalf("auth should still run after pre_auth allow, got %d", w.Code)
	}
	if atomic.LoadInt32(postCalls) != 0 {
		t.Fatal("post_auth must not run for unauthenticated / blocked requests")
	}
	if atomic.LoadInt32(preCalls) < 4 {
		t.Fatalf("pre_auth should have seen all requests, calls=%d", *preCalls)
	}
}

func TestPluginHooks_PostAuthRunsAfterSuccessfulAuth(t *testing.T) {
	e := newHookE2E(t, func(ep *ProxyEndpoint) {
		ep.AuthenticationProvider = &AuthenticationProvider{AuthMethod: AuthMethodNone}
	})
	e.addPlugin(t, "post", hooksFor(zp.HookStagePostAuth), func(fr *zp.FilterRequest) *zp.FilterVerdict {
		return zp.Deny(409, "post")
	}, true)
	if w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil)); w.Code != 409 {
		t.Fatalf("post_auth deny, got %d", w.Code)
	}
}

func TestPluginHooks_ResponseHeaders(t *testing.T) {
	e := newHookE2E(t, nil)
	e.addPlugin(t, "resp", hooksFor(zp.HookStageResponse), func(fr *zp.FilterRequest) *zp.FilterVerdict {
		if fr.Response == nil || fr.Response.Status != 200 || len(fr.Response.Header["X-Powered-By"]) == 0 {
			return zp.Deny(500, "") //invalid at this stage -> failure; test would notice the missing header
		}
		return zp.ModifyResponseHeaders(zp.HeaderOps{
			Set:    map[string]string{"X-Frame-Options": "DENY"},
			Remove: []string{"X-Powered-By"},
		})
	}, true)
	w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil))
	if w.Code != 200 || w.Body.String() != "upstream-ok" || w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("X-Powered-By") != "" {
		t.Fatalf("response hook: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
}

func TestPluginHooks_GlobalPluginAndEndpointOptOut(t *testing.T) {
	e := newHookE2E(t, func(ep *ProxyEndpoint) { ep.Tags = nil })
	calls := e.addPlugin(t, "glob", hooksFor(zp.HookStagePreAuth), func(fr *zp.FilterRequest) *zp.FilterVerdict {
		return zp.Deny(403, "global")
	}, false)

	if w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil)); w.Code != 200 || atomic.LoadInt32(calls) != 0 {
		t.Fatalf("a plugin is not global by default, got %d", w.Code)
	}
	yes := true
	if err := e.mgr.SetHookAdminSettings("glob", &yes, nil); err != nil {
		t.Fatal(err)
	}
	if w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil)); w.Code != 403 {
		t.Fatalf("global plugin must apply to an untagged endpoint, got %d", w.Code)
	}
	//endpoint-level opt-out
	ep := e.handler.Parent.GetProxyEndpointFromHostname("hooks.test")
	ep.Tags = []string{"no-plugin:glob"}
	if w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil)); w.Code != 200 {
		t.Fatalf("endpoint opt-out ignored, got %d", w.Code)
	}
	ep.Tags = []string{"no-global-plugins"}
	if w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil)); w.Code != 200 {
		t.Fatalf("no-global-plugins opt-out ignored, got %d", w.Code)
	}
}

func TestPluginHooks_BodyPreviewEndToEnd(t *testing.T) {
	e := newHookE2E(t, nil)
	var seen []byte
	var trunc bool
	var mu sync.Mutex
	h := hooksFor(zp.HookStagePreAuth)
	h.BodyPreviewBytes = 8
	h.BodyContentTypes = []string{"application/json"}
	e.addPlugin(t, "body", h, func(fr *zp.FilterRequest) *zp.FilterVerdict {
		mu.Lock()
		seen, trunc = fr.BodyPreview, fr.BodyTruncated
		mu.Unlock()
		return zp.Allow()
	}, true)
	payload := `{"user":"alice","password":"hunter2"}`
	r := httptest.NewRequest("POST", "http://hooks.test/login", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	w := e.do(r)
	_, upBody := e.upstream.last()
	mu.Lock()
	defer mu.Unlock()
	if w.Code != 200 || string(upBody) != payload {
		t.Fatalf("upstream must receive the full body: %d %q", w.Code, upBody)
	}
	if string(seen) != payload[:8] || !trunc {
		t.Fatalf("plugin preview %q truncated=%v", seen, trunc)
	}
}

func TestPluginHooks_FailClosedNeedsConsentEndToEnd(t *testing.T) {
	e := newHookE2E(t, nil)
	h := hooksFor(zp.HookStagePreAuth)
	h.FailurePolicy = zp.FailureClosed
	h.TimeoutMs = 100
	e.addPlugin(t, "strict", h, func(fr *zp.FilterRequest) *zp.FilterVerdict { return &zp.FilterVerdict{Action: "bogus"} }, true)

	if w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil)); w.Code != 200 {
		t.Fatalf("without admin consent the plugin fails open, got %d", w.Code)
	}
	yes := true
	if err := e.mgr.SetHookAdminSettings("strict", nil, &yes); err != nil {
		t.Fatal(err)
	}
	if w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil)); w.Code != 503 {
		t.Fatalf("with consent the plugin fails closed, got %d", w.Code)
	}
}

func TestPluginHooks_NoPluginsIsTransparent(t *testing.T) {
	e := newHookE2E(t, nil)
	if w := e.do(httptest.NewRequest("GET", "http://hooks.test/", nil)); w.Code != 200 || w.Body.String() != "upstream-ok" {
		t.Fatalf("got %d", w.Code)
	}
}
