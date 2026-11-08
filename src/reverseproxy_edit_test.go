package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/info/logger"
)

// editTestBaseline returns a rule with every field the edit handler manages set to a
// non default value, so that an unwanted reset to the zero value is visible.
func editTestBaseline() *dynamicproxy.ProxyEndpoint {
	return &dynamicproxy.ProxyEndpoint{
		ProxyType:            dynamicproxy.ProxyTypeHost,
		RootOrMatchingDomain: "app.example.com",
		ActiveOrigins: []*loadbalance.Upstream{
			{OriginIpOrDomain: "127.0.0.1:1", Weight: 1},
		},
		InactiveOrigins:                []*loadbalance.Upstream{},
		UseStickySession:               true,
		BypassGlobalTLS:                true,
		EnableConnectSupport:           true,
		EnableUpgradeForwarding:        true,
		DisableUptimeMonitor:           true,
		UptimeMonitorURI:               "/healthz",
		DisableAutoFallback:            true,
		RequireRateLimit:               true,
		RateLimit:                      50,
		RateLimitBurst:                 80,
		RequireCaptcha:                 true,
		CaptchaConfig:                  &dynamicproxy.CaptchaConfig{SiteKey: "site", SecretKey: "secret", SessionDuration: 3600},
		DisableChunkedTransferEncoding: true,
		ForceHTTP11:                    true,
		SanitiseClientIPHeaders:        true,
		DisableWebSocket:               true,
		WebsocketTimeout:               99,
		EnableTimeoutRefreshOnActivity: true,
		DisableLogging:                 true,
		DisableStatisticCollection:     true,
		BlockCommonExploits:            true,
		BlockAICrawlers:                true,
		MitigationAction:               3,
		Tags:                           []string{"keep", "me"},
		AuthenticationProvider: &dynamicproxy.AuthenticationProvider{
			AuthMethod: dynamicproxy.AuthMethodBasic,
		},
	}
}

// setupEditTest installs a router holding a single baseline rule and returns it.
func setupEditTest(t *testing.T) *dynamicproxy.Router {
	t.Helper()
	oldConf, oldLB, oldRouter, oldLogger := CONF_HTTP_PROXY, loadBalancer, dynamicProxyRouter, SystemWideLogger
	t.Cleanup(func() {
		CONF_HTTP_PROXY, loadBalancer, dynamicProxyRouter, SystemWideLogger = oldConf, oldLB, oldRouter, oldLogger
	})
	SystemWideLogger, _ = logger.NewFmtLogger()
	CONF_HTTP_PROXY = t.TempDir()
	loadBalancer = loadbalance.NewLoadBalancer(&loadbalance.Options{SystemUUID: "edit-test", Logger: SystemWideLogger})
	router, err := dynamicproxy.NewDynamicProxy(dynamicproxy.RouterOption{LoadBalancer: loadBalancer})
	if err != nil {
		t.Fatal(err)
	}
	dynamicProxyRouter = router
	ep, err := router.PrepareProxyRoute(editTestBaseline())
	if err != nil {
		t.Fatal(err)
	}
	if err := router.AddProxyRouteToRuntime(ep); err != nil {
		t.Fatal(err)
	}
	return router
}

func postEdit(t *testing.T, values url.Values) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/proxy/edit", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	ReverseProxyHandleEditEndpoint(w, r)
	return strings.TrimSpace(w.Body.String())
}

func endpointJSON(t *testing.T, ep *dynamicproxy.ProxyEndpoint) string {
	t.Helper()
	js, err := json.Marshal(ep)
	if err != nil {
		t.Fatal(err)
	}
	return string(js)
}

type editCase struct {
	name   string
	form   url.Values
	mutate func(ep *dynamicproxy.ProxyEndpoint)
}

// editCases lists, per form field of the edit handler, a request carrying only that field
// and the change it must cause. Append here when the handler learns a new field.
var editCases = []editCase{
	{"nothing else", url.Values{}, func(ep *dynamicproxy.ProxyEndpoint) {}},
	{"ss", url.Values{"ss": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.UseStickySession = false }},
	{"bpgtls", url.Values{"bpgtls": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.BypassGlobalTLS = false }},
	{"enableConnectSupport", url.Values{"enableConnectSupport": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.EnableConnectSupport = false }},
	{"enableUpgradeForwarding", url.Values{"enableUpgradeForwarding": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.EnableUpgradeForwarding = false }},
	{"dutm", url.Values{"dutm": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.DisableUptimeMonitor = false }},
	{"utmURI", url.Values{"utmURI": {"/other"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.UptimeMonitorURI = "/other" }},
	{"dAutoFallback", url.Values{"dAutoFallback": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.DisableAutoFallback = false }},
	{"rate off", url.Values{"rate": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.RequireRateLimit = false }},
	{"ratenum", url.Values{"ratenum": {"7"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.RateLimit = 7 }},
	{"captcha off", url.Values{"captcha": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.RequireCaptcha = false; ep.CaptchaConfig = nil }},
	{"dChunkedEnc", url.Values{"dChunkedEnc": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.DisableChunkedTransferEncoding = false }},
	{"forceHTTP11", url.Values{"forceHTTP11": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.ForceHTTP11 = false }},
	{"sanitiseClientIP", url.Values{"sanitiseClientIP": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.SanitiseClientIPHeaders = false }},
	{"disableWebSocket", url.Values{"disableWebSocket": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.DisableWebSocket = false }},
	{"websocketTimeout", url.Values{"websocketTimeout": {"12"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.WebsocketTimeout = 12 }},
	{"enableTimeoutRefreshOnActivity", url.Values{"enableTimeoutRefreshOnActivity": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.EnableTimeoutRefreshOnActivity = false }},
	{"dLogging", url.Values{"dLogging": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.DisableLogging = false }},
	{"dStatisticCollection", url.Values{"dStatisticCollection": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.DisableStatisticCollection = false }},
	{"blockCommonExploits", url.Values{"blockCommonExploits": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.BlockCommonExploits = false }},
	{"blockAICrawlers", url.Values{"blockAICrawlers": {"false"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.BlockAICrawlers = false }},
	{"mitigationAction", url.Values{"mitigationAction": {"1"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.MitigationAction = 1 }},
	{"tags", url.Values{"tags": {"a, b"}}, func(ep *dynamicproxy.ProxyEndpoint) { ep.Tags = []string{"a", "b"} }},
	{"authprovider", url.Values{"authprovider": {"0"}}, func(ep *dynamicproxy.ProxyEndpoint) {
		ep.AuthenticationProvider.AuthMethod = dynamicproxy.AuthMethodNone
	}},
}

// Upstream #1109 follow up: the edit handler is a partial update. Only the fields present
// in the request change, every other one (rate limit, CAPTCHA, exploit blocking, ...) keeps
// its current value.
func TestEditEndpointIsPartialUpdate(t *testing.T) {
	for _, tc := range editCases {
		t.Run(tc.name, func(t *testing.T) {
			router := setupEditTest(t)
			want := dynamicproxy.CopyEndpoint(editTestBaseline())
			tc.mutate(want)

			form := url.Values{"rootname": {"app.example.com"}}
			for k, v := range tc.form {
				form[k] = v
			}
			if resp := postEdit(t, form); strings.Contains(resp, "error") {
				t.Fatalf("edit failed: %s", resp)
			}
			got, err := router.LoadProxy("app.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if g, w := endpointJSON(t, got), endpointJSON(t, want); g != w {
				t.Errorf("fields not present in the request were modified\n got: %s\nwant: %s", g, w)
			}
		})
	}
}
