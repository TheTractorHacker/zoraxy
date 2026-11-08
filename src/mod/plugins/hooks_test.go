package plugins

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
	zp "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

/* Test helpers */

func newHookTestManager(t testing.TB) *Manager {
	t.Helper()
	lg, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{
		LoadedPlugins: map[string]*Plugin{},
		tagPluginList: map[string][]*Plugin{},
		Options: &ManagerOptions{
			PluginGroups: map[string][]string{},
			SystemConst:  &zp.RuntimeConstantValue{},
			Logger:       lg,
		},
	}
}

// addFakePlugin starts an httptest server standing in for the plugin process and
// registers it as an enabled router plugin. handler serves every path.
func addFakePlugin(t testing.TB, m *Manager, id string, hooks *zp.HookSettings, handler http.HandlerFunc, tags ...string) *Plugin {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	p := &Plugin{
		RootDir: t.TempDir(),
		Spec: &zp.IntroSpect{
			ID: id, Name: id, Type: zp.PluginType_Router, Hooks: hooks,
		},
		Enabled:      true,
		AssignedPort: port,
	}
	sanitizeHookSpec(p.Spec)
	m.LoadedPlugins[id] = p
	for _, tag := range tags {
		m.Options.PluginGroups[tag] = append(m.Options.PluginGroups[tag], id)
	}
	m.UpdateTagsToPluginMaps()
	return p
}

func verdictHandler(v *zp.FilterVerdict, calls *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			atomic.AddInt32(calls, 1)
		}
		io.Copy(io.Discard, r.Body)
		json.NewEncoder(w).Encode(v)
	}
}

func preAuth(extra ...func(*zp.HookSettings)) *zp.HookSettings {
	h := &zp.HookSettings{Version: 1, Stages: []zp.HookStage{zp.HookStagePreAuth}, FilterRequestPath: "/filter"}
	for _, f := range extra {
		f(h)
	}
	return h
}

func newReq(method, target string, body string) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	r.RemoteAddr = "198.51.100.9:5000"
	return r
}

/* Manifest parsing */

func TestManifestOldFormatStillParses(t *testing.T) {
	old := `{"id":"com.example.old","name":"Old","author":"a","author_contact":"c","description":"d","url":"u","type":0,
	"version_major":1,"version_minor":0,"version_patch":0,"static_capture_paths":[{"capture_path":"/x"}],"static_capture_ingress":"/s",
	"dynamic_capture_sniff":"/sniff","dynamic_capture_ingress":"/d","ui_path":"/ui","subscription_path":"","subscriptions_events":{},"permitted_api_endpoints":[]}`
	var spec zp.IntroSpect
	if err := json.Unmarshal([]byte(old), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Hooks != nil {
		t.Fatal("legacy manifest must have no hooks")
	}
	if w := sanitizeHookSpec(&spec); len(w) != 0 {
		t.Fatalf("unexpected warnings %v", w)
	}
	if spec.DynamicCaptureSniff != "/sniff" {
		t.Fatal("legacy fields lost")
	}
	//Re-encoding a legacy spec must not invent a hooks key
	out, _ := json.Marshal(spec)
	if strings.Contains(string(out), `"hooks"`) {
		t.Fatal("legacy spec re-encoded with hooks key")
	}
}

func TestManifestNewFormatAndSanitising(t *testing.T) {
	js := `{"id":"x","hooks":{"version":1,"stages":["pre_auth","response","bogus","pre_auth"],"filter_request_path":"filter","timeout_ms":99999,
	"failure_policy":"fail_closed","body_preview_bytes":9999999,"body_content_types":["application/json"],"priority":-5}}`
	var spec zp.IntroSpect
	if err := json.Unmarshal([]byte(js), &spec); err != nil {
		t.Fatal(err)
	}
	warns := sanitizeHookSpec(&spec)
	h := spec.Hooks
	if len(warns) != 1 || !strings.Contains(warns[0], "bogus") {
		t.Fatalf("warnings: %v", warns)
	}
	if len(h.Stages) != 2 || h.FilterRequestPath != "/filter" || h.TimeoutMs != zp.MaxHookTimeoutMs ||
		h.BodyPreviewBytes != zp.MaxBodyPreviewBytes || h.Priority != -5 || h.Version != 1 {
		t.Fatalf("unexpected sanitised hooks %+v", h)
	}
	if h.EffectiveTimeout() != 10*time.Second {
		t.Fatal("timeout must be capped at 10s")
	}
}

func TestManifestHookEdgeCases(t *testing.T) {
	spec := &zp.IntroSpect{Hooks: &zp.HookSettings{Version: 7, Stages: []zp.HookStage{zp.HookStagePreAuth}, FilterRequestPath: "/f"}}
	sanitizeHookSpec(spec)
	if spec.Hooks != nil {
		t.Fatal("hooks from a newer API version must be ignored")
	}
	spec = &zp.IntroSpect{Hooks: &zp.HookSettings{Stages: []zp.HookStage{zp.HookStagePreAuth}, FilterRequestPath: "/a/../b"}}
	sanitizeHookSpec(spec)
	if len(spec.Hooks.Stages) != 0 {
		t.Fatal("unsafe filter path must disable the stages")
	}
	spec = &zp.IntroSpect{Hooks: &zp.HookSettings{Stages: []zp.HookStage{zp.HookStagePreAuth}, FilterRequestPath: "/f", FailurePolicy: "weird"}}
	sanitizeHookSpec(spec)
	if spec.Hooks.FailurePolicy != zp.FailureOpen || spec.Hooks.Version != 1 {
		t.Fatalf("defaults wrong: %+v", spec.Hooks)
	}
	var nilHooks *zp.HookSettings
	if nilHooks.EffectiveTimeout() != 2*time.Second {
		t.Fatal("default timeout must be 2s")
	}
}

/* Verdict validation */

func TestSanitizeVerdictRejections(t *testing.T) {
	str := func(s string) *string { return &s }
	req := func(ops zp.HeaderOps) *zp.FilterVerdict { return zp.ModifyRequestHeaders(ops) }
	res := func(ops zp.HeaderOps) *zp.FilterVerdict { return zp.ModifyResponseHeaders(ops) }
	bad := []struct {
		name  string
		stage zp.HookStage
		v     *zp.FilterVerdict
	}{
		{"host header", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"Host": "evil.com"}})},
		{"host lowercase", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"hOsT": "evil.com"}})},
		{"connection", zp.HookStagePreAuth, req(zp.HeaderOps{Add: map[string]string{"Connection": "close"}})},
		{"transfer-encoding", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"Transfer-Encoding": "chunked"}})},
		{"upgrade remove", zp.HookStagePreAuth, req(zp.HeaderOps{Remove: []string{"Upgrade"}})},
		{"content-length", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"Content-Length": "1"}})},
		{"x-forwarded-for", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"X-Forwarded-For": "1.1.1.1"}})},
		{"zoraxy internal", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"X-Zoraxy-Plugin-Token": "x"}})},
		{"crlf value", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"X-A": "a\r\nSet-Cookie: x=1"}})},
		{"bad name", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"X A": "a"}})},
		{"empty name", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"": "a"}})},
		{"huge value", zp.HookStagePreAuth, req(zp.HeaderOps{Set: map[string]string{"X-A": strings.Repeat("a", zp.MaxHeaderValueBytes+1)}})},
		{"path with host", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Path: str("//evil.com/x")}}},
		{"path relative", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Path: str("evil.com/x")}}},
		{"path dotdot", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Path: str("/a/../../etc")}}},
		{"path query inside", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Path: str("/a?b=1")}}},
		{"path control", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Path: str("/a\nb")}}},
		{"query with fragment", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Query: str("a=1#x")}}},
		{"query with space", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Query: str("a=1 HTTP/1.1")}}},
		{"response hdr in request stage", zp.HookStagePreAuth, res(zp.HeaderOps{Set: map[string]string{"X-A": "1"}})},
		{"request hdr in response stage", zp.HookStageResponse, req(zp.HeaderOps{Set: map[string]string{"X-A": "1"}})},
		{"path in response stage", zp.HookStageResponse, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Path: str("/x")}}},
		{"set-cookie set", zp.HookStageResponse, res(zp.HeaderOps{Set: map[string]string{"Set-Cookie": "a=b"}})},
		{"set-cookie remove", zp.HookStageResponse, res(zp.HeaderOps{Remove: []string{"Set-Cookie"}})},
		{"content-encoding resp", zp.HookStageResponse, res(zp.HeaderOps{Set: map[string]string{"Content-Encoding": "gzip"}})},
		{"deny at response", zp.HookStageResponse, zp.Deny(403, "x")},
		{"capture at response", zp.HookStageResponse, zp.Capture()},
		{"deny status 200", zp.HookStagePreAuth, zp.Deny(200, "x")},
		{"deny status 302", zp.HookStagePreAuth, zp.Deny(302, "x")},
		{"deny status 700", zp.HookStagePreAuth, zp.Deny(700, "x")},
		{"deny body too big", zp.HookStagePreAuth, zp.Deny(403, strings.Repeat("a", zp.MaxDenyBodyBytes+1))},
		{"deny set-cookie", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "deny", Deny: &zp.DenyAction{Headers: map[string]string{"Set-Cookie": "a=b"}}}},
		{"deny location", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "deny", Deny: &zp.DenyAction{Headers: map[string]string{"Location": "http://evil"}}}},
		{"modify empty", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify"}},
		{"unknown action", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "explode"}},
		{"future version", zp.HookStagePreAuth, &zp.FilterVerdict{Version: 99, Action: "allow"}},
		{"too many ops", zp.HookStagePreAuth, func() *zp.FilterVerdict {
			ops := zp.HeaderOps{Set: map[string]string{}}
			for i := 0; i < zp.MaxHeaderOps+1; i++ {
				ops.Set["X-H"+strconv.Itoa(i)] = "v"
			}
			return req(ops)
		}()},
	}
	for _, c := range bad {
		if _, err := sanitizeVerdict(c.stage, c.v); err == nil {
			t.Errorf("%s: expected rejection", c.name)
		}
	}

	good := []struct {
		name  string
		stage zp.HookStage
		v     *zp.FilterVerdict
	}{
		{"allow", zp.HookStagePreAuth, zp.Allow()},
		{"deny default status", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "deny"}},
		{"deny page", zp.HookStagePostAuth, &zp.FilterVerdict{Action: "deny", Deny: &zp.DenyAction{Status: 429, Body: "slow down", Headers: map[string]string{"Retry-After": "5", "x-custom": "1"}}}},
		{"capture", zp.HookStagePostAuth, zp.Capture()},
		{"req hdrs", zp.HookStagePreAuth, req(zp.HeaderOps{Add: map[string]string{"x-bot-score": "3"}, Remove: []string{"Cookie"}})},
		{"rewrite", zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{Path: str("/new/path"), Query: str("a=1&b=2")}}},
		{"resp hdrs", zp.HookStageResponse, res(zp.HeaderOps{Set: map[string]string{"X-Frame-Options": "DENY"}, Add: map[string]string{"Set-Cookie": "plugin=1"}, Remove: []string{"Server"}})},
	}
	for _, c := range good {
		if _, err := sanitizeVerdict(c.stage, c.v); err != nil {
			t.Errorf("%s: unexpected rejection: %v", c.name, err)
		}
	}
}

func TestApplyRequestModifyKeepsHost(t *testing.T) {
	r := newReq("GET", "http://app.example.com/old?x=1", "")
	r.Header.Set("Cookie", "a=b")
	path, q := "/new path/é", "k=v&z=1"
	cv, err := sanitizeVerdict(zp.HookStagePreAuth, &zp.FilterVerdict{Action: "modify", Modify: &zp.ModifyAction{
		Path: &path, Query: &q,
		RequestHeaders: &zp.HeaderOps{Set: map[string]string{"x-a": "1"}, Add: map[string]string{"x-a2": "2"}, Remove: []string{"cookie"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	applyRequestModify(r, cv)
	if r.Host != "app.example.com" || r.URL.Path != path || r.URL.RawQuery != q {
		t.Fatalf("rewrite wrong: host=%q url=%v", r.Host, r.URL)
	}
	if !strings.HasPrefix(r.RequestURI, "/new%20path/") || !strings.HasSuffix(r.RequestURI, "?k=v&z=1") {
		t.Fatalf("RequestURI not rebuilt: %q", r.RequestURI)
	}
	if r.Header.Get("X-A") != "1" || r.Header.Get("X-A2") != "2" || r.Header.Get("Cookie") != "" {
		t.Fatalf("headers wrong: %v", r.Header)
	}
	u, _ := url.ParseRequestURI(r.RequestURI)
	if u.Host != "" {
		t.Fatal("RequestURI must stay origin-form")
	}
}

/* Verdicts through the pipeline */

func TestVerdictAllowDenyModify(t *testing.T) {
	m := newHookTestManager(t)

	var gotReq zp.FilterRequest
	var gotHeaders http.Header
	addFakePlugin(t, m, "allow", preAuth(), func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		json.NewDecoder(r.Body).Decode(&gotReq)
		json.NewEncoder(w).Encode(zp.Allow())
	}, "t")

	r := newReq("GET", "http://app.example.com/p?q=1", "")
	w := httptest.NewRecorder()
	if res := m.RunRequestStage(w, r, []string{"t"}, "203.0.113.7", zp.HookStagePreAuth); res.Handled {
		t.Fatal("allow must continue")
	}
	if gotReq.Version != 1 || gotReq.Stage != zp.HookStagePreAuth || gotReq.Request.ClientIP != "203.0.113.7" ||
		gotReq.Request.Method != "GET" || gotReq.RequestID == "" || len(gotReq.BodyPreview) != 0 {
		t.Fatalf("filter request wrong: %+v", gotReq)
	}
	if gotHeaders.Get("X-Zoraxy-RequestID") != gotReq.RequestID || gotHeaders.Get("Content-Type") != "application/json" {
		t.Fatalf("request id header missing: %v", gotHeaders)
	}

	//deny
	m2 := newHookTestManager(t)
	addFakePlugin(t, m2, "deny", preAuth(), verdictHandler(&zp.FilterVerdict{Version: 1, Action: "deny", Reason: "bad bot\n",
		Deny: &zp.DenyAction{Status: 429, Body: "go away", Headers: map[string]string{"Retry-After": "9"}}}, nil), "t")
	w = httptest.NewRecorder()
	res := m2.RunRequestStage(w, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if !res.Handled || !res.Denied || res.Status != 429 || res.PluginID != "deny" {
		t.Fatalf("result %+v", res)
	}
	if w.Code != 429 || w.Body.String() != "go away" || w.Header().Get("Retry-After") != "9" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("deny response wrong: %d %q %v", w.Code, w.Body.String(), w.Header())
	}

	//modify
	m3 := newHookTestManager(t)
	path := "/rewritten"
	addFakePlugin(t, m3, "mod", preAuth(), verdictHandler(&zp.FilterVerdict{Version: 1, Action: "modify", Modify: &zp.ModifyAction{
		Path: &path, RequestHeaders: &zp.HeaderOps{Set: map[string]string{"X-Bot-Score": "7"}},
	}}, nil), "t")
	r = newReq("GET", "http://app/orig", "")
	w = httptest.NewRecorder()
	if res := m3.RunRequestStage(w, r, []string{"t"}, "1.1.1.1", zp.HookStagePreAuth); res.Handled {
		t.Fatal("modify must continue")
	}
	if r.URL.Path != "/rewritten" || r.Header.Get("X-Bot-Score") != "7" {
		t.Fatalf("modification not applied: %v %v", r.URL, r.Header)
	}
}

func TestInvalidVerdictIsAFailureAndLeavesRequestUntouched(t *testing.T) {
	m := newHookTestManager(t)
	addFakePlugin(t, m, "evil", preAuth(), verdictHandler(&zp.FilterVerdict{Version: 1, Action: "modify", Modify: &zp.ModifyAction{
		RequestHeaders: &zp.HeaderOps{Set: map[string]string{"X-Ok": "1", "Host": "evil.com"}},
	}}, nil), "t")
	r := newReq("GET", "http://app/", "")
	w := httptest.NewRecorder()
	res := m.RunRequestStage(w, r, []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if res.Handled || r.Header.Get("X-Ok") != "" || r.Host != "app" {
		t.Fatal("invalid verdict must not be partially applied")
	}
	if m.LoadedPlugins["evil"].hook.consecFail != 1 {
		t.Fatal("invalid verdict must count as failure")
	}
}

func TestCaptureVerdictStages(t *testing.T) {
	m := newHookTestManager(t)
	hooks := &zp.HookSettings{Stages: []zp.HookStage{zp.HookStagePreAuth, zp.HookStagePostAuth}, FilterRequestPath: "/filter"}
	var ingressHits int32
	p := addFakePlugin(t, m, "cap", hooks, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ingress") {
			atomic.AddInt32(&ingressHits, 1)
			if r.Header.Get("X-Zoraxy-RequestID") == "" || r.Header.Get(zp.InvokeTokenHeader) != "sekret" {
				t.Error("capture ingress must get request id and token")
			}
			w.WriteHeader(218)
			return
		}
		json.NewEncoder(w).Encode(zp.Capture())
	}, "t")
	p.Spec.DynamicCaptureIngress = "/ingress"
	p.Spec.DynamicCaptureSniff = "/sniff"
	p.hook.token = "sekret"
	if err := p.StartDynamicForwardRouter(); err != nil {
		t.Fatal(err)
	}

	//pre_auth: capture would skip authentication, must be ignored
	w := httptest.NewRecorder()
	if res := m.RunRequestStage(w, newReq("GET", "http://app/x", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth); res.Handled {
		t.Fatal("capture at pre_auth must be ignored")
	}
	//post_auth: proxied to the plugin ingress
	w = httptest.NewRecorder()
	if res := m.RunRequestStage(w, newReq("GET", "http://app/x", ""), []string{"t"}, "1.1.1.1", zp.HookStagePostAuth); !res.Handled {
		t.Fatal("capture at post_auth must be handled")
	}
	if w.Code != 218 || ingressHits != 1 {
		t.Fatalf("code=%d hits=%d", w.Code, ingressHits)
	}
}

/* Body preview */

func TestBodyPreview(t *testing.T) {
	m := newHookTestManager(t)
	var got zp.FilterRequest
	var calls int32
	addFakePlugin(t, m, "body", preAuth(func(h *zp.HookSettings) {
		h.BodyPreviewBytes = 10
		h.BodyContentTypes = []string{"application/json", "text/*"}
	}), func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		got = zp.FilterRequest{}
		json.NewDecoder(r.Body).Decode(&got)
		json.NewEncoder(w).Encode(zp.Allow())
	}, "t")

	run := func(method, ct, body string) (*http.Request, zp.FilterRequest) {
		r := newReq(method, "http://app/", body)
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		m.RunRequestStage(httptest.NewRecorder(), r, []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
		return r, got
	}

	r, fr := run("POST", "application/json; charset=utf-8", `{"a":"0123456789"}`)
	if string(fr.BodyPreview) != `{"a":"0123` || !fr.BodyTruncated {
		t.Fatalf("preview %q truncated=%v", fr.BodyPreview, fr.BodyTruncated)
	}
	all, _ := io.ReadAll(r.Body)
	if string(all) != `{"a":"0123456789"}` {
		t.Fatalf("upstream must still receive the whole body, got %q", all)
	}

	_, fr = run("PUT", "text/plain", "short")
	if string(fr.BodyPreview) != "short" || fr.BodyTruncated {
		t.Fatalf("short body: %q %v", fr.BodyPreview, fr.BodyTruncated)
	}
	if _, fr = run("POST", "image/png", "binary"); len(fr.BodyPreview) != 0 {
		t.Fatal("content type not listed must not leak the body")
	}
	if _, fr = run("POST", "", "nocontenttype"); len(fr.BodyPreview) != 0 {
		t.Fatal("missing content type must not leak the body")
	}
	if _, fr = run("GET", "application/json", ""); len(fr.BodyPreview) != 0 {
		t.Fatal("GET has no body")
	}
}

func TestBodyPreviewDefaultsAndCaps(t *testing.T) {
	h := &zp.HookSettings{BodyContentTypes: []string{"application/json"}}
	if h.EffectiveBodyPreviewBytes() != 0 || h.WantsBodyFor("application/json") {
		t.Fatal("default must be no body")
	}
	h.BodyPreviewBytes = 1 << 30
	if h.EffectiveBodyPreviewBytes() != 64*1024 {
		t.Fatal("cap is 64KiB")
	}
	h.BodyContentTypes = []string{"*/*"}
	if h.WantsBodyFor("application/json") {
		t.Fatal("wildcard-everything must not be accepted")
	}

	//large body: only limit+1 bytes read ahead, rest streamed intact
	m := newHookTestManager(t)
	var got zp.FilterRequest
	addFakePlugin(t, m, "big", preAuth(func(h *zp.HookSettings) {
		h.BodyPreviewBytes = 1 << 20
		h.BodyContentTypes = []string{"application/octet-stream"}
	}), func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		json.NewEncoder(w).Encode(zp.Allow())
	}, "t")
	big := strings.Repeat("x", 200*1024)
	r := newReq("POST", "http://app/", big)
	r.Header.Set("Content-Type", "application/octet-stream")
	m.RunRequestStage(httptest.NewRecorder(), r, []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if len(got.BodyPreview) != 64*1024 || !got.BodyTruncated {
		t.Fatalf("preview len %d", len(got.BodyPreview))
	}
	all, _ := io.ReadAll(r.Body)
	if string(all) != big {
		t.Fatal("body corrupted")
	}
}

/* Timeouts, circuit breaker, failure policy */

func TestTimeoutFailOpenAndFailClosedConsent(t *testing.T) {
	m := newHookTestManager(t)
	m.hookCfg = hookTunables{BreakerThreshold: 100}
	slow := func(w http.ResponseWriter, r *http.Request) { time.Sleep(400 * time.Millisecond) }
	addFakePlugin(t, m, "slow", preAuth(func(h *zp.HookSettings) {
		h.TimeoutMs = 50
		h.FailurePolicy = zp.FailureClosed
	}), slow, "t")
	p := m.LoadedPlugins["slow"]

	//declared fail_closed but no admin consent: still fail open
	start := time.Now()
	w := httptest.NewRecorder()
	if res := m.RunRequestStage(w, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth); res.Handled {
		t.Fatal("fail_closed without consent must fail open")
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("timeout not enforced, took %v", d)
	}
	if p.failsClosed() {
		t.Fatal("plugin must not be able to make itself fail closed")
	}

	//consent gate
	yes := true
	if err := m.SetHookAdminSettings("slow", nil, &yes); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	res := m.RunRequestStage(w, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if !res.Handled || w.Code != 503 || !res.Denied {
		t.Fatalf("fail_closed with consent must answer 503, got handled=%v code=%d", res.Handled, w.Code)
	}
	if st := p.hookAdminState(); st.EffectivePolicy != "fail_closed" || !st.FailClosedDeclared {
		t.Fatalf("state %+v", st)
	}
}

func TestConsentOnlyForDeclaredFailClosed(t *testing.T) {
	m := newHookTestManager(t)
	addFakePlugin(t, m, "open", preAuth(), verdictHandler(zp.Allow(), nil), "t")
	yes := true
	if err := m.SetHookAdminSettings("open", nil, &yes); err == nil {
		t.Fatal("consent for a plugin that does not declare fail_closed must be refused")
	}
	if m.LoadedPlugins["open"].failsClosed() {
		t.Fatal("must stay fail-open")
	}
	if err := m.SetHookAdminSettings("missing", &yes, nil); err == nil {
		t.Fatal("unknown plugin must error")
	}
	//plugin without hooks or dynamic capture cannot be global
	m.LoadedPlugins["plain"] = &Plugin{Spec: &zp.IntroSpect{ID: "plain", Type: zp.PluginType_Router}}
	if err := m.SetHookAdminSettings("plain", &yes, nil); err == nil {
		t.Fatal("plugin without hooks cannot be attached globally")
	}
}

func TestCircuitBreaker(t *testing.T) {
	m := newHookTestManager(t)
	m.hookCfg = hookTunables{BreakerThreshold: 3, BreakerCooldown: 150 * time.Millisecond}
	var calls int32
	var healthy atomic.Bool
	addFakePlugin(t, m, "flaky", preAuth(), func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if !healthy.Load() {
			http.Error(w, "boom", 500)
			return
		}
		json.NewEncoder(w).Encode(zp.Deny(403, "no"))
	}, "t")
	run := func() StageResult {
		return m.RunRequestStage(httptest.NewRecorder(), newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	}
	for i := 0; i < 3; i++ {
		if run().Handled {
			t.Fatal("failures fail open")
		}
	}
	if calls != 3 {
		t.Fatalf("calls %d", calls)
	}
	for i := 0; i < 10; i++ {
		run()
	}
	if calls != 3 {
		t.Fatalf("open breaker must skip the plugin, calls=%d", calls)
	}
	if !m.LoadedPlugins["flaky"].hookAdminState().BreakerOpen {
		t.Fatal("state must report the open breaker")
	}

	//after the cooldown a single probe goes through; still failing -> re-open
	time.Sleep(200 * time.Millisecond)
	run()
	run()
	if calls != 4 {
		t.Fatalf("exactly one probe expected, calls=%d", calls)
	}
	//recovery
	healthy.Store(true)
	time.Sleep(200 * time.Millisecond)
	if res := run(); !res.Denied {
		t.Fatal("probe must succeed and apply the verdict")
	}
	if res := run(); !res.Denied {
		t.Fatal("breaker must be closed again")
	}
}

func TestBreakerOpenFailClosedStillBlocks(t *testing.T) {
	m := newHookTestManager(t)
	m.hookCfg = hookTunables{BreakerThreshold: 1, BreakerCooldown: time.Minute}
	var calls int32
	addFakePlugin(t, m, "strict", preAuth(func(h *zp.HookSettings) { h.FailurePolicy = zp.FailureClosed }),
		func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&calls, 1); http.Error(w, "x", 500) }, "t")
	yes := true
	m.SetHookAdminSettings("strict", nil, &yes)
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		m.RunRequestStage(w, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
		if w.Code != 503 {
			t.Fatalf("iteration %d: code %d", i, w.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("breaker should have stopped calls, got %d", calls)
	}
}

func TestPluginDownDoesNotHang(t *testing.T) {
	m := newHookTestManager(t)
	p := addFakePlugin(t, m, "gone", preAuth(), verdictHandler(zp.Allow(), nil), "t")
	p.AssignedPort = 1 //nothing listens there
	start := time.Now()
	res := m.RunRequestStage(httptest.NewRecorder(), newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if res.Handled || time.Since(start) > 3*time.Second {
		t.Fatal("unreachable plugin must fail open quickly")
	}
}

func TestOversizedVerdictRejected(t *testing.T) {
	m := newHookTestManager(t)
	addFakePlugin(t, m, "huge", preAuth(), func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"action":"allow","reason":"` + strings.Repeat("a", zp.MaxVerdictBytes+10) + `"}`))
	}, "t")
	m.RunRequestStage(httptest.NewRecorder(), newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if m.LoadedPlugins["huge"].hook.consecFail != 1 {
		t.Fatal("oversized verdict must be a failure")
	}
}

/* Legacy sniff */

func TestLegacySniffTimeoutAndSkip(t *testing.T) {
	m := newHookTestManager(t)
	var mode atomic.Int32 //0 accept, 1 skip, 2 hang
	p := addFakePlugin(t, m, "legacy", &zp.HookSettings{TimeoutMs: 80}, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ingress") {
			w.WriteHeader(219)
			return
		}
		switch mode.Load() {
		case 1:
			w.WriteHeader(501)
		case 2:
			time.Sleep(500 * time.Millisecond)
		}
	}, "t")
	p.Spec.DynamicCaptureSniff = "/sniff"
	p.Spec.DynamicCaptureIngress = "/ingress"
	p.StartDynamicForwardRouter()

	serve := func() (bool, int, time.Duration) {
		w := httptest.NewRecorder()
		s := time.Now()
		ok := m.HandleRoute(w, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1")
		return ok, w.Code, time.Since(s)
	}
	if ok, code, _ := serve(); !ok || code != 219 {
		t.Fatalf("accept: %v %d", ok, code)
	}
	mode.Store(1)
	if ok, _, _ := serve(); ok {
		t.Fatal("501 is skip")
	}
	mode.Store(2)
	ok, _, d := serve()
	if ok || d > 400*time.Millisecond {
		t.Fatalf("hanging sniff must time out and skip: ok=%v d=%v", ok, d)
	}
}

/* Global plugins and opt-out */

func TestGlobalPluginAndOptOut(t *testing.T) {
	m := newHookTestManager(t)
	var calls int32
	addFakePlugin(t, m, "g", preAuth(), verdictHandler(zp.Deny(403, "g"), &calls)) //no tag
	run := func(tags ...string) bool {
		return m.RunRequestStage(httptest.NewRecorder(), newReq("GET", "http://app/", ""), tags, "1.1.1.1", zp.HookStagePreAuth).Handled
	}

	if run("anything") || run() || calls != 0 {
		t.Fatal("not global by default")
	}
	yes, no := true, false
	if err := m.SetHookAdminSettings("g", &yes, nil); err != nil {
		t.Fatal(err)
	}
	if !run() || !run("unrelated") {
		t.Fatal("global plugin must apply to endpoints without tags")
	}
	if run("no-global-plugins") || run("x", "no-global-plugins") {
		t.Fatal("no-global-plugins opts out")
	}
	if run("no-plugin:g") {
		t.Fatal("no-plugin:<id> opts out")
	}
	if !run("no-plugin:other") {
		t.Fatal("opt-out of another plugin must not matter")
	}
	m.SetHookAdminSettings("g", &no, nil)
	if run() {
		t.Fatal("global off again")
	}
	//a tagged plugin is also excluded by its explicit opt-out
	m.Options.PluginGroups["t"] = []string{"g"}
	m.UpdateTagsToPluginMaps()
	if !run("t") || run("t", "no-plugin:g") {
		t.Fatal("tag attach / opt-out wrong")
	}
	//no double call when both tagged and global
	m.SetHookAdminSettings("g", &yes, nil)
	atomic.StoreInt32(&calls, 0)
	run("t")
	if calls != 1 {
		t.Fatalf("plugin called %d times", calls)
	}
}

func TestDisabledPluginNeverCalled(t *testing.T) {
	m := newHookTestManager(t)
	var calls int32
	p := addFakePlugin(t, m, "off", preAuth(), verdictHandler(zp.Deny(403, ""), &calls), "t")
	p.Enabled = false
	if m.RunRequestStage(httptest.NewRecorder(), newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth).Handled || calls != 0 {
		t.Fatal("disabled plugin must be skipped")
	}
}

/* Ordering and concurrency */

func TestPriorityOrderAndConcurrentCalls(t *testing.T) {
	m := newHookTestManager(t)
	delay := func(v *zp.FilterVerdict) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			json.NewEncoder(w).Encode(v)
		}
	}
	//registered in "wrong" order on purpose
	addFakePlugin(t, m, "late", preAuth(func(h *zp.HookSettings) { h.Priority = 20 }), delay(zp.Deny(418, "late")), "t")
	addFakePlugin(t, m, "early", preAuth(func(h *zp.HookSettings) { h.Priority = 5 }), delay(zp.Deny(451, "early")), "t")
	addFakePlugin(t, m, "mid", preAuth(func(h *zp.HookSettings) { h.Priority = 10 }), delay(zp.Allow()), "t")

	names := []string{}
	for _, p := range m.pluginsForRequest([]string{"t"}) {
		names = append(names, p.Spec.ID)
	}
	if strings.Join(names, ",") != "early,mid,late" {
		t.Fatalf("order %v", names)
	}

	start := time.Now()
	w := httptest.NewRecorder()
	res := m.RunRequestStage(w, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if d := time.Since(start); d > 550*time.Millisecond {
		t.Fatalf("plugins of one stage must run concurrently, took %v", d)
	}
	if res.PluginID != "early" || w.Code != 451 {
		t.Fatalf("highest priority deny must win: %+v code=%d", res, w.Code)
	}
}

func TestSamePriorityIsDeterministic(t *testing.T) {
	m := newHookTestManager(t)
	for _, id := range []string{"c", "a", "b"} {
		addFakePlugin(t, m, id, preAuth(), verdictHandler(zp.Allow(), nil))
		m.Options.PluginGroups["g"] = nil
	}
	yes := true
	for _, id := range []string{"c", "a", "b"} {
		m.SetHookAdminSettings(id, &yes, nil)
	}
	for i := 0; i < 20; i++ {
		var names string
		for _, p := range m.pluginsForRequest(nil) {
			names += p.Spec.ID
		}
		if names != "abc" {
			t.Fatalf("global ties must be ordered by ID, got %s", names)
		}
	}
}

func TestModifiesApplyInPriorityOrder(t *testing.T) {
	m := newHookTestManager(t)
	set := func(v string) http.HandlerFunc {
		return verdictHandler(zp.ModifyRequestHeaders(zp.HeaderOps{Set: map[string]string{"X-Winner": v}}), nil)
	}
	addFakePlugin(t, m, "p2", preAuth(func(h *zp.HookSettings) { h.Priority = 2 }), set("second"), "t")
	addFakePlugin(t, m, "p1", preAuth(func(h *zp.HookSettings) { h.Priority = 1 }), set("first"), "t")
	r := newReq("GET", "http://app/", "")
	m.RunRequestStage(httptest.NewRecorder(), r, []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if r.Header.Get("X-Winner") != "second" {
		t.Fatalf("later priority applies last, got %q", r.Header.Get("X-Winner"))
	}
}

func TestStableRequestIDAcrossStagesAndNotSpoofable(t *testing.T) {
	m := newHookTestManager(t)
	var mu sync.Mutex
	var ids []string
	hooks := &zp.HookSettings{Stages: []zp.HookStage{zp.HookStagePreAuth, zp.HookStagePostAuth, zp.HookStageResponse}, FilterRequestPath: "/f"}
	addFakePlugin(t, m, "ids", hooks, func(w http.ResponseWriter, r *http.Request) {
		var fr zp.FilterRequest
		json.NewDecoder(r.Body).Decode(&fr)
		mu.Lock()
		ids = append(ids, r.Header.Get("X-Zoraxy-RequestID"), fr.RequestID)
		mu.Unlock()
		json.NewEncoder(w).Encode(zp.Allow())
	}, "t")
	r := newReq("GET", "http://app/", "")
	r.Header.Set("X-Zoraxy-RequestID", "client-supplied")
	rec := httptest.NewRecorder()
	m.RunRequestStage(rec, r, []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	m.HandleStage(rec, r, []string{"t"}, "1.1.1.1", zp.HookStagePostAuth)
	ww := m.WrapResponse(rec, r, []string{"t"}, "1.1.1.1")
	ww.WriteHeader(200)
	if len(ids) != 6 {
		t.Fatalf("expected 3 calls, ids=%v", ids)
	}
	for _, id := range ids {
		if id != ids[0] || id == "client-supplied" || id == "" {
			t.Fatalf("request id must be stable and server generated: %v", ids)
		}
	}
}

func TestInvokeTokenSent(t *testing.T) {
	m := newHookTestManager(t)
	var tok string
	p := addFakePlugin(t, m, "tok", preAuth(), func(w http.ResponseWriter, r *http.Request) {
		tok = r.Header.Get(zp.InvokeTokenHeader)
		json.NewEncoder(w).Encode(zp.Allow())
	}, "t")
	generated, err := p.generateInvokeToken()
	if err != nil || len(generated) < 32 {
		t.Fatalf("token %q %v", generated, err)
	}
	m.RunRequestStage(httptest.NewRecorder(), newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
	if tok != generated {
		t.Fatalf("token header %q want %q", tok, generated)
	}
	other, _ := p.generateInvokeToken()
	if other == generated {
		t.Fatal("tokens must be random per start")
	}
}

func TestSDKTokenVerification(t *testing.T) {
	h := zp.NewFilterHandler("s3", func(fr *zp.FilterRequest) *zp.FilterVerdict { return zp.Deny(403, "x") })
	call := func(tok string) int {
		r := httptest.NewRequest("POST", "/filter", strings.NewReader(`{"version":1}`))
		if tok != "" {
			r.Header.Set(zp.InvokeTokenHeader, tok)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if call("") != 403 || call("wrong") != 403 {
		t.Fatal("missing / wrong token must be refused")
	}
	if call("s3") != 200 {
		t.Fatal("right token accepted")
	}
}

/* Response stage */

func responsePlugin(t testing.TB, m *Manager, id string, v *zp.FilterVerdict, hookMods ...func(*zp.HookSettings)) *Plugin {
	h := &zp.HookSettings{Stages: []zp.HookStage{zp.HookStageResponse}, FilterRequestPath: "/f"}
	for _, f := range hookMods {
		f(h)
	}
	return addFakePlugin(t, m, id, h, func(w http.ResponseWriter, r *http.Request) {
		var fr zp.FilterRequest
		json.NewDecoder(r.Body).Decode(&fr)
		if fr.Stage != zp.HookStageResponse || fr.Response == nil || fr.Response.Status != 201 {
			t.Errorf("response stage payload wrong: %+v", fr)
		}
		json.NewEncoder(w).Encode(v)
	}, "t")
}

func TestResponseHeaderModification(t *testing.T) {
	m := newHookTestManager(t)
	responsePlugin(t, m, "hdr", zp.ModifyResponseHeaders(zp.HeaderOps{
		Set:    map[string]string{"X-Frame-Options": "DENY", "Server": "hidden"},
		Add:    map[string]string{"Set-Cookie": "plugin=1", "X-Added": "yes"},
		Remove: []string{"X-Powered-By"},
	}))
	r := newReq("GET", "http://app/", "")
	rec := httptest.NewRecorder()
	w := m.WrapResponse(rec, r, []string{"t"}, "1.1.1.1")
	if w == http.ResponseWriter(rec) {
		t.Fatal("expected wrapper")
	}
	rec.Header().Set("X-Powered-By", "php")
	rec.Header().Set("Server", "nginx")
	rec.Header().Add("Set-Cookie", "zoraxy_sso=abc")
	w.WriteHeader(201)
	w.Write([]byte("body"))
	if rec.Code != 201 || rec.Body.String() != "body" {
		t.Fatalf("code/body altered: %d %q", rec.Code, rec.Body.String())
	}
	h := rec.Header()
	if h.Get("X-Frame-Options") != "DENY" || h.Get("Server") != "hidden" || h.Get("X-Added") != "yes" || h.Get("X-Powered-By") != "" {
		t.Fatalf("headers wrong: %v", h)
	}
	if cookies := h.Values("Set-Cookie"); len(cookies) != 2 || cookies[0] != "zoraxy_sso=abc" {
		t.Fatalf("existing cookies must be preserved: %v", cookies)
	}
}

func TestResponseStageNoopWithoutPlugins(t *testing.T) {
	m := newHookTestManager(t)
	addFakePlugin(t, m, "pre", preAuth(), verdictHandler(zp.Allow(), nil), "t")
	rec := httptest.NewRecorder()
	if m.WrapResponse(rec, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1") != http.ResponseWriter(rec) {
		t.Fatal("no response plugin: writer must be returned unchanged")
	}
}

func TestResponseForbiddenOpsFailureAndPolicy(t *testing.T) {
	m := newHookTestManager(t)
	responsePlugin(t, m, "cookie", zp.ModifyResponseHeaders(zp.HeaderOps{Remove: []string{"Set-Cookie"}}),
		func(h *zp.HookSettings) { h.FailurePolicy = zp.FailureClosed })
	run := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		w := m.WrapResponse(rec, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1")
		rec.Header().Add("Set-Cookie", "zoraxy_sso=abc")
		w.WriteHeader(201)
		w.Write([]byte("upstream body"))
		return rec
	}
	//fail open (no consent): upstream response untouched, auth cookie intact
	rec := run()
	if rec.Code != 201 || rec.Body.String() != "upstream body" || rec.Header().Get("Set-Cookie") != "zoraxy_sso=abc" {
		t.Fatalf("fail open broken: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	//fail closed with consent: 502, no upstream body or cookie
	yes := true
	m.SetHookAdminSettings("cookie", nil, &yes)
	rec = run()
	if rec.Code != 502 || strings.Contains(rec.Body.String(), "upstream") || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("fail closed broken: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
}

func TestResponseWriterPassthroughs(t *testing.T) {
	m := newHookTestManager(t)
	p := responsePlugin(t, m, "pt", zp.Allow())
	_ = p
	rec := httptest.NewRecorder()
	w := m.WrapResponse(rec, newReq("GET", "http://app/", ""), []string{"t"}, "1.1.1.1")
	w.WriteHeader(103) //informational passes through without consulting the plugin
	if _, ok := w.(http.Flusher); !ok {
		t.Fatal("wrapper must be a Flusher")
	}
	if _, ok := w.(http.Hijacker); !ok {
		t.Fatal("wrapper must be a Hijacker")
	}
	if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok || u.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("wrapper must Unwrap")
	}
	//implicit 200 on first Write runs the hook (plugin asserts status 201 -> would flag), so only check no panic path via Flush
	w.WriteHeader(201)
	w.(http.Flusher).Flush()
}

/* Race */

func TestConcurrentRequestsRace(t *testing.T) {
	m := newHookTestManager(t)
	m.hookCfg = hookTunables{BreakerThreshold: 2, BreakerCooldown: 20 * time.Millisecond}
	var flip atomic.Int32
	addFakePlugin(t, m, "r1", preAuth(), func(w http.ResponseWriter, r *http.Request) {
		if flip.Add(1)%3 == 0 {
			http.Error(w, "x", 500)
			return
		}
		json.NewEncoder(w).Encode(zp.ModifyRequestHeaders(zp.HeaderOps{Set: map[string]string{"X-R": "1"}}))
	}, "t")
	addFakePlugin(t, m, "r2", preAuth(func(h *zp.HookSettings) { h.Priority = 1 }), verdictHandler(zp.Allow(), nil))
	yes := true
	m.SetHookAdminSettings("r2", &yes, nil)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				r := newReq("POST", "http://app/", "body")
				m.RunRequestStage(httptest.NewRecorder(), r, []string{"t"}, "1.1.1.1", zp.HookStagePreAuth)
				m.HandleRoute(httptest.NewRecorder(), r, []string{"t"}, "1.1.1.1")
			}
		}()
	}
	wg.Add(1)
	go func() { //admin toggles while traffic flows
		defer wg.Done()
		no := false
		for i := 0; i < 50; i++ {
			m.SetHookAdminSettings("r2", &no, nil)
			m.SetHookAdminSettings("r2", &yes, nil)
			m.UpdateTagsToPluginMaps()
		}
	}()
	wg.Wait()
}
