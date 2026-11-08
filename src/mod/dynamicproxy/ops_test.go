package dynamicproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/rewrite"
)

func opsBackend(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

func errPagesOn(statuses ...int) *OpsConfig {
	return &OpsConfig{ErrorPages: &ErrorPagesConfig{Mode: ErrorPagesOn, Statuses: statuses,
		Template: `<h1>{{.Status}}</h1><i>{{.Host}}{{.Path}}</i><b>{{.RequestID}}</b>`}}
}

func TestErrorPage_ReplacesUpstreamErrorBody(t *testing.T) {
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "abc")
		w.WriteHeader(503)
		w.Write([]byte(`{"secret":"upstream stack trace"}`))
	})
	router, sep := newOpsTestRouter(t, be)
	sep.Ops = errPagesOn(502, 503)
	sep.Ops.ErrorPages.RetryAfterSeconds = 30
	w := serveOps(router, "GET", "/x<script>", nil)
	body := w.Body.String()
	if w.Code != 503 || strings.Contains(body, "secret") || !strings.Contains(body, "<h1>503</h1>") {
		t.Fatalf("got %d %q", w.Code, body)
	}
	if strings.Contains(body, "<script>") {
		t.Fatalf("path not escaped: %q", body)
	}
	if w.Header().Get("Retry-After") != "30" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Etag") != "" {
		t.Fatalf("headers: %v", w.Header())
	}
	if w.Header().Get("Content-Length") == "" {
		t.Fatal("content length missing")
	}
}

func TestErrorPage_UnlistedStatusAndSuccessPassThrough(t *testing.T) {
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/404" {
			w.WriteHeader(404)
			w.Write([]byte("upstream 404"))
			return
		}
		w.Write([]byte("fine"))
	})
	router, sep := newOpsTestRouter(t, be)
	sep.Ops = errPagesOn(502)
	if w := serveOps(router, "GET", "/404", nil); w.Code != 404 || w.Body.String() != "upstream 404" {
		t.Fatalf("unlisted: %d %q", w.Code, w.Body.String())
	}
	if w := serveOps(router, "GET", "/", nil); w.Code != 200 || w.Body.String() != "fine" {
		t.Fatalf("success: %d %q", w.Code, w.Body.String())
	}
}

func TestErrorPage_StreamingAndGRPCNotIntercepted(t *testing.T) {
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(503)
			w.Write([]byte("data: keep\n\n"))
		case "/grpc":
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "14")
			w.WriteHeader(503)
			w.Write([]byte("grpcbody"))
		default:
			w.WriteHeader(503)
			w.Write([]byte("upstream"))
		}
	})
	router, sep := newOpsTestRouter(t, be)
	sep.Ops = errPagesOn(503)
	if w := serveOps(router, "GET", "/sse", nil); !strings.Contains(w.Body.String(), "data: keep") {
		t.Fatalf("SSE intercepted: %q", w.Body.String())
	}
	if w := serveOps(router, "GET", "/grpc", nil); w.Body.String() != "grpcbody" {
		t.Fatalf("grpc intercepted: %q", w.Body.String())
	}
	if w := serveOps(router, "POST", "/other", map[string]string{"Content-Type": "application/grpc"}); w.Body.String() != "upstream" {
		t.Fatalf("grpc request intercepted: %q", w.Body.String())
	}
}

func TestErrorPage_OwnErrorsAndGlobalDefault(t *testing.T) {
	router, sep := newOpsTestRouter(t, "127.0.0.1:1") //nothing listens: connection refused -> 521
	if w := serveOps(router, "GET", "/", nil); w.Code != 521 || strings.Contains(w.Body.String(), "<h1>521</h1>") {
		t.Fatalf("baseline %d", w.Code)
	}
	if err := SetGlobalErrorPages(&ErrorPagesConfig{Mode: ErrorPagesOn, Statuses: []int{521}, Template: "GLOBAL {{.Status}}"}); err != nil {
		t.Fatal(err)
	}
	defer SetGlobalErrorPages(nil)
	if w := serveOps(router, "GET", "/", nil); w.Code != 521 || w.Body.String() != "GLOBAL 521" {
		t.Fatalf("global default not used: %d %q", w.Code, w.Body.String())
	}
	sep.Ops = &OpsConfig{ErrorPages: &ErrorPagesConfig{Mode: ErrorPagesOff}}
	if w := serveOps(router, "GET", "/", nil); w.Body.String() == "GLOBAL 521" {
		t.Fatal("per rule off must override the global default")
	}
	sep.Ops = errPagesOn(521)
	if w := serveOps(router, "GET", "/", nil); !strings.Contains(w.Body.String(), "<h1>521</h1>") {
		t.Fatalf("per rule must override global: %q", w.Body.String())
	}
}

func TestErrorPage_AuthChallengeIsNeverReplaced(t *testing.T) {
	router, sep := newOpsTestRouter(t, "127.0.0.1:1")
	sep.AuthenticationProvider = &AuthenticationProvider{AuthMethod: AuthMethodBasic, BasicAuthCredentials: []*BasicAuthCredentials{{Username: "u", PasswordHash: "x"}}}
	sep.Ops = errPagesOn(401, 403)
	w := serveOps(router, "GET", "/", nil)
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" || strings.Contains(w.Body.String(), "<h1>") {
		t.Fatalf("auth challenge was altered: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
}

func TestErrorPageTemplateValidation(t *testing.T) {
	if (&ErrorPagesConfig{Mode: "on", Template: "{{.Nope"}).Validate() == nil {
		t.Error("broken template accepted")
	}
	if (&ErrorPagesConfig{Mode: "on", Template: strings.Repeat("a", MaxOpsTemplateBytes+1)}).Validate() == nil {
		t.Error("oversize template accepted")
	}
	if (&ErrorPagesConfig{Mode: "on", Statuses: []int{200}}).Validate() == nil {
		t.Error("2xx accepted")
	}
	if (&ErrorPagesConfig{Mode: "on", Template: "{{.Missing}}"}).Validate() == nil {
		t.Error("unknown field accepted")
	}
	out, err := RenderErrorPagePreview("<p>{{.Host}}</p>", 502)
	if err != nil || !strings.Contains(out, "app.example.com") {
		t.Errorf("preview: %v %q", err, out)
	}
}

func TestStaticResponses(t *testing.T) {
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("upstream")) })
	router, sep := newOpsTestRouter(t, be)
	sep.AuthenticationProvider = &AuthenticationProvider{AuthMethod: AuthMethodBasic, BasicAuthCredentials: []*BasicAuthCredentials{{Username: "u", PasswordHash: "x"}}}
	sep.Ops = &OpsConfig{StaticResponses: []*StaticResponse{
		{Path: "/robots.txt", Body: "User-agent: *\nDisallow: /\n", Public: true},
		{Path: "/healthz", Status: 204, Public: true, Headers: []StaticHeader{{Name: "X-Probe", Value: "{{rule_name}}"}}},
		{Path: "/private/", MatchMode: "prefix", Body: "behind auth {{request_id}}"},
		{Path: "/old", Status: 301, Location: "https://example.org/new", Public: true},
	}}
	if err := sep.Ops.Validate(); err != nil {
		t.Fatal(err)
	}
	if w := serveOps(router, "GET", "/robots.txt", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Disallow") || w.Header().Get("Content-Type") == "" {
		t.Fatalf("robots: %d %q", w.Code, w.Body.String())
	}
	if w := serveOps(router, "HEAD", "/robots.txt", nil); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %q", w.Code, w.Body.String())
	}
	if w := serveOps(router, "GET", "/healthz", nil); w.Code != 204 || w.Body.Len() != 0 || w.Header().Get("X-Probe") != "app.example.com" {
		t.Fatalf("healthz: %d %v", w.Code, w.Header())
	}
	if w := serveOps(router, "GET", "/old", nil); w.Code != 301 || w.Header().Get("Location") != "https://example.org/new" {
		t.Fatalf("redirect: %d %v", w.Code, w.Header())
	}
	//non public: authentication first
	if w := serveOps(router, "GET", "/private/a", nil); w.Code != 401 {
		t.Fatalf("non public static must sit behind auth, got %d", w.Code)
	}
	//methods and non matches go on to the normal chain (here: auth)
	if w := serveOps(router, "POST", "/robots.txt", nil); w.Code != 401 {
		t.Fatalf("POST must not match a GET/HEAD static response, got %d", w.Code)
	}
	if w := serveOps(router, "GET", "/robots.txt/../secret", nil); w.Code == 200 && strings.Contains(w.Body.String(), "Disallow") {
		t.Fatal("traversal matched the static response")
	}
	if w := serveOps(router, "GET", "/robots.txtx", nil); w.Code != 401 {
		t.Fatalf("near miss matched: %d", w.Code)
	}
}

func TestStaticResponseValidation(t *testing.T) {
	bad := []*StaticResponse{
		{Path: "robots.txt"}, {Path: "/a?b"}, {Path: "/a", Status: 100}, {Path: "/a", Status: 302},
		{Path: "/a", Status: 302, Location: "//evil.example"}, {Path: "/a", Location: "/x\r\nSet-Cookie: a=b", Status: 302},
		{Path: "/a", Headers: []StaticHeader{{Name: "Content-Length", Value: "1"}}},
		{Path: "/a", Headers: []StaticHeader{{Name: "X-A", Value: "a\r\nb"}}},
		{Path: "/a", Headers: []StaticHeader{{Name: "X A", Value: "a"}}},
		{Path: "/a", ContentType: "text/plain\r\nX: y"},
		{Path: "/a", Body: strings.Repeat("x", MaxOpsBodyBytes+1)},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, s)
		}
	}
}

func TestCORSMatrix(t *testing.T) {
	hits := 0
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Access-Control-Allow-Origin", "https://upstream-set.example")
		w.Write([]byte("ok"))
	})
	router, sep := newOpsTestRouter(t, be)
	sep.Ops = &OpsConfig{CORS: &CORSConfig{Enabled: true,
		AllowedOrigins:   []string{"https://app.example.com", "https://*.trusted.example", `regex:https://dev[0-9]+\.example\.org`},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Content-Type", "X-Token"},
		ExposeHeaders:    []string{"X-Total"},
		AllowCredentials: true, MaxAgeSeconds: 600}}
	if err := sep.Ops.Validate(); err != nil {
		t.Fatal(err)
	}
	pre := func(origin, method, headers string) *httptest.ResponseRecorder {
		h := map[string]string{"Origin": origin, "Access-Control-Request-Method": method}
		if headers != "" {
			h["Access-Control-Request-Headers"] = headers
		}
		return serveOps(router, "OPTIONS", "/api", h)
	}
	// allowed preflight, answered without the upstream
	w := pre("https://app.example.com", "POST", "content-type, x-token")
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" ||
		w.Header().Get("Access-Control-Allow-Credentials") != "true" || w.Header().Get("Access-Control-Max-Age") != "600" ||
		w.Header().Get("Access-Control-Allow-Methods") != "GET, POST" {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Origin") {
		t.Fatalf("Vary: %v", w.Header().Values("Vary"))
	}
	if hits != 0 {
		t.Fatal("preflight reached the upstream")
	}
	for _, o := range []string{"https://a.trusted.example", "https://a.b.trusted.example", "https://dev12.example.org"} {
		if w := pre(o, "GET", ""); w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != o {
			t.Errorf("%s should be allowed: %d %v", o, w.Code, w.Header())
		}
	}
	for _, o := range []string{"https://evil.example", "https://trusted.example", "https://xtrusted.example", "http://app.example.com",
		"https://a.trusted.example.evil.com", "https://dev1x.example.org", "null"} {
		if w := pre(o, "GET", ""); w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s must be refused: %d %v", o, w.Code, w.Header())
		}
	}
	if w := pre("https://app.example.com", "DELETE", ""); w.Code != 403 {
		t.Errorf("method not allowed: %d", w.Code)
	}
	if w := pre("https://app.example.com", "GET", "x-evil"); w.Code != 403 {
		t.Errorf("header not allowed: %d", w.Code)
	}
	// actual requests
	w = serveOps(router, "GET", "/api", map[string]string{"Origin": "https://app.example.com"})
	if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" || w.Header().Get("Access-Control-Expose-Headers") != "X-Total" ||
		len(w.Header().Values("Access-Control-Allow-Origin")) != 1 {
		t.Fatalf("actual: %d %v", w.Code, w.Header())
	}
	w = serveOps(router, "GET", "/api", map[string]string{"Origin": "https://evil.example"})
	if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed origin got CORS headers (upstream's must be stripped too): %v", w.Header())
	}
	if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Origin") {
		t.Fatal("Vary: Origin missing on a non matching origin response")
	}
	// OPTIONS without preflight markers goes to the upstream
	before := hits
	serveOps(router, "OPTIONS", "/api", nil)
	if hits != before+1 {
		t.Fatal("plain OPTIONS must reach the upstream")
	}
}

func TestCORSWildcardAndCredentialsRules(t *testing.T) {
	if (&CORSConfig{Enabled: true, AllowedOrigins: []string{"*"}, AllowCredentials: true}).Validate() == nil {
		t.Fatal("* with credentials must be refused")
	}
	for _, o := range []string{"https://*", "*.example.com", "https://a.*.example.com", "https://x/path", "ftp"} {
		if (&CORSConfig{Enabled: true, AllowedOrigins: []string{o}}).Validate() == nil {
			t.Errorf("origin pattern %q accepted", o)
		}
	}
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	router, sep := newOpsTestRouter(t, be)
	sep.Ops = &OpsConfig{CORS: &CORSConfig{Enabled: true, AllowedOrigins: []string{"*"}}}
	w := serveOps(router, "OPTIONS", "/", map[string]string{"Origin": "https://any.example", "Access-Control-Request-Method": "GET"})
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	// runtime guard: even a hand edited config never answers * with credentials
	sep.Ops = &OpsConfig{CORS: &CORSConfig{Enabled: true, AllowedOrigins: []string{"*"}, AllowCredentials: true}}
	w = serveOps(router, "GET", "/", map[string]string{"Origin": "https://any.example"})
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("invalid config leaked: %v", w.Header())
	}
}

func TestCORSPreflightRespectsAccessList(t *testing.T) {
	router, sep := newOpsTestRouter(t, "127.0.0.1:1")
	rule, _ := router.Option.AccessController.GetAccessRuleByID("default")
	rule.BlacklistEnabled = true
	rule.AddIPToBlackList("198.51.100.1", "test")
	sep.Ops = &OpsConfig{CORS: &CORSConfig{Enabled: true, AllowedOrigins: []string{"*"}}}
	w := serveOps(router, "OPTIONS", "/", map[string]string{"Origin": "https://a.example", "Access-Control-Request-Method": "GET"})
	if w.Code != 403 || w.Header().Get("Access-Control-Max-Age") != "" || w.Header().Get("Access-Control-Allow-Methods") != "" {
		t.Fatalf("blacklisted client got a preflight answer: %d", w.Code)
	}
}

// ---- bandwidth ----

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestBandwidthLimitAccuracy(t *testing.T) {
	for _, rate := range []int64{1000, 64 * 1024, 5 * 1024 * 1024} {
		clk := &fakeClock{now: time.Unix(1000, 0)}
		rt := newBandwidthRuntime(&BandwidthConfig{BytesPerSecond: rate})
		rt.now, rt.sleep = clk.Now, clk.Sleep
		rec := httptest.NewRecorder()
		conn := rt.newConn("1.2.3.4", context.Background())
		total := int(rate) * 4
		start := clk.Now()
		n, err := conn.write(rec, make([]byte, total))
		if err != nil || n != total || rec.Body.Len() != total {
			t.Fatalf("rate %d: n=%d err=%v", rate, n, err)
		}
		el := clk.Now().Sub(start).Seconds()
		if el < 3.7 || el > 4.05 {
			t.Fatalf("rate %d: %d bytes took %.3fs, want about 4s", rate, total, el)
		}
	}
}

func TestBandwidthPerClientSharedAcrossConnections(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	rt := newBandwidthRuntime(&BandwidthConfig{PerClientBytesPerSecond: 10000})
	rt.now, rt.sleep = clk.Now, clk.Sleep
	a := rt.newConn("9.9.9.9", context.Background())
	b := rt.newConn("9.9.9.9", context.Background())
	other := rt.newConn("8.8.8.8", context.Background())
	start := clk.Now()
	a.write(httptest.NewRecorder(), make([]byte, 20000))
	b.write(httptest.NewRecorder(), make([]byte, 20000))
	if el := clk.Now().Sub(start).Seconds(); el < 3.6 || el > 4.1 {
		t.Fatalf("two connections of one client sent 40000 bytes in %.2fs, want about 4s", el)
	}
	start = clk.Now()
	other.write(httptest.NewRecorder(), make([]byte, 10000))
	if el := clk.Now().Sub(start).Seconds(); el > 1.05 {
		t.Fatalf("other client was slowed by the first: %.2f", el)
	}
}

func TestBandwidthThroughProxyHandlerKeepsBodyIntact(t *testing.T) {
	payload := strings.Repeat("0123456789", 3000)
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, payload) })
	router, sep := newOpsTestRouter(t, be)
	sep.Ops = &OpsConfig{Bandwidth: &BandwidthConfig{BytesPerSecond: 50 * 1024 * 1024}}
	w := serveOps(router, "GET", "/", nil)
	if w.Code != 200 || w.Body.String() != payload {
		t.Fatalf("body altered by throttling: %d len=%d", w.Code, w.Body.Len())
	}
	if (&BandwidthConfig{BytesPerSecond: 5}).Validate() == nil {
		t.Fatal("useless limit accepted")
	}
}

// ---- variables ----

func TestTemplateVariablesAreSanitised(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "evil.example\r\nX-Injected: 1"
	r.RemoteAddr = "203.0.113.5:5555"
	r.Header.Set("X-Request-Id", "bad id\r\n")
	rewrite.SetExternalIPProvider(func() string { return "198.51.100.77" })
	defer rewrite.SetExternalIPProvider(nil)
	out := rewrite.ExpandTemplateVars(r, "h={{host}} ip={{client_ip}} ext={{ external_ip }} unknown={{nope}} id={{request_id}}")
	if strings.ContainsAny(out, "\r\n") {
		t.Fatalf("control characters survived: %q", out)
	}
	for _, want := range []string{"ip=203.0.113.5", "ext=198.51.100.77", "{{nope}}"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing in %q", want, out)
		}
	}
}

func TestRequestIDAndRuleNameReachUpstreamHeaders(t *testing.T) {
	var gotID, gotRule, gotExt string
	be := opsBackend(t, func(w http.ResponseWriter, r *http.Request) {
		gotID, gotRule, gotExt = r.Header.Get("X-Req"), r.Header.Get("X-Rule"), r.Header.Get("X-Ext")
	})
	rewrite.SetExternalIPProvider(func() string { return "198.51.100.77" })
	defer rewrite.SetExternalIPProvider(nil)
	router, sep := newOpsTestRouter(t, be)
	sep.Ops = &OpsConfig{ExposeRequestID: true}
	sep.HeaderRewriteRules = GetDefaultHeaderRewriteRules()
	sep.HeaderRewriteRules.UserDefinedHeaders = []*rewrite.UserDefinedHeader{
		{Direction: rewrite.HeaderDirection_ZoraxyToUpstream, Key: "X-Req", Value: "{{request_id}}"},
		{Direction: rewrite.HeaderDirection_ZoraxyToUpstream, Key: "X-Rule", Value: "{{rule_name}}"},
		{Direction: rewrite.HeaderDirection_ZoraxyToUpstream, Key: "X-Ext", Value: "{{external_ip}}"},
	}
	w := serveOps(router, "GET", "/", nil)
	if gotRule != "app.example.com" || gotExt != "198.51.100.77" || len(gotID) != 16 || w.Header().Get("X-Request-Id") != gotID {
		t.Fatalf("id=%q rule=%q ext=%q resp=%q", gotID, gotRule, gotExt, w.Header().Get("X-Request-Id"))
	}
}

func TestOldEndpointJSONWithoutOpsUnchanged(t *testing.T) {
	ep := &ProxyEndpoint{RootOrMatchingDomain: "a"}
	js := mustJSON(t, ep)
	if strings.Contains(js, "Ops") {
		t.Fatalf("Ops must be omitted when unset: %s", js)
	}
}
