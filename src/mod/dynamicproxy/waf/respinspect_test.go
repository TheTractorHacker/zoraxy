package waf

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

/*
	Tests of response inspection. Every secret in here is generated at run time from a fixed seed,
	so the source contains no complete token (and no secret scanner can mistake it for one).
*/

func fakeRand(n int, alphabet string, seed int64) string {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

const (
	alnum  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digits = "0123456789"
	b64    = alnum + "+/"
)

func fakeGitHubToken(valid bool) string {
	body := fakeRand(30, alnum, 11)
	sum := githubChecksum(body)
	if !valid {
		sum = "000000"
		if githubChecksum(body) == sum {
			sum = "111111"
		}
	}
	return "gh" + "p_" + body + sum
}

func fakePEM() string {
	return "-----BEGIN RSA PRIV" + "ATE KEY-----\n" + fakeRand(64, b64, 21) + "\n" + fakeRand(64, b64, 22) + "\n-----END RSA PRIV" + "ATE KEY-----\n"
}

func fakeStripe(kind string) string {
	return "sk" + "_" + kind + "_" + fakeRand(32, alnum, 31)
}

func fakeSlack() string {
	return "xo" + "xb-" + fakeRand(12, digits, 41) + "-" + fakeRand(13, digits, 42) + "-" + fakeRand(24, alnum, 43)
}

func fakeAWSPair() (id, secret string) {
	return "AK" + "IA" + fakeRand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 51), fakeRand(40, b64[:62]+"/+", 52)
}

// allGroups returns a guard with every group on and the given action
func allGroups(m *Manager, action string, mode string) *ResponseGuard {
	rc := &ResponseConfig{Groups: map[string]string{
		GroupStackTrace: action, GroupDBError: action, GroupSecrets: action, GroupDirListing: action, GroupHeaders: RespActionLog,
	}}
	return m.NewResponseGuard(rc, mode)
}

func scanSigs(t *testing.T, body string, flags int) map[string]int {
	t.Helper()
	g := allGroups(NewManager(), RespActionLog, ModeBlock)
	out := map[string]int{}
	for _, h := range g.scan([]byte(body), flags) {
		out[h.sig.ID] = h.conf
	}
	return out
}

func TestSignaturesTruePositives(t *testing.T) {
	ghOK, ghBad := fakeGitHubToken(true), fakeGitHubToken(false)
	awsID, awsSecret := fakeAWSPair()
	cases := []struct {
		name  string
		body  string
		flags int
		sig   string
		conf  int
	}{
		{"java", "HTTP Status 500\njava.lang.NullPointerException: x\n\tat com.acme.Foo.bar(Foo.java:42)\n\tat com.acme.Baz.run(Baz.java:7)\n\tat java.lang.Thread.run(Thread.java:748)\n", 0, "ST-JAVA", confHigh},
		{"java html", "<pre>org.x.Err<br/>&nbsp;at a.b.C.d(C.java:1)<br/>&nbsp;at a.b.C.e(C.java:2)<br/>&nbsp;at a.b.C.f(C.java:3)<br/></pre>", 0, "ST-JAVA", confHigh},
		{"python", "Traceback (most recent call last):\n  File \"/app/views.py\", line 12, in index\n    x = 1/0\nZeroDivisionError", 0, "ST-PY", confHigh},
		{"php", "<br />\n<b>Warning</b>:  Undefined variable $x in <b>/var/www/html/index.php</b> on line <b>3</b><br />", 0, "ST-PHP", confHigh},
		{"php plain", "PHP Fatal error:  Uncaught Exception: boom in /srv/app/a.php:12\nStack trace:\n#0 /srv/app/b.php(4): f()\n#1 {main}", 0, "ST-PHP-TRACE", confHigh},
		{"aspnet page", "<title>Runtime Error</title><h1>Server Error in '/' Application.</h1><b>Exception Details: </b>System.Exception", 0, "ST-DOTNET-PAGE", confHigh},
		{"dotnet", "   at Acme.Web.HomeController.Index() in C:\\src\\HomeController.cs:line 25\n   at lambda_method(Closure , Object , Object[] ) in C:\\src\\x.cs:line 3\n", 0, "ST-DOTNET", confHigh},
		{"node", "Error: boom\n    at Object.<anonymous> (/app/server.js:10:11)\n    at Module._compile (node:internal/modules/cjs/loader:1256:14)\n    at /app/node_modules/express/lib/router/layer.js:95:5\n", 0, "ST-NODE", confHigh},
		{"go", "panic: runtime error: index out of range\n\ngoroutine 1 [running]:\nmain.main()\n\t/app/main.go:12 +0x1d\nexit status 2\n", 0, "ST-GO", confHigh},
		{"rails", "<title>Action Controller: Exception caught</title>", 0, "ST-RAILS", confHigh},
		{"django", "<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>", 0, "ST-DJANGO", confHigh},
		{"werkzeug", "<h1>The debugger caught an exception in your WSGI application.</h1>", 0, "ST-WERKZEUG", confHigh},

		{"mysql", "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1", 0, "DB-MYSQL", confHigh},
		{"mysql unknown col", "Unknown column 'foo' in 'where clause'", 0, "DB-MYSQL", confHigh},
		{"pdo", "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error", 0, "DB-MYSQL", confHigh},
		{"pgsql", "ERROR:  relation \"users\" does not exist\nLINE 1: SELECT * FROM users", 0, "DB-PGSQL", confHigh},
		{"mssql", "Unclosed quotation mark after the character string ''.", 0, "DB-MSSQL", confHigh},
		{"oracle", "ORA-00933: SQL command not properly ended", 0, "DB-ORACLE", confHigh},
		{"sqlite", "SQLite3::SQLException: no such table: users", 0, "DB-SQLITE", confHigh},
		{"mongo", "MongoServerError: E11000 duplicate key error collection: app.users index: email_1", 0, "DB-MONGO", confHigh},

		{"pem", `{"key":"` + strings.ReplaceAll(fakePEM(), "\n", `\n`) + `"}`, ctxJSON, "SEC-PEM", confHigh},
		{"pem plain", fakePEM(), ctxPlain, "SEC-PEM", confHigh},
		{"aws secret", "aws_secret_access_key = " + awsSecret + "\n", ctxPlain, "SEC-AWS-SECRET", confHigh},
		{"aws id alone", "id: " + awsID, 0, "SEC-AWS-KEYID", confLow},
		{"aws id + secret", "AWS_ACCESS_KEY_ID=" + awsID + "\nAWS_SECRET=" + awsSecret + "\n", 0, "SEC-AWS-KEYID", confHigh},
		{"github valid checksum", "token " + ghOK, 0, "SEC-GITHUB", confHigh},
		{"github bad checksum", "token " + ghBad, 0, "SEC-GITHUB", confLow},
		{"gitlab", "glp" + "at-" + fakeRand(20, alnum, 61), 0, "SEC-GITLAB", confHigh},
		{"slack", "token=" + fakeSlack(), 0, "SEC-SLACK", confHigh},
		{"stripe live", fakeStripe("live"), 0, "SEC-STRIPE", confHigh},
		{"stripe test low", fakeStripe("test"), 0, "SEC-STRIPE", confLow},
		{"json password", `{"user":"bob","password":"` + fakeRand(14, alnum, 71) + `"}`, ctxJSON, "SEC-JSON-CRED", confLow},
		{"dotenv", "APP_NAME=x\nDB_PASSWORD=" + fakeRand(16, alnum, 72) + "\n", ctxPlain, "SEC-DOTENV", confLow},

		{"apache index", `<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><table><tr><th><a href="?C=N;O=D">Name</a></th></tr><tr><td><a href="/">Parent Directory</a></td></tr>`, 0, "DL-INDEXOF", confHigh},
		{"nginx index", `<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1><hr><pre><a href="../">../</a>`, 0, "DL-INDEXOF", confHigh},
		{"python index", `<title>Directory listing for /</title></head><body><h1>Directory listing for /</h1><hr><ul><li>`, 0, "DL-PYHTTP", confHigh},
		{"iis", `<pre>[<A HREF="/">To Parent Directory</A>]`, 0, "", confNone}, // different markup, intentionally not matched
		{"iis2", `[To Parent Directory]<br><br>`, 0, "DL-IIS", confHigh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scanSigs(t, c.body, c.flags)
			if c.sig == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected hits %v", got)
				}
				return
			}
			if got[c.sig] != c.conf {
				t.Fatalf("want %s conf %d, got %v", c.sig, c.conf, got)
			}
		})
	}
}

func TestSignaturesNearMissNegatives(t *testing.T) {
	awsExampleID := "AKIA" + "IOSFODNN7EXAMPLE"
	cases := []struct {
		name  string
		body  string
		flags int
	}{
		{"prose stack trace", "<p>When your app crashes, read the stack trace from the top. A traceback (most recent call last) lists frames. Java prints 'at' lines.</p>", 0},
		{"prose with one java frame", "See the line: at com.acme.Foo.bar(Foo.java:42) in the report, and fix it.", 0},
		{"two java frames", "at a.B.c(B.java:1)\nat a.B.d(B.java:2)\n", 0},
		{"python docs without frame", "A Traceback (most recent call last): header is printed first.", 0},
		{"php docs", "Set display_errors to Off. Example: Warning: something in your config file on line 3 of the manual.", 0},
		{"node prose", "Errors look like: at Object.run (file) and later at x. Not a trace.", 0},
		{"go prose", "A goroutine dump starts with goroutine 1 [running]: in the output.", 0},
		{"base64 blob", fakeRand(4000, b64, 81), 0},
		{"base64 blob with key words", "data:application/octet-stream;base64," + fakeRand(3000, b64, 82) + " PRIVATE KEY", 0},
		{"pem header only", "Generate with openssl; it starts with -----BEGIN RSA PRIVATE KEY----- and ends with -----END RSA PRIVATE KEY-----.", 0},
		{"pem elided", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN...\n-----END PRIVATE KEY-----", 0},
		{"public key", "-----BEGIN PUBLIC KEY-----\n" + fakeRand(64, b64, 83) + "\n-----END PUBLIC KEY-----", 0},
		{"aws docs example id", "aws_access_key_id = " + awsExampleID, 0},
		{"aws docs example secret", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ctxPlain},
		{"github placeholder", "export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0},
		{"github token too short", "ghp_" + fakeRand(20, alnum, 84), 0},
		{"gitlab placeholder", "glpat-xxxxxxxxxxxxxxxxxxxx", 0},
		{"stripe publishable", "pk_" + "live_" + fakeRand(32, alnum, 85), 0},
		{"stripe placeholder", "sk_" + "live_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0},
		{"slack prose", "Slack bot tokens start with xoxb- and look like xoxb-123-456-abc", 0},
		{"json placeholder password", `{"password":"********"}`, ctxJSON},
		{"json password placeholder words", `{"password":"changeme123","api_key":"your-api-key-here","secret":"${SECRET_VALUE}"}`, ctxJSON},
		{"json short password", `{"password":"abc"}`, ctxJSON},
		{"json password in html", `<input name="password" value="Zk3-9fLq-72Hs">`, 0},
		{"json cred outside json", `"password": "` + fakeRand(14, alnum, 86) + `"`, ctxPlain},
		{"dotenv outside text/plain", "DB_PASSWORD=" + fakeRand(16, alnum, 87), ctxJSON},
		{"dotenv placeholder", "DB_PASSWORD=changeme\nAPI_KEY=your_api_key_here\n", ctxPlain},
		{"ora prose", "Error code ORA-00942 means table or view does not exist.", 0},
		{"sql prose", "A syntax error in SQL happens when you forget a comma. MySQL and PostgreSQL both complain.", 0},
		{"mysql prose", "Most MySQL tutorials show the keyword SELECT. The word Duplicate entry alone is fine.", 0},
		{"error word", "ERROR: something went wrong, please try again", 0},
		{"mongo prose", "MongoDB is a document database. MongoError is a class name.", 0},
		{"index of prose", "<h1>Index of /docs</h1><p>This is the documentation index.</p>", 0},
		{"index of title only", "<title>Index of /</title><body>Welcome</body>", 0},
		{"rails prose", "Rails.root is the path of the application", 0},
		{"django prose", "Set DEBUG = True only in development. Django Version: 5 is supported.", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanSigs(t, c.body, c.flags); len(got) != 0 {
				t.Fatalf("unexpected hits %v", got)
			}
		})
	}
}

/* ---- inspection path ---- */

func mkRes(body []byte, ct string, status int) *http.Response {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return &http.Response{StatusCode: status, Header: h, ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body))}
}

func guardWith(m *Manager, win int, mode string, groups map[string]string) *ResponseGuard {
	return m.NewResponseGuard(&ResponseConfig{WindowKiB: win, Groups: groups}, mode)
}

func hash(b []byte) [32]byte { return sha256.Sum256(b) }

const javaLeak = "java.lang.RuntimeException: boom\n\tat com.acme.Foo.bar(Foo.java:42)\n\tat com.acme.Baz.run(Baz.java:7)\n\tat java.lang.Thread.run(Thread.java:748)\n"

func page(prefix int, leak string) []byte {
	return []byte("<html><body>" + strings.Repeat("x", prefix) + leak + "</body></html>")
}

func TestWindowLimits(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 1, ModeBlock, map[string]string{GroupStackTrace: RespActionLog}) // 1 KiB window

	inside := page(100, javaLeak)
	res := mkRes(inside, "text/html", 200)
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	if n := len(m.RecentEvents(10, "")); n != 1 {
		t.Fatalf("leak inside the window: want 1 event, got %d", n)
	}

	beyond := page(2000, javaLeak)
	res = mkRes(beyond, "text/html", 200)
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	if n := len(m.RecentEvents(10, "")); n != 1 {
		t.Fatalf("leak beyond the window must not be detected (documented limit), events: %d", n)
	}
	got, _ := io.ReadAll(res.Body)
	if hash(got) != hash(beyond) {
		t.Fatal("body altered")
	}
}

func TestLeakSplitAcrossReadChunks(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 8, ModeBlock, map[string]string{GroupStackTrace: RespActionBlock})
	body := page(500, javaLeak)
	for _, chunk := range []int{1, 3, 7, 61} {
		res := mkRes(body, "text/html", 200)
		res.Body = io.NopCloser(chunkedReader(body, chunk))
		if st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != http.StatusBadGateway {
			t.Fatalf("chunk %d: leak split across reads not detected (status %d)", chunk, st)
		}
	}
}

// chunkedReader returns at most n bytes per Read
func chunkedReader(b []byte, n int) io.Reader {
	return &limitedRead{r: bytes.NewReader(b), n: n}
}

type limitedRead struct {
	r io.Reader
	n int
}

func (l *limitedRead) Read(p []byte) (int, error) {
	if len(p) > l.n {
		p = p[:l.n]
	}
	return l.r.Read(p)
}

// spyBody counts Read calls
type spyBody struct {
	r     io.Reader
	reads int
}

func (s *spyBody) Read(p []byte) (int, error) { s.reads++; return s.r.Read(p) }
func (s *spyBody) Close() error               { return nil }

func TestSkippedResponsesAreNotRead(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionBlock, GroupSecrets: RespActionBlock})
	leak := page(10, javaLeak)
	mk := func(ct string, status int, cl int64, mod func(*http.Response)) (*http.Response, *spyBody) {
		sb := &spyBody{r: bytes.NewReader(leak)}
		r := &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {ct}}, ContentLength: cl, Body: sb}
		if mod != nil {
			mod(r)
		}
		return r, sb
	}
	n := int64(len(leak))
	cases := map[string]struct {
		res       *http.Response
		sb        *spyBody
		streaming bool
		req       *http.Request
	}{}
	add := func(name string, res *http.Response, sb *spyBody, streaming bool, req *http.Request) {
		cases[name] = struct {
			res       *http.Response
			sb        *spyBody
			streaming bool
			req       *http.Request
		}{res, sb, streaming, req}
	}
	r, s := mk("text/event-stream", 200, n, nil)
	add("sse", r, s, false, nil)
	r, s = mk("application/grpc", 200, n, nil)
	add("grpc", r, s, false, nil)
	r, s = mk("text/html", 200, -1, nil)
	add("chunked", r, s, false, nil)
	r, s = mk("text/html", 206, n, nil)
	add("206", r, s, false, nil)
	r, s = mk("text/html", 200, n, func(r *http.Response) { r.Header.Set("Content-Range", "bytes 0-9/100") })
	add("content-range", r, s, false, nil)
	r, s = mk("text/html", 200, n, nil)
	add("streaming flag", r, s, true, nil)
	r, s = mk("application/octet-stream", 200, n, nil)
	add("binary", r, s, false, nil)
	r, s = mk("image/png", 200, n, nil)
	add("image", r, s, false, nil)
	r, s = mk("text/html", 200, n, func(r *http.Response) { r.Header.Set("Content-Encoding", "br") })
	add("brotli", r, s, false, nil)
	r, s = mk("text/html", 200, n, func(r *http.Response) { r.Header.Set("Content-Encoding", "gzip, br") })
	add("stacked encoding", r, s, false, nil)
	r, s = mk("text/html", 200, n, func(r *http.Response) { r.Trailer = http.Header{"X-T": nil} })
	add("trailers", r, s, false, nil)
	r, s = mk("text/html", 200, n, nil)
	add("HEAD", r, s, false, &http.Request{Method: http.MethodHead, Header: http.Header{}})
	r, s = mk("text/html", 200, n, nil)
	add("upgrade", r, s, false, &http.Request{Method: "GET", Header: http.Header{"Upgrade": {"websocket"}}})
	r, s = mk("text/html", 304, n, nil)
	add("304", r, s, false, nil)
	r, s = mk("text/html", 101, n, nil)
	add("101", r, s, false, nil)
	for name, c := range cases {
		if st := g.Inspect(ResponseInfo{Endpoint: "e"}, c.req, c.res, c.streaming); st != 0 {
			t.Errorf("%s: blocked", name)
		}
		if c.sb.reads != 0 {
			t.Errorf("%s: body was read %d times, must pass through unbuffered", name, c.sb.reads)
		}
		if c.res.Body != io.ReadCloser(c.sb) {
			t.Errorf("%s: body was wrapped", name)
		}
	}
	if len(m.RecentEvents(10, "")) != 0 {
		t.Fatal("events for skipped responses")
	}
}

func TestLogLeavesBytesIdentical(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionLog})
	body := page(70000, "") // larger than the window
	body = append([]byte(javaLeak), body...)
	res := mkRes(body, "text/html", 200)
	if st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != 0 {
		t.Fatal("log must not block")
	}
	got, _ := io.ReadAll(res.Body)
	if hash(got) != hash(body) {
		t.Fatal("log changed the body")
	}
	ev := m.RecentEvents(10, "")
	if len(ev) != 1 || ev[0].Action != "detected" || ev[0].Kind != KindResponse || ev[0].Response.Group != GroupStackTrace {
		t.Fatalf("events: %+v", ev)
	}
}

type closeSpy struct {
	io.Reader
	closed bool
}

func (c *closeSpy) Close() error { c.closed = true; return nil }

func TestBlockClosesUpstreamAndSignalsReplacement(t *testing.T) {
	m := NewManager()
	var notified int
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionBlock})
	cs := &closeSpy{Reader: bytes.NewReader(page(10, javaLeak))}
	res := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, ContentLength: 500, Body: cs}
	st := g.Inspect(ResponseInfo{Endpoint: "e", OnBlock: func(Event) { notified++ }}, nil, res, false)
	if st != http.StatusBadGateway || !cs.closed || notified != 1 {
		t.Fatalf("status %d closed %v notified %d", st, cs.closed, notified)
	}
	ev := m.RecentEvents(1, "")[0]
	if ev.Action != "blocked" || !ev.WouldBlock {
		t.Fatalf("%+v", ev)
	}

	// detection_only never blocks, but records the would-block
	m2 := NewManager()
	g2 := guardWith(m2, 64, ModeDetectionOnly, map[string]string{GroupStackTrace: RespActionBlock})
	res = mkRes(page(10, javaLeak), "text/html", 200)
	if st := g2.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != 0 {
		t.Fatal("detection_only blocked")
	}
	if ev := m2.RecentEvents(1, "")[0]; ev.Action != "detected" || !ev.WouldBlock {
		t.Fatalf("%+v", ev)
	}
}

func TestLowConfidenceNeverBlocks(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupSecrets: RespActionBlock})
	for _, body := range []string{fakeStripe("test"), fakeGitHubToken(false), `{"password":"` + fakeRand(14, alnum, 5) + `"}`} {
		res := mkRes([]byte(body), "application/json", 200)
		if st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != 0 {
			t.Fatalf("low confidence hit blocked: %.12s", body)
		}
	}
	if n := len(m.RecentEvents(10, "")); n != 3 {
		t.Fatalf("want 3 logged events, got %d", n)
	}
	// and a verified token does block
	res := mkRes([]byte("t="+fakeGitHubToken(true)), "text/plain", 200)
	if st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != http.StatusBadGateway {
		t.Fatal("valid token not blocked")
	}
}

func TestGroupsOffAndPerGroupActions(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionOff, GroupDBError: RespActionLog})
	res := mkRes(page(10, javaLeak+"ORA-00933: SQL command not properly ended"), "text/html", 200)
	if st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != 0 {
		t.Fatal("blocked")
	}
	ev := m.RecentEvents(10, "")
	if len(ev) != 1 || ev[0].Response.Group != GroupDBError {
		t.Fatalf("%+v", ev)
	}
	if guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionOff}) != nil {
		t.Fatal("all off must give a nil guard")
	}
	var nilGuard *ResponseGuard
	if nilGuard.Inspect(ResponseInfo{}, nil, mkRes(nil, "text/html", 200), false) != 0 {
		t.Fatal("nil guard")
	}
}

/* ---- compression ---- */

func gz(t testing.TB, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func TestGzipAndDeflate(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionBlock})
	plain := page(100, javaLeak)

	res := mkRes(gz(t, plain), "text/html", 200)
	res.Header.Set("Content-Encoding", "gzip")
	if st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != http.StatusBadGateway {
		t.Fatal("gzip leak not detected")
	}

	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write(plain)
	zw.Close()
	res = mkRes(zb.Bytes(), "text/html", 200)
	res.Header.Set("Content-Encoding", "deflate")
	if st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != http.StatusBadGateway {
		t.Fatal("deflate leak not detected")
	}

	// clean gzip passes through byte identical (the compressed bytes)
	clean := page(5000, "")
	c := gz(t, clean)
	res = mkRes(c, "text/html", 200)
	res.Header.Set("Content-Encoding", "gzip")
	if st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false); st != 0 {
		t.Fatal("blocked")
	}
	got, _ := io.ReadAll(res.Body)
	if hash(got) != hash(c) {
		t.Fatal("compressed bytes altered")
	}

	// corrupt gzip: no inspection, bytes preserved
	bad := append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff}, bytes.Repeat([]byte{0xAB}, 300)...)
	res = mkRes(bad, "text/html", 200)
	res.Header.Set("Content-Encoding", "gzip")
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	got, _ = io.ReadAll(res.Body)
	if hash(got) != hash(bad) {
		t.Fatal("corrupt stream altered")
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func TestGzipBombStaysWithinCap(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionBlock})

	// 400 MiB of zeros followed by a leak: compresses to ~400 KiB, must never be inflated beyond the window
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zeros := make([]byte, 1<<20)
	for i := 0; i < 400; i++ {
		w.Write(zeros)
	}
	w.Write([]byte(javaLeak))
	w.Close()
	bomb := buf.Bytes()
	t.Logf("bomb: %d compressed bytes, 400 MiB inflated", len(bomb))

	cr := &countingReader{r: bytes.NewReader(bomb)}
	res := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"gzip"}}, ContentLength: int64(len(bomb)), Body: io.NopCloser(cr)}

	var before, after runtimeMem
	before.read()
	st := g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	after.read()
	if st != 0 || len(m.RecentEvents(10, "")) != 0 {
		t.Fatal("a leak after 400 MiB of zeros is beyond the window and must not be found")
	}
	if grown := after.total - before.total; grown > 2<<20 {
		t.Fatalf("inspecting the bomb allocated %d bytes", grown)
	}
	if limit := int64(2*64*1024 + compressedSlackBytes + 8192); cr.n > limit {
		t.Fatalf("read %d compressed bytes, cap is %d", cr.n, limit)
	}
	got, _ := io.ReadAll(res.Body)
	if hash(got) != hash(bomb) {
		t.Fatal("bomb bytes altered on the way through")
	}
}

func TestGzipStoredBlockFloodStaysWithinCap(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionBlock})
	// valid gzip header, then 4 MiB of empty stored deflate blocks: no output, endless input
	stream := []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff}
	stream = append(stream, bytes.Repeat([]byte{0, 0, 0, 0xff, 0xff}, 800000)...)
	cr := &countingReader{r: bytes.NewReader(stream)}
	res := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"gzip"}}, ContentLength: int64(len(stream)), Body: io.NopCloser(cr)}
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	if limit := int64(2*64*1024 + compressedSlackBytes + 8192); cr.n > limit {
		t.Fatalf("read %d compressed bytes, cap is %d", cr.n, limit)
	}
	got, _ := io.ReadAll(res.Body)
	if hash(got) != hash(stream) {
		t.Fatal("bytes altered")
	}
}

/* ---- headers ---- */

func hdrRes() *http.Response {
	r := mkRes([]byte("x"), "text/html", 200)
	r.Header.Set("Server", "nginx/1.18.0 (Ubuntu)")
	r.Header.Set("X-Powered-By", "PHP/8.1.2")
	r.Header.Set("X-AspNet-Version", "4.0.30319")
	return r
}

func TestHeaderStrip(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 0, ModeBlock, map[string]string{GroupHeaders: RespActionStrip})
	res := hdrRes()
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if res.Header.Get(h) != "" {
			t.Errorf("%s not stripped", h)
		}
	}
	if ev := m.RecentEvents(10, ""); len(ev) != 3 || ev[0].Action != "stripped" {
		t.Fatalf("events %+v", ev)
	}
	// second response: stripped again, but events are rate limited
	res = hdrRes()
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	if res.Header.Get("Server") != "" || len(m.RecentEvents(10, "")) != 3 {
		t.Fatal("repeat handling")
	}

	// bare product name is not a leak, X-Powered-By always is
	res = mkRes([]byte("x"), "text/html", 200)
	res.Header.Set("Server", "nginx")
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	if res.Header.Get("Server") != "nginx" {
		t.Fatal("bare Server header stripped")
	}

	for name, mode := range map[string]struct{ act, mode string }{
		"log":             {RespActionLog, ModeBlock},
		"strip in dtonly": {RespActionStrip, ModeDetectionOnly},
	} {
		m2 := NewManager()
		g2 := guardWith(m2, 0, mode.mode, map[string]string{GroupHeaders: mode.act})
		res = hdrRes()
		g2.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
		if res.Header.Get("Server") == "" || res.Header.Get("X-Powered-By") == "" {
			t.Errorf("%s: headers were stripped", name)
		}
		if len(m2.RecentEvents(10, "")) != 3 {
			t.Errorf("%s: want 3 events", name)
		}
	}
	// off: no guard at all, headers untouched
	if guardWith(m, 0, ModeBlock, map[string]string{GroupHeaders: RespActionOff}) != nil {
		t.Fatal("off must not create a guard")
	}
}

func TestHeaderStripAlsoOnStreamingResponses(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 0, ModeBlock, map[string]string{GroupHeaders: RespActionStrip})
	res := hdrRes()
	res.Header.Set("Content-Type", "text/event-stream")
	res.ContentLength = -1
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, true)
	if res.Header.Get("X-Powered-By") != "" {
		t.Fatal("not stripped on a stream")
	}
}

/* ---- redaction ---- */

func TestEventsNeverContainFullSecrets(t *testing.T) {
	m := NewManager()
	var lines []string
	m.SetAuditSink(sinkFunc(func(l string) { lines = append(lines, l) }))
	g := allGroups(m, RespActionLog, ModeBlock)
	awsID, awsSecret := fakeAWSPair()
	secrets := []string{
		fakeGitHubToken(true), fakeSlack(), fakeStripe("live"), awsSecret, awsID,
		fakeRand(64, b64, 21), // PEM body line
		fakeRand(18, alnum, 71),
	}
	body := fakePEM() + "\n" + secrets[0] + "\n" + secrets[1] + "\n" + secrets[2] + "\naws_secret_access_key=" + awsSecret + "\n" + awsID +
		"\n" + `{"password":"` + secrets[6] + `"}`
	res := mkRes([]byte(body), "text/plain", 200)
	g.Inspect(ResponseInfo{Endpoint: "e", Path: "/p"}, nil, res, false)
	evs := m.RecentEvents(50, "")
	if len(evs) < 5 {
		t.Fatalf("expected several events, got %d", len(evs))
	}
	blob, _ := json.Marshal(evs)
	all := string(blob) + strings.Join(lines, "\n")
	for _, s := range secrets {
		if strings.Contains(all, s) {
			t.Fatalf("secret stored in full: %.8s...", s)
		}
		// no long fragment of the secret either: nothing beyond a short prefix and suffix
		mid := s[len(s)/3 : len(s)/3+10]
		if strings.Contains(all, mid) {
			t.Fatalf("middle of a secret stored: %s", mid)
		}
	}
	if strings.Contains(all, "BEGIN RSA PRIVATE KEY-----\n"+fakeRand(10, b64, 21)) {
		t.Fatal("pem body stored")
	}
}

type sinkFunc func(string)

func (f sinkFunc) LogRaw(l string) { f(l) }

func TestDBSampleDoesNotKeepQuotedData(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupDBError: RespActionLog})
	res := mkRes([]byte("Duplicate entry 'alice@example.org' for key 'users.email'"), "text/html", 200)
	g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
	ev := m.RecentEvents(1, "")[0]
	if strings.Contains(ev.Response.Sample, "alice") {
		t.Fatalf("user data in sample: %q", ev.Response.Sample)
	}
}

/* ---- config, merge, events ---- */

func TestResponseConfigValidate(t *testing.T) {
	bad := []*ResponseConfig{
		{WindowKiB: -1}, {WindowKiB: MaxResponseWindowKiB + 1},
		{Groups: map[string]string{"nope": RespActionLog}},
		{Groups: map[string]string{GroupHeaders: RespActionBlock}},
		{Groups: map[string]string{GroupSecrets: RespActionStrip}},
		{Groups: map[string]string{GroupSecrets: "destroy"}},
	}
	for i, c := range bad {
		if c.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	ok := &ResponseConfig{WindowKiB: 1024, Groups: map[string]string{GroupSecrets: "BLOCK", GroupHeaders: RespActionStrip, GroupDBError: ""}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	var nilCfg *ResponseConfig
	if nilCfg.Validate() != nil || nilCfg.Active() {
		t.Fatal("nil")
	}
}

func TestResponseMergeAcrossLevels(t *testing.T) {
	pol := Policy{Enabled: true, DefaultMode: ModeBlock, AllowEndpointOverride: true,
		Response: &ResponseConfig{WindowKiB: 32, Groups: map[string]string{GroupStackTrace: RespActionLog, GroupSecrets: RespActionBlock, GroupHeaders: RespActionStrip}}}
	prof := Profile{Name: "P", Mode: ModeBlock,
		Response: &ResponseConfig{Groups: map[string]string{GroupStackTrace: RespActionBlock, GroupDBError: RespActionLog}}}
	st, err := NewState(pol, []Profile{prof})
	if err != nil {
		t.Fatal(err)
	}
	// inherit: policy only
	c := st.Resolve(Setting{Source: SourceInherit}).Config.Response
	if c.WindowKiB != 32 || c.Action(GroupStackTrace) != RespActionLog || c.Action(GroupSecrets) != RespActionBlock {
		t.Fatalf("policy: %+v", c)
	}
	// profile overrides per group, other groups inherit
	c = st.Resolve(Setting{Source: SourceProfile, Profile: "P"}).Config.Response
	if c.Action(GroupStackTrace) != RespActionBlock || c.Action(GroupDBError) != RespActionLog || c.Action(GroupSecrets) != RespActionBlock || c.WindowKiB != 32 {
		t.Fatalf("profile: %+v", c)
	}
	// endpoint override wins over the profile; off disables a group; window override
	extra := &Overrides{Response: &ResponseConfig{WindowKiB: 256, Groups: map[string]string{GroupStackTrace: RespActionOff, GroupSecrets: RespActionLog}}}
	c = st.Resolve(Setting{Source: SourceProfile, Profile: "P", Extra: extra}).Config.Response
	if c.Action(GroupStackTrace) != RespActionOff || c.Action(GroupSecrets) != RespActionLog || c.Action(GroupDBError) != RespActionLog || c.WindowKiB != 256 {
		t.Fatalf("endpoint: %+v", c)
	}
	// the policy value is not modified by merging
	if pol.Response.Groups[GroupStackTrace] != RespActionLog || pol.Response.WindowKiB != 32 {
		t.Fatal("policy mutated")
	}
	// WAF off: no response inspection, nothing to resolve
	if r := st.Resolve(Setting{Source: SourceOff}); r.Config != nil {
		t.Fatal("off resolved a config")
	}
	// nothing configured: nil
	st2 := EmptyState()
	if r := st2.Resolve(Setting{Source: ModeBlock}); r.Config == nil || r.Config.Response != nil {
		t.Fatalf("empty policy: %+v", r.Config)
	}
	// invalid settings are rejected on save
	if _, err := NewState(Policy{DefaultMode: ModeBlock, Response: &ResponseConfig{Groups: map[string]string{"x": "log"}}}, nil); err == nil {
		t.Fatal("bad policy accepted")
	}
	if st.ValidateSetting(Setting{Source: ModeBlock, Extra: &Overrides{Response: &ResponseConfig{WindowKiB: 5000}}}) == nil {
		t.Fatal("bad override accepted")
	}
	if _, err := NewState(pol, []Profile{{Name: "Q", Response: &ResponseConfig{Groups: map[string]string{GroupHeaders: "block"}}}}); err == nil {
		t.Fatal("bad profile accepted")
	}
}

func TestResponseConfigJSONBackwardsCompatible(t *testing.T) {
	// persisted data written before this feature
	var pol Policy
	if err := json.Unmarshal([]byte(`{"Enabled":true,"DefaultMode":"block","ParanoiaLevel":1}`), &pol); err != nil || pol.Response != nil {
		t.Fatalf("%v %+v", err, pol.Response)
	}
	// and nothing new is written while unused
	for _, v := range []interface{}{Policy{}, Profile{}, Overrides{}, Config{}} {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), "Response") {
			t.Fatalf("%T serialises Response when unset: %s", v, b)
		}
	}
	// the compiled-rules cache key ignores response settings
	a := Config{Mode: ModeBlock}
	b := Config{Mode: ModeBlock, Response: &ResponseConfig{Groups: map[string]string{GroupSecrets: RespActionBlock}}}
	if a.Hash() != b.Hash() {
		t.Fatal("response settings must not change the Coraza cache key")
	}
}

func TestResponseEventsFilterAndStats(t *testing.T) {
	m := NewManager()
	g := guardWith(m, 64, ModeBlock, map[string]string{GroupStackTrace: RespActionBlock, GroupDBError: RespActionLog})
	g.Inspect(ResponseInfo{Endpoint: "a.example", ClientIP: "1.2.3.4", Path: "/x", Method: "GET"}, nil, mkRes(page(1, javaLeak), "text/html", 500), false)
	g.Inspect(ResponseInfo{Endpoint: "b.example"}, nil, mkRes([]byte("ORA-00933: SQL command not properly ended"), "text/html", 200), false)
	if got := m.QueryEvents(EventFilter{Kind: KindResponse}); len(got) != 2 {
		t.Fatalf("kind filter: %d", len(got))
	}
	if got := m.QueryEvents(EventFilter{Kind: KindRequest}); len(got) != 0 {
		t.Fatalf("request filter: %d", len(got))
	}
	if got := m.QueryEvents(EventFilter{Group: GroupDBError}); len(got) != 1 || got[0].Endpoint != "b.example" {
		t.Fatalf("group filter: %+v", got)
	}
	if got := m.QueryEvents(EventFilter{Action: "blocked"}); len(got) != 1 {
		t.Fatalf("action filter: %d", len(got))
	}
	ev := m.QueryEvents(EventFilter{Endpoint: "a.example"})[0]
	if ev.Response.Status != 500 || ev.ClientIP != "1.2.3.4" || ev.Path != "/x" || ev.Response.Signature != "ST-JAVA" || ev.TransactionID == "" {
		t.Fatalf("%+v", ev)
	}
	st := m.Stats()
	if st.Response != 2 || st.ResponseBlocked != 1 || st.Total != 2 || st.PerSignature["ST-JAVA"] != 1 || st.PerSignature["DB-ORACLE"] != 1 {
		t.Fatalf("%+v", st)
	}
	if s := m.Summary(ev.Time.Add(-1e9), 5); s.Response != 2 || s.Blocked != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestEverySignatureHasDocAndCompiles(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range builtinSignatures {
		if s.ID == "" || s.Doc == "" || s.Name == "" || s.re == nil || seen[s.ID] {
			t.Errorf("bad signature %q", s.ID)
		}
		seen[s.ID] = true
	}
	if n := len(ResponseSignatures()); n < len(builtinSignatures) {
		t.Fatal(n)
	}
}

/* ---- benchmarks ---- */

func benchPage(size int) []byte {
	var sb strings.Builder
	sb.WriteString("<!doctype html><html><head><title>Shop</title><script src=\"/app.js\"></script></head><body>")
	r := rand.New(rand.NewSource(1))
	for sb.Len() < size {
		sb.WriteString("<div class=\"item\"><a href=\"/p/" + strconv.Itoa(r.Intn(100000)) + "\">Product name with some text</a><span>$" + strconv.Itoa(r.Intn(900)) + "</span></div>\n")
	}
	return []byte(sb.String()[:size])
}

// BenchmarkScanClean64K: signature scan of a clean 64 KiB HTML window, all groups on
func BenchmarkScanClean64K(b *testing.B) {
	g := allGroups(NewManager(), RespActionBlock, ModeBlock)
	data := benchPage(64 * 1024)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.scan(data, 0)
	}
}

// BenchmarkScanWorstCase64K: a page that contains every prefilter literal but no real leak
func BenchmarkScanWorstCase64K(b *testing.B) {
	g := allGroups(NewManager(), RespActionBlock, ModeBlock)
	var sb strings.Builder
	for _, s := range builtinSignatures {
		for _, p := range s.pre {
			sb.Write(p)
			sb.WriteString(" filler text ")
		}
	}
	data := append(benchPage(64*1024-sb.Len()), sb.String()...)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.scan(data, ctxJSON|ctxPlain)
	}
}

func benchInspect(b *testing.B, g *ResponseGuard, body []byte, ct string) {
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	rd := bytes.NewReader(body)
	for i := 0; i < b.N; i++ {
		rd.Reset(body)
		res := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {ct}}, ContentLength: int64(len(body)), Body: io.NopCloser(rd)}
		g.Inspect(ResponseInfo{Endpoint: "e"}, nil, res, false)
		io.Copy(io.Discard, res.Body)
	}
}

// BenchmarkInspectDisabled: the disabled path is the nil check of the caller; a nil guard is the same cost
func BenchmarkInspectDisabled(b *testing.B) {
	var g *ResponseGuard
	res := &http.Response{StatusCode: 200, Header: http.Header{}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g.Inspect(ResponseInfo{}, nil, res, false)
	}
}

// BenchmarkInspectEnabled*: whole guard path (window fill, scan, replay copy) for a 100 KiB page
func BenchmarkInspectEnabledHTML100K(b *testing.B) {
	benchInspect(b, allGroups(NewManager(), RespActionBlock, ModeBlock), benchPage(100*1024), "text/html; charset=utf-8")
}

func BenchmarkInspectEnabledSmallJSON(b *testing.B) {
	benchInspect(b, allGroups(NewManager(), RespActionBlock, ModeBlock), []byte(`{"id":1,"name":"widget","tags":["a","b"],"price":12.5}`), "application/json")
}

// BenchmarkInspectSkippedBinary: enabled guard, response that is not inspected
func BenchmarkInspectSkippedBinary(b *testing.B) {
	benchInspect(b, allGroups(NewManager(), RespActionBlock, ModeBlock), benchPage(100*1024), "application/octet-stream")
}

// BenchmarkBaselineCopy100K: the copy alone, to put the numbers above in relation
func BenchmarkBaselineCopy100K(b *testing.B) {
	benchInspect(b, nil, benchPage(100*1024), "text/html")
}

type runtimeMem struct{ total uint64 }

func (r *runtimeMem) read() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	r.total = ms.TotalAlloc
}
