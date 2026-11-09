package dpcore_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	End to end tests of the response inspection hook: real upstream, real dpcore proxy, real client.
*/

type testGuard struct {
	g     *waf.ResponseGuard
	calls atomic.Int32
}

func (t *testGuard) GuardResponse(req *http.Request, res *http.Response, streaming bool) int {
	t.calls.Add(1)
	return t.g.Inspect(waf.ResponseInfo{Endpoint: "test", Method: req.Method, Path: req.URL.Path}, req, res, streaming)
}

const leakPage = "<html><body>java.lang.RuntimeException: boom\n\tat com.acme.Foo.bar(Foo.java:42)\n\tat com.acme.Baz.run(Baz.java:7)\n\tat java.lang.Thread.run(Thread.java:748)\n</body></html>"

func newGuard(m *waf.Manager, mode string, winKiB int, groups map[string]string) *testGuard {
	return &testGuard{g: m.NewResponseGuard(&waf.ResponseConfig{WindowKiB: winKiB, Groups: groups}, mode)}
}

func frontFor(t *testing.T, upstream http.Handler, guard dpcore.ResponseGuard) (*httptest.Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	proxy := dpcore.NewDynamicProxyCore(u, "", &dpcore.DpcoreOptions{FlushInterval: 10 * time.Second})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r, &dpcore.ResponseRewriteRuleSet{ProxyDomain: u.Host, OriginalHost: r.Host, AllowUpgrade: true, ResponseGuard: guard})
	}))
	t.Cleanup(front.Close)
	return front, up
}

func get(t *testing.T, url string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept-Encoding", "identity")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestGuardBlockSendsGenericPageOnly(t *testing.T) {
	m := waf.NewManager()
	g := newGuard(m, waf.ModeBlock, 64, map[string]string{waf.GroupStackTrace: waf.RespActionBlock})
	front, _ := frontFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Upstream-Secret", "abc")
		w.WriteHeader(500)
		io.WriteString(w, leakPage)
	}), g)
	resp, body := get(t, front.URL+"/x", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "Foo") || strings.Contains(string(body), "RuntimeException") || len(body) > 64 {
		t.Fatalf("block page leaks or is not generic: %q", body)
	}
	if resp.Header.Get("X-Upstream-Secret") != "" {
		t.Fatal("upstream headers forwarded with a blocked response")
	}
	if ev := m.RecentEvents(5, ""); len(ev) != 1 || ev[0].Action != "blocked" {
		t.Fatalf("events %+v", ev)
	}
}

func TestGuardLogForwardsIdenticalBytes(t *testing.T) {
	m := waf.NewManager()
	g := newGuard(m, waf.ModeBlock, 64, map[string]string{waf.GroupStackTrace: waf.RespActionLog})
	payload := []byte(leakPage + strings.Repeat("y", 300000))
	front, _ := frontFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload))) // unknown length (chunked) responses are never held back
		w.Write(payload)
	}), g)
	resp, body := get(t, front.URL, nil)
	if resp.StatusCode != 200 || sha256.Sum256(body) != sha256.Sum256(payload) {
		t.Fatalf("status %d, body changed (%d vs %d bytes)", resp.StatusCode, len(body), len(payload))
	}
	if len(m.RecentEvents(5, "")) != 1 {
		t.Fatal("no event")
	}
}

func TestGuardLeakBeyondWindowPasses(t *testing.T) {
	m := waf.NewManager()
	g := newGuard(m, waf.ModeBlock, 1, map[string]string{waf.GroupStackTrace: waf.RespActionBlock})
	payload := []byte(strings.Repeat("y", 5000) + leakPage)
	front, _ := frontFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Write(payload)
	}), g)
	resp, body := get(t, front.URL, nil)
	if resp.StatusCode != 200 || !bytes.Equal(body, payload) {
		t.Fatal("a leak beyond the window is a documented limit and must pass through")
	}
}

func TestGuardLargeResponseStreamsAfterWindow(t *testing.T) {
	m := waf.NewManager()
	g := newGuard(m, waf.ModeBlock, 64, map[string]string{waf.GroupStackTrace: waf.RespActionBlock})
	release := make(chan struct{})
	const total = 1 << 20
	front, _ := frontFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "1048576")
		w.Write(bytes.Repeat([]byte("a"), 256*1024))
		w.(http.Flusher).Flush()
		<-release // the rest only exists once the test has seen the first part
		w.Write(bytes.Repeat([]byte("b"), total-256*1024))
	}), g)
	resp, err := http.Get(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, 200*1024)
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(resp.Body, first); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the part after the inspection window is being buffered until the upstream finishes")
	}
	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if len(first)+len(rest) != total {
		t.Fatalf("got %d bytes", len(first)+len(rest))
	}
}

func TestGuardStreamingAndSpecialResponsesPassUnbuffered(t *testing.T) {
	m := waf.NewManager()
	g := newGuard(m, waf.ModeBlock, 64, map[string]string{waf.GroupStackTrace: waf.RespActionBlock, waf.GroupSecrets: waf.RespActionBlock})

	t.Run("SSE reaches the client before the upstream finishes", func(t *testing.T) {
		release := make(chan struct{})
		front, _ := frontFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: "+strings.ReplaceAll(leakPage, "\n", " ")+"\n\n")
			w.(http.Flusher).Flush()
			<-release
			io.WriteString(w, "data: done\n\n")
		}), g)
		resp, err := http.Get(front.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 6)
		got := make(chan error, 1)
		go func() { _, err := io.ReadFull(resp.Body, buf); got <- err }()
		select {
		case err := <-got:
			if err != nil || string(buf) != "data: " {
				t.Fatalf("%v %q", err, buf)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("SSE event held back")
		}
		close(release)
		rest, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(rest), "data: done") {
			t.Fatalf("rest %q", rest)
		}
	})

	t.Run("chunked unknown length response", func(t *testing.T) {
		release := make(chan struct{})
		front, _ := frontFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "first-part ")
			w.(http.Flusher).Flush()
			<-release
			io.WriteString(w, leakPage)
		}), g)
		resp, err := http.Get(front.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 5)
		got := make(chan error, 1)
		go func() { _, err := io.ReadFull(resp.Body, buf); got <- err }()
		select {
		case err := <-got:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("chunked response held back")
		}
		close(release)
		rest, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(rest), "RuntimeException") {
			t.Fatal("chunked responses must pass through unmodified")
		}
	})

	t.Run("grpc content type", func(t *testing.T) {
		front, _ := frontFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Content-Length", strconv.Itoa(len(leakPage)))
			io.WriteString(w, leakPage)
		}), g)
		resp, body := get(t, front.URL, nil)
		if resp.StatusCode != 200 || !strings.Contains(string(body), "RuntimeException") {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("partial content", func(t *testing.T) {
		payload := leakPage
		front, _ := frontFor(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			http.ServeContent(w, r, "x.html", time.Time{}, strings.NewReader(payload))
		}), g)
		resp, body := get(t, front.URL, map[string]string{"Range": "bytes=0-99"})
		if resp.StatusCode != http.StatusPartialContent || string(body) != payload[:100] {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
	})

	t.Run("websocket style upgrade", func(t *testing.T) {
		before := g.calls.Load()
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, brw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nServer: nginx/1.18.0\r\n\r\nHELLO " + leakPage)
			brw.Flush()
			time.Sleep(200 * time.Millisecond)
		}))
		defer up.Close()
		u, _ := url.Parse(up.URL)
		proxy := dpcore.NewDynamicProxyCore(u, "", &dpcore.DpcoreOptions{})
		front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r, &dpcore.ResponseRewriteRuleSet{ProxyDomain: u.Host, OriginalHost: r.Host, AllowUpgrade: true, ResponseGuard: g})
		}))
		defer front.Close()
		conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		all, _ := io.ReadAll(bufio.NewReader(conn))
		if !strings.Contains(string(all), "101 Switching Protocols") || !strings.Contains(string(all), "HELLO") || !strings.Contains(string(all), "RuntimeException") {
			t.Fatalf("upgrade tunnel altered: %q", all)
		}
		if g.calls.Load() != before {
			t.Fatal("the guard saw an upgraded connection")
		}
	})
}

func TestGuardHeaderStripThroughProxy(t *testing.T) {
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "hello")
	})
	m := waf.NewManager()
	front, _ := frontFor(t, up, newGuard(m, waf.ModeBlock, 64, map[string]string{waf.GroupHeaders: waf.RespActionStrip}))
	resp, body := get(t, front.URL, nil)
	if resp.Header.Get("Server") != "" || resp.Header.Get("X-Powered-By") != "" || string(body) != "hello" {
		t.Fatalf("headers %v body %q", resp.Header, body)
	}
	front2, _ := frontFor(t, up, newGuard(m, waf.ModeBlock, 64, map[string]string{waf.GroupHeaders: waf.RespActionLog}))
	resp, _ = get(t, front2.URL, nil)
	if resp.Header.Get("Server") == "" || resp.Header.Get("X-Powered-By") != "PHP/7.4.3" {
		t.Fatalf("log must not strip: %v", resp.Header)
	}
	front3, _ := frontFor(t, up, nil)
	resp, _ = get(t, front3.URL, nil)
	if resp.Header.Get("X-Powered-By") != "PHP/7.4.3" {
		t.Fatalf("no guard must not strip: %v", resp.Header)
	}
}
