package dynamicproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

type zeroReader struct{ left int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.left {
		p = p[:z.left]
	}
	for i := range p {
		p[i] = 'a'
	}
	z.left -= int64(len(p))
	return len(p), nil
}

func uploadRate(t *testing.T, url string, size int64) (float64, int64) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, &zeroReader{left: size})
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	el := time.Since(start).Seconds()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %.80s", resp.StatusCode, b)
	}
	return float64(size) / el, size
}

// Upstream #950: a speed test through Zoraxy reported an impossible upload rate. A proxy that buffers or
// peeks the request body would inflate the number the browser reports. Check that the body is streamed:
// the upstream must receive every byte, and
// the proxied rate may not collapse compared with talking to the backend directly (also with the WAF on).
func TestUploadIsStreamedThroughProxy(t *testing.T) {
	for _, withWAF := range []bool{false, true} {
		name := "plain"
		if withWAF {
			name = "waf"
		}
		t.Run(name, func(t *testing.T) {
			router, sep, _ := newNonTLSTestRouter(t)
			router.pluginRouteHook = nil

			var received atomic.Int64
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n, _ := io.Copy(io.Discard, r.Body)
				received.Store(n)
				w.Write([]byte("ok"))
			}))
			defer backend.Close()

			sep.ProxyType = ProxyTypeHost
			if withWAF {
				sep.WAF = &waf.Config{Mode: waf.ModeBlock}
			}
			sep.VirtualDirectories = []*VirtualDirectoryEndpoint{{
				MatchingPath: "/up/",
				Domain:       strings.TrimPrefix(backend.URL, "http://") + "/up/",
			}}
			prepared, err := router.PrepareProxyRoute(sep)
			if err != nil {
				t.Fatal(err)
			}
			prepared.parent = router
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				router.handleNonTLSRequest(w, r, prepared)
			}))
			defer proxy.Close()

			const size = 96 << 20
			direct, _ := uploadRate(t, backend.URL+"/up/x", size)
			if received.Load() != size {
				t.Fatalf("direct: backend got %d bytes", received.Load())
			}
			received.Store(0)
			via, _ := uploadRate(t, proxy.URL+"/up/x", size)
			if received.Load() != size {
				t.Fatalf("proxied: backend got %d of %d bytes", received.Load(), int64(size))
			}
			t.Logf("direct %.0f MB/s, via proxy %.0f MB/s", direct/1e6, via/1e6)
			if via < direct/10 {
				t.Fatalf("proxy upload rate %.0f MB/s collapses vs direct %.0f MB/s", via/1e6, direct/1e6)
			}
		})
	}
}

// A slow client must not be acknowledged faster than it sends: when the upstream stalls reading, the
// client's Write has to block (back-pressure) instead of the proxy absorbing the whole body in memory.
func TestUploadBackpressureReachesClient(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.pluginRouteHook = nil

	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // do not read the body until released
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	sep.ProxyType = ProxyTypeHost
	sep.VirtualDirectories = []*VirtualDirectoryEndpoint{{
		MatchingPath: "/up/",
		Domain:       strings.TrimPrefix(backend.URL, "http://") + "/up/",
	}}
	prepared, err := router.PrepareProxyRoute(sep)
	if err != nil {
		t.Fatal(err)
	}
	prepared.parent = router
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		router.handleNonTLSRequest(w, r, prepared)
	}))
	defer proxy.Close()

	const size = 256 << 20
	pr, pw := io.Pipe()
	var sent atomic.Int64
	go func() {
		buf := make([]byte, 64<<10)
		for sent.Load() < size {
			n, err := pw.Write(buf)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
		pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/up/x", pr)
	done := make(chan struct{})
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		close(done)
	}()
	time.Sleep(1500 * time.Millisecond)
	got := sent.Load()
	close(release)
	pr.CloseWithError(io.EOF)
	<-done
	// Socket buffers hold some MB at most; absorbing 256 MiB means the proxy buffers the body.
	if got > 64<<20 {
		t.Fatalf("client managed to hand over %d MiB while the upstream was not reading: body is buffered", got>>20)
	}
}
