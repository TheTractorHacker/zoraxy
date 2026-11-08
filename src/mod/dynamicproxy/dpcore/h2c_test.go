package dpcore

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// grpcLikeUpstream is a plain HTTP/2 (h2c only) server that behaves like a gRPC bidi stream:
// it echoes every line of the request body as soon as it arrives and ends with trailers.
// It rejects HTTP/1.x, like a real gRPC server would.
func grpcLikeUpstream(t *testing.T, protoSeen *atomic.Value) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protoSeen.Store(r.Proto)
		if r.ProtoMajor != 2 {
			http.Error(w, "http/2 only", http.StatusHTTPVersionNotSupported)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // headers go out before the first message, like a gRPC server
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			w.Write([]byte(sc.Text() + "\n"))
			w.(http.Flusher).Flush()
		}
		w.Header().Set("Grpc-Status", "0")
	})
	srv := httptest.NewServer(h2c.NewHandler(handler, &http2.Server{}))
	t.Cleanup(srv.Close)
	return srv
}

// h2cClient talks prior-knowledge HTTP/2 to the proxy front, like a gRPC client
func h2cClient() *http.Client {
	return &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
}

func newH2CFront(t *testing.T, core *ReverseProxy, target *url.URL) *httptest.Server {
	t.Helper()
	front := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		core.ProxyHTTP(w, r, &ResponseRewriteRuleSet{ProxyDomain: target.Host, OriginalHost: r.Host})
	}), &http2.Server{}))
	t.Cleanup(front.Close)
	return front
}

// Upstream #1029: a gRPC backend on plain HTTP/2 (NetBird) needs h2c towards the upstream.
// Bidirectional streaming and trailers must work, and the default (off) must keep HTTP/1.1.
func TestH2CUpstreamBidirectionalStream(t *testing.T) {
	var proto atomic.Value
	upstream := grpcLikeUpstream(t, &proto)
	target, _ := url.Parse(upstream.URL)

	// default: HTTP/1.1 towards the upstream, which a gRPC server rejects
	off := NewDynamicProxyCore(target, "", &DpcoreOptions{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://front.example.com/svc/Stream", strings.NewReader("hello\n"))
	req.Header.Set("Content-Type", "application/grpc")
	off.ProxyHTTP(rec, req, &ResponseRewriteRuleSet{ProxyDomain: target.Host, OriginalHost: "front.example.com"})
	if rec.Code == http.StatusOK {
		t.Fatalf("h2c off: plain HTTP/1.1 request unexpectedly served by an h2-only upstream (proto %v)", proto.Load())
	}

	// h2c on: full duplex stream
	on := NewDynamicProxyCore(target, "", &DpcoreOptions{H2C: true})
	front := newH2CFront(t, on, target)

	pr, pw := io.Pipe()
	creq, _ := http.NewRequest(http.MethodPost, front.URL+"/svc/Stream", pr)
	creq.Header.Set("Content-Type", "application/grpc")
	resp, err := h2cClient().Do(creq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	for _, msg := range []string{"ping1", "ping2", "ping3"} {
		// the reply must arrive while the request body is still open (bidi, no buffering)
		if _, err := pw.Write([]byte(msg + "\n")); err != nil {
			t.Fatal(err)
		}
		done := make(chan string, 1)
		go func() {
			line, _ := reader.ReadString('\n')
			done <- strings.TrimSpace(line)
		}()
		select {
		case got := <-done:
			if got != msg {
				t.Fatalf("echo = %q, want %q", got, msg)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no echo for %q: the stream is buffered or blocked", msg)
		}
	}
	pw.Close()
	io.Copy(io.Discard, reader)

	if p, _ := proto.Load().(string); p != "HTTP/2.0" {
		t.Errorf("upstream saw %q, want HTTP/2.0", p)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Errorf("trailer Grpc-Status = %q, want 0 (trailers: %v)", got, resp.Trailer)
	}
}

// h2c is for plain http:// upstreams only, and requests that need an Upgrade stay on HTTP/1.1
func TestH2CIgnoredForTLSAndUpgradeUsesHTTP1(t *testing.T) {
	httpsTarget, _ := url.Parse("https://example.com")
	if _, isH2C := NewDynamicProxyCore(httpsTarget, "", &DpcoreOptions{H2C: true}).Transport.(*h2cTransport); isH2C {
		t.Error("h2c must not replace the transport of an https upstream")
	}

	var gotProto atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto.Store(r.Proto + "|" + r.Header.Get("Upgrade"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	rt := NewDynamicProxyCore(target, "", &DpcoreOptions{H2C: true}).Transport
	req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if p, _ := gotProto.Load().(string); !strings.HasPrefix(p, "HTTP/1.1") {
		t.Errorf("upgrade request went over %q, want HTTP/1.1", p)
	}
}
