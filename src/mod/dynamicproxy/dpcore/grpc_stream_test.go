package dpcore

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// proxyWithPendingBody proxies a request whose body (unknown length) stays
// silent until the client is released, mimicking a gRPC bidi stream such as
// NetBird Signal, where the client sends nothing until the server responds.
//
// It returns a channel that fires when the upstream receives the request and
// one that carries ProxyHTTP's status once the body is released.
func proxyWithPendingBody(t *testing.T, contentType string) (arrived chan struct{}, done chan int, release func()) {
	t.Helper()
	arrived = make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		// Respond before reading any request body.
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
	}))
	t.Cleanup(upstream.Close)

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}
	core := NewDynamicProxyCore(target, "", &DpcoreOptions{})

	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, "http://front.example.com/signalexchange.SignalExchange/ConnectStream", pr)
	req.ContentLength = -1
	req.Header.Set("Content-Type", contentType)

	done = make(chan int, 1)
	go func() {
		status, _ := core.ProxyHTTP(httptest.NewRecorder(), req, &ResponseRewriteRuleSet{
			ProxyDomain:  target.Host,
			OriginalHost: "front.example.com",
		})
		done <- status
	}()
	release = func() { pw.Close() }
	t.Cleanup(release)
	return arrived, done, release
}

// Regression: the #1204 one-byte body peek must not block gRPC streams.
func TestGRPCStreamWithPendingBodyIsNotBlocked(t *testing.T) {
	for _, ct := range []string{"application/grpc", "application/grpc+proto", "Application/GRPC"} {
		t.Run(ct, func(t *testing.T) {
			arrived, done, release := proxyWithPendingBody(t, ct)
			select {
			case <-arrived:
			case <-time.After(3 * time.Second):
				t.Fatal("request never reached upstream: proxy blocked on the silent request body (gRPC stream deadlock)")
			}
			release()
			select {
			case status := <-done:
				if status != http.StatusOK {
					t.Fatalf("status = %d, want 200", status)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("ProxyHTTP did not return after the client body closed")
			}
		})
	}
}

// The #1204 workaround still applies to non-gRPC requests: the peeked byte
// must be restored so the upstream receives the complete body.
func TestNonGRPCChunkedBodyIsForwardedIntact(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)
	core := NewDynamicProxyCore(target, "", &DpcoreOptions{})

	const body = "hello-zoraxy"
	req := httptest.NewRequest(http.MethodPost, "http://front.example.com/", io.NopCloser(strings.NewReader(body)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")

	status, err := core.ProxyHTTP(httptest.NewRecorder(), req, &ResponseRewriteRuleSet{
		ProxyDomain:  target.Host,
		OriginalHost: "front.example.com",
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("status = %d, err = %v", status, err)
	}
	if got != body {
		t.Fatalf("upstream got body %q, want %q", got, body)
	}
}
