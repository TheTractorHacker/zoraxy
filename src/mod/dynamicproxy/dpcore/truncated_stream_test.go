package dpcore_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
)

// If the upstream connection breaks after the response headers were sent, the
// client must see a failed transfer. Ending the chunked response cleanly would
// make a truncated download look complete.
func TestBrokenUpstreamBodyIsNotReportedAsComplete(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		// A chunked response that announces more data but is cut off without the final 0-chunk.
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nchunk\r\n")
		buf.Flush()
		time.Sleep(150 * time.Millisecond)
		conn.Close()
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := dpcore.NewDynamicProxyCore(upstreamURL, "", &dpcore.DpcoreOptions{})
	var gotErr atomic.Value
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := proxy.ServeHTTP(w, r, &dpcore.ResponseRewriteRuleSet{ProxyDomain: upstreamURL.Host, OriginalHost: r.Host})
		if err != nil {
			gotErr.Store(err)
			// the contract: callers abort the connection on ErrResponseAborted
			if errors.Is(err, dpcore.ErrResponseAborted) {
				panic(http.ErrAbortHandler)
			}
		}
	}))
	defer front.Close()

	resp, err := http.Get(front.URL + "/download")
	if err != nil {
		t.Fatalf("request failed before the body: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("truncated response (%q) was delivered to the client as if it were complete", body)
	}

	if e, _ := gotErr.Load().(error); e == nil || !errors.Is(e, dpcore.ErrResponseAborted) {
		t.Fatalf("ProxyHTTP should report dpcore.ErrResponseAborted, got %v", e)
	}
}
