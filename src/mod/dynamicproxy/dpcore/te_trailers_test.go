package dpcore

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// gRPC clients send "TE: trailers" and some gRPC servers insist on it. TE is hop-by-hop, but
// net/http/httputil.ReverseProxy keeps exactly the "trailers" token (Go issue 21096); so must we.
// Found by the data-plane e2e suite (tools/e2e, h2c_grpc_upstream).
func TestTETrailersIsForwardedToUpstream(t *testing.T) {
	cases := []struct{ in, want string }{
		{"trailers", "trailers"},
		{"gzip, trailers", "trailers"},
		{"gzip", ""},
		{"", ""},
	}
	for _, c := range cases {
		var got atomic.Value
		got.Store("unset")
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got.Store(r.Header.Get("Te"))
		}))
		target, _ := url.Parse(up.URL)
		core := NewDynamicProxyCore(target, "", &DpcoreOptions{})
		req := httptest.NewRequest(http.MethodPost, "http://front.example.com/svc/Call", strings.NewReader("x"))
		if c.in != "" {
			req.Header.Set("Te", c.in)
		}
		core.ProxyHTTP(httptest.NewRecorder(), req, &ResponseRewriteRuleSet{ProxyDomain: target.Host, OriginalHost: "front.example.com"})
		up.Close()
		if got.Load().(string) != c.want {
			t.Errorf("TE %q: upstream saw %q, want %q", c.in, got.Load(), c.want)
		}
	}
}
