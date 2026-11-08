package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSplitUpstreamTarget(t *testing.T) {
	cases := []struct{ in, addr, path, hint string }{
		{"192.168.1.5:8080", "192.168.1.5:8080", "/", ""},
		{"example.com", "example.com:80", "/", ""},
		{"https://example.com", "example.com:443", "/", "https"},
		{"http://example.com/app?x=1", "example.com:80", "/app?x=1", "http"},
		{"[::1]:9000/health", "[::1]:9000", "/health", ""},
	}
	for _, c := range cases {
		a, p, h, err := splitUpstreamTarget(c.in)
		if err != nil || a != c.addr || p != c.path || h != c.hint {
			t.Errorf("%q: got %q %q %q %v", c.in, a, p, h, err)
		}
	}
	if _, _, _, err := splitUpstreamTarget("  "); err == nil {
		t.Error("empty input must be rejected")
	}
}

func TestTestUpstream(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer plain.Close()
	res := testUpstream(strings.TrimPrefix(plain.URL, "http://"))
	if !res.OK || res.Protocol != "http" || res.Status != 204 || res.SelfSign {
		t.Fatalf("plain http upstream: %+v", res)
	}

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer secure.Close()
	res = testUpstream(strings.TrimPrefix(secure.URL, "https://"))
	if !res.OK || res.Protocol != "https" || !res.SelfSign || res.Status != 200 {
		t.Fatalf("self signed https upstream: %+v", res)
	}
	// an explicit http:// hint must not try TLS
	res = testUpstream("http://" + strings.TrimPrefix(plain.URL, "http://"))
	if res.Protocol != "http" {
		t.Fatalf("hint ignored: %+v", res)
	}

	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := strings.TrimPrefix(closed.URL, "http://")
	closed.Close()
	res = testUpstream(addr)
	if res.OK || res.Error == "" {
		t.Fatalf("closed port must fail: %+v", res)
	}
	if res = testUpstream("unix:/nonexistent/zoraxy-test.sock"); res.OK {
		t.Fatalf("missing socket must fail: %+v", res)
	}
}
