package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPprofSubPaths(t *testing.T) {
	cases := []struct {
		path string
		want int
		body string
	}{
		{"/api/info/pprof/", 200, "Types of profiles"},
		{"/api/info/pprof/heap?debug=1", 200, "heap profile"},
		{"/api/info/pprof/goroutine?debug=1", 200, "goroutine profile"},
		{"/api/info/pprof/cmdline", 200, ""},
		{"/api/info/pprof/nonexistent", 404, ""},
		{"/api/info/pprof/heap/../../x", 404, ""},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		handlePprof(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.path, rec.Code, c.want)
		}
		if c.body != "" && !strings.Contains(rec.Body.String(), c.body) {
			t.Errorf("%s: body does not contain %q", c.path, c.body)
		}
	}
}
