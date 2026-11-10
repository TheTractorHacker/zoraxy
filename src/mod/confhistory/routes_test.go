package confhistory

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSummaryNeverShowsRawPaths(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/some/unlisted/endpoint", nil)
	if s := Summary(r); strings.Contains(s, "/api") {
		t.Fatalf("raw API path in the summary: %q", s)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/security/posture/apply", nil)
	if s := Summary(r); s != "Security fixes applied" {
		t.Fatalf("apply summary: %q", s)
	}
}

// the preview of a security fix changes nothing, so it must not create a version or name one
func TestPosturePreviewIsReadOnly(t *testing.T) {
	if !SkipPath("/api/security/posture/preview") {
		t.Fatal("preview must be skipped")
	}
	if SkipPath("/api/security/posture/apply") {
		t.Fatal("apply must be recorded")
	}
}
