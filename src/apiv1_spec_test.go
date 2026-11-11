package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The spec must say which admin features are not reachable with a token, and those
// routes must really be absent from /api/v1 (a token never opens cookie-only APIs).
// TestAPIv1OpenAPIMatchesRoutes already proves every documented path is routed and vice versa.
func TestAPIv1SpecDocumentsAdminOnlyAreas(t *testing.T) {
	var spec struct {
		Info struct {
			Description string `yaml:"description"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal(apiV1OpenAPI, &spec); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(spec.Info.Description, "Not part of the token API") {
		t.Fatal("openapi.yaml lacks the 'Not part of the token API' section")
	}
	_, h, _, _, rw := v1TestSetup(t)
	for _, p := range []string{"/api/v1/proxy/captcha/default", "/api/v1/proxy/captcha/central", "/api/v1/proxy/templates/list", "/api/v1/updater/info", "/api/v1/apitoken/list", "/api/v1/backup"} {
		if w := v1Do(h, "GET", p, rw, ""); w.Code == 200 {
			t.Errorf("%s is reachable with a token", p)
		}
	}
}
