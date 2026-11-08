package captcha

import "testing"

// Java servlet containers (Tomcat, Jetty, Spring) drop ";param" from every path segment, so
// /private;x=1/area is the resource /private/area for them. A protected-prefix list must treat
// that reading as inside the prefix, otherwise the CAPTCHA can be skipped by adding ";a=b".
// Found by the data-plane e2e suite (tools/e2e, captcha_exemptions).
func TestShouldEnforcePathPathParameters(t *testing.T) {
	cfg := &Config{ProtectedPathPrefixes: []string{"/private"}}
	cases := []struct {
		target string
		want   bool
	}{
		{"/private/area", true},
		{"/private;a=b/area", true},
		{"/private;a=b", true},
		{"/x/..;a=b/private/area", true},
		{"/private%3Ba=b/area", true},
		{"/public;a=b/area", false},
		{"/privateer;a=b", false},
		{"/public/logo.png?next=/private;x", false},
	}
	for _, tc := range cases {
		if got := ShouldEnforcePath(tc.target, cfg); got != tc.want {
			t.Errorf("ShouldEnforcePath(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}
