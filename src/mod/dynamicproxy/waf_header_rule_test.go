package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

// Upstream #1356 asks for header based access rules ("drop requests that do not carry
// X-Origin-Auth: <token>"). The per-endpoint WAF custom SecLang rules already express this.
func TestWAFCustomRuleRequiresHeader(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	sep.ProxyType = ProxyTypeHost
	sep.WAF = &waf.Config{
		Mode: waf.ModeBlock,
		CustomRules: "SecRule &REQUEST_HEADERS:X-Origin-Auth \"@eq 0\" \"id:100001,phase:1,deny,status:403\"\n" +
			"SecRule REQUEST_HEADERS:X-Origin-Auth \"!@streq s3cr3t\" \"id:100002,phase:1,deny,status:403\"",
	}
	prepared, err := router.PrepareProxyRoute(sep)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	prepared.parent = router

	do := func(token string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/index.html", nil)
		r.RemoteAddr = "198.51.100.1:1000"
		if token != "" {
			r.Header.Set("X-Origin-Auth", token)
		}
		router.handleNonTLSRequest(w, r, prepared)
		return w.Code
	}
	if code := do(""); code != 403 {
		t.Fatalf("request without the header got %d, want 403", code)
	}
	if code := do("wrong"); code != 403 {
		t.Fatalf("request with a wrong header value got %d, want 403", code)
	}
	if code := do("s3cr3t"); code != 299 {
		t.Fatalf("request with the right header got %d, want 299", code)
	}
}
