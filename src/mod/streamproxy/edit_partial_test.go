package streamproxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/streamproxy"
)

// An edit request that only renames a rule must not switch off TCP / logging or reset the
// PROXY protocol setting of the rule (API users that send a partial update).
func TestEditStreamProxyIsPartialUpdate(t *testing.T) {
	lg, _ := logger.NewFmtLogger()
	mgr, err := streamproxy.NewStreamProxy(&streamproxy.Options{
		DefaultTimeout: 1,
		ConfigStore:    t.TempDir(),
		Logger:         lg,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := mgr.NewConfig(&streamproxy.ProxyRelayOptions{
		Name: "orig", ListeningAddr: "127.0.0.1:0", ProxyAddr: "127.0.0.1:1",
		UseTCP: true, UseUDP: true, EnableLogging: true, Timeout: 7,
		ProxyProtocolVersion: streamproxy.ProxyProtocolV2,
	})

	form := url.Values{"uuid": {id}, "name": {"renamed"}}
	r := httptest.NewRequest(http.MethodPost, "/api/streamprox/config/edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mgr.HandleEditProxyConfigs(w, r)

	cfg, err := mgr.GetConfigByUUID(id)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "renamed" {
		t.Fatalf("name not updated: %q (%s)", cfg.Name, w.Body.String())
	}
	if !cfg.UseTCP || !cfg.UseUDP || !cfg.EnableLogging || cfg.ProxyProtocolVersion != streamproxy.ProxyProtocolV2 || cfg.Timeout != 7 {
		t.Fatalf("partial edit reset unrelated settings: %+v", cfg)
	}
}
