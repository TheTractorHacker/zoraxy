package main

import (
	"encoding/json"
	"imuslab.com/zoraxy/mod/botrules"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// The Bot rules page warns "challenge without a CAPTCHA blocks" from this field: it must be present, and 0 when no site has a CAPTCHA.
func TestBotRulesGetReportsCaptchaSites(t *testing.T) {
	old, oldBots := dynamicProxyRouter, botEngine
	dynamicProxyRouter = nil
	botEngine = botrules.New(filepath.Join(t.TempDir(), "botrules.json"))
	botEngineOnce.Do(func() {})
	defer func() { dynamicProxyRouter, botEngine = old, oldBots }()
	w := httptest.NewRecorder()
	HandleBotRulesGet(w, httptest.NewRequest("GET", "/api/botrules/get", nil))
	var out map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if string(out["CaptchaSites"]) != "0" {
		t.Fatalf("CaptchaSites = %s, want 0", out["CaptchaSites"])
	}
}
