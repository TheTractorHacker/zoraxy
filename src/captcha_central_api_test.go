package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
)

const centralTestSecret = "TOP-SECRET-central-value-123"

func centralTestDB(t *testing.T) {
	t.Helper()
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	old := sysdb
	sysdb = db
	sysdb.NewTable("settings")
	captcha.SetCentral(nil)
	t.Cleanup(func() { sysdb = old; captcha.SetCentral(nil) })
}

func centralPost(form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/proxy/captcha/central", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	HandleCaptchaCentral(w, r)
	return w
}

func centralGet() *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	HandleCaptchaCentral(w, httptest.NewRequest(http.MethodGet, "/api/proxy/captcha/central", nil))
	return w
}

func TestCaptchaCentralAPISaveLoadMask(t *testing.T) {
	centralTestDB(t)
	if w := centralGet(); strings.TrimSpace(w.Body.String()) != "null" {
		t.Fatalf("unset central must read null: %s", w.Body.String())
	}
	w := centralPost(url.Values{
		"captchaProvider": {"0"}, "captchaSiteKey": {"csite"}, "captchaSecretKey": {centralTestSecret},
		"captchaSessionDuration": {"1800"}, "turnstileTheme": {"dark"}, "captchaVerifyHostname": {"true"},
	})
	if strings.Contains(w.Body.String(), "error") {
		t.Fatalf("save failed: %s", w.Body.String())
	}
	// in memory and in the database
	c := captcha.GetCentral()
	if c == nil || c.SiteKey != "csite" || c.SecretKey != centralTestSecret || c.SessionDuration != 1800 ||
		c.Turnstile == nil || c.Turnstile.Theme != "dark" || !c.VerifyHostname {
		t.Fatalf("not applied: %+v", c)
	}
	// the secret is never in the GET response
	g := centralGet().Body.String()
	if strings.Contains(g, centralTestSecret) {
		t.Fatalf("GET leaks the secret: %s", g)
	}
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(g), &v); err != nil || v["SecretSet"] != true || v["SecretKey"] != "" || v["SiteKey"] != "csite" {
		t.Fatalf("GET view: %s", g)
	}
	// restart: reload from the database
	captcha.SetCentral(nil)
	loadCaptchaCentral()
	if c := captcha.GetCentral(); c == nil || c.SecretKey != centralTestSecret {
		t.Fatalf("not restored from sysdb: %+v", c)
	}
}

func TestCaptchaCentralAPIEmptySecretKeepsStored(t *testing.T) {
	centralTestDB(t)
	centralPost(url.Values{"captchaProvider": {"0"}, "captchaSiteKey": {"csite"}, "captchaSecretKey": {centralTestSecret}})
	// change other fields, leave the secret empty
	w := centralPost(url.Values{"captchaProvider": {"0"}, "captchaSiteKey": {"csite2"}, "captchaSecretKey": {""}, "captchaSessionDuration": {"7200"}})
	if strings.Contains(w.Body.String(), "error") {
		t.Fatalf("%s", w.Body.String())
	}
	c := captcha.GetCentral()
	if c.SecretKey != centralTestSecret || c.SiteKey != "csite2" || c.SessionDuration != 7200 {
		t.Fatalf("%+v", c)
	}
	// another provider cannot reuse the stored secret
	w = centralPost(url.Values{"captchaProvider": {"1"}, "captchaSiteKey": {"g"}, "captchaSecretKey": {""}})
	if !strings.Contains(w.Body.String(), "secret key") || captcha.GetCentral().Provider != captcha.ProviderCloudflare {
		t.Fatalf("provider switch without a secret must be refused: %s", w.Body.String())
	}
}

func TestCaptchaCentralAPIValidation(t *testing.T) {
	centralTestDB(t)
	cases := map[string]url.Values{
		"no keys":       {"captchaProvider": {"0"}},
		"bad provider":  {"captchaProvider": {"x"}, "captchaSiteKey": {"a"}, "captchaSecretKey": {"b"}},
		"unknown":       {"captchaProvider": {"7"}, "captchaSiteKey": {"a"}, "captchaSecretKey": {"b"}},
		"bad duration":  {"captchaProvider": {"0"}, "captchaSiteKey": {"a"}, "captchaSecretKey": {"b"}, "captchaSessionDuration": {"soon"}},
		"bad turnstile": {"captchaProvider": {"0"}, "captchaSiteKey": {"a"}, "captchaSecretKey": {"b"}, "turnstileMode": {"bogus"}},
		"bad score":     {"captchaProvider": {"1"}, "captchaSiteKey": {"a"}, "captchaSecretKey": {"b"}, "captchaRecaptchaScore": {"4"}},
		"bad action":    {"captchaProvider": {"1"}, "captchaSiteKey": {"a"}, "captchaSecretKey": {"b"}, "captchaRecaptchaAction": {"x y"}},
	}
	for name, form := range cases {
		if w := centralPost(form); !strings.Contains(w.Body.String(), "error") {
			t.Errorf("%s: accepted: %s", name, w.Body.String())
		}
		if captcha.GetCentral() != nil {
			t.Fatalf("%s: a rejected save changed the central config", name)
		}
	}
	if w := httptest.NewRecorder(); true {
		HandleCaptchaCentral(w, httptest.NewRequest(http.MethodDelete, "/api/proxy/captcha/central", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE: %d", w.Code)
		}
	}
}

func TestCaptchaCentralAPIClear(t *testing.T) {
	centralTestDB(t)
	centralPost(url.Values{"captchaProvider": {"2"}, "captchaSecretKey": {"hmac-key"}})
	if captcha.GetCentral() == nil {
		t.Fatal("altcha save failed")
	}
	centralPost(url.Values{"clear": {"true"}})
	if captcha.GetCentral() != nil || sysdb.KeyExists("settings", captchaCentralKey) {
		t.Fatal("clear did not remove the central config")
	}
}

func TestApplyCaptchaCentralOptIn(t *testing.T) {
	old := &captcha.Config{Provider: captcha.ProviderGoogle, SiteKey: "own", SecretKey: "ownsecret", SessionDuration: 111,
		RecaptchaVersion: "v3", RecaptchaScore: 0.7, Turnstile: &captcha.TurnstileOptions{Theme: "dark"}}
	post := func(form url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/proxy/edit", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	// opt in: the posted (hidden) own fields are ignored, the stored ones stay
	form := url.Values{"captcha": {"true"}, "captchaUseCentral": {"true"}, "captchaProvider": {"0"}, "captchaSiteKey": {"junk"},
		"captchaSecretKey": {"junk"}, "captchaPathPrefixes": {"/a\n/b"}}
	r := post(form)
	cfg, err := parseCaptchaConfigFromRequest(r)
	if err != nil || !cfg.UseCentral {
		t.Fatalf("%v %+v", err, cfg)
	}
	applyCaptchaCentralOptIn(r, cfg, old)
	if cfg.Provider != captcha.ProviderGoogle || cfg.SiteKey != "own" || cfg.SecretKey != "ownsecret" || cfg.SessionDuration != 111 ||
		cfg.RecaptchaVersion != "v3" || cfg.Turnstile == nil || cfg.Turnstile.Theme != "dark" {
		t.Fatalf("own provider fields not kept: %+v", cfg)
	}
	if len(cfg.ProtectedPathPrefixes) != 2 {
		t.Fatalf("per-site paths must come from the form: %+v", cfg.ProtectedPathPrefixes)
	}
	// opt out: the posted fields win
	form.Set("captchaUseCentral", "false")
	form.Set("captchaSiteKey", "new")
	r = post(form)
	cfg, _ = parseCaptchaConfigFromRequest(r)
	applyCaptchaCentralOptIn(r, cfg, old)
	if cfg.UseCentral || cfg.SiteKey != "new" {
		t.Fatalf("%+v", cfg)
	}
	// a form without the field (older UI / script) keeps the stored choice
	old.UseCentral = true
	form.Del("captchaUseCentral")
	r = post(form)
	cfg, _ = parseCaptchaConfigFromRequest(r)
	applyCaptchaCentralOptIn(r, cfg, old)
	if !cfg.UseCentral || cfg.SiteKey != "own" {
		t.Fatalf("stored opt-in lost: %+v", cfg)
	}
}
