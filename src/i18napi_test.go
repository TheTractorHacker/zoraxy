package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/database"
)

func TestUILanguageAPI(t *testing.T) {
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	old := sysdb
	sysdb = db
	sysdb.NewTable("settings")
	t.Cleanup(func() { sysdb = old })

	call := func(method, lang string) (uiLanguageState, string) {
		var r = httptest.NewRequest(method, "/api/i18n/language", nil)
		if method == "POST" {
			r = httptest.NewRequest(method, "/api/i18n/language", strings.NewReader(url.Values{"language": {lang}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		w := httptest.NewRecorder()
		HandleUILanguage(w, r)
		var s uiLanguageState
		json.Unmarshal(w.Body.Bytes(), &s)
		return s, w.Body.String()
	}
	if s, _ := call("GET", ""); s.Language != "" || len(s.Supported) < 9 {
		t.Fatalf("fresh instance: %+v", s)
	}
	if s, _ := call("POST", "zh-CN"); s.Language != "zh-CN" {
		t.Fatalf("not saved: %+v", s)
	}
	if s, _ := call("GET", ""); s.Language != "zh-CN" {
		t.Fatalf("not persisted: %+v", s)
	}
	if _, body := call("POST", "klingon"); !strings.Contains(body, "error") {
		t.Fatal("unsupported language must be rejected")
	}
	if _, body := call("POST", "zh-tw"); !strings.Contains(body, "error") {
		t.Fatal("only canonical codes are stored")
	}
	if s, _ := call("GET", ""); s.Language != "zh-CN" {
		t.Fatalf("rejected value changed the setting: %+v", s)
	}
	if s, _ := call("POST", ""); s.Language != "" {
		t.Fatalf("clearing failed: %+v", s)
	}
}
