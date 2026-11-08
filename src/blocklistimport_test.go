package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/access/blocklistimport"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

func setupBlocklistImportTest(t *testing.T) *access.AccessRule {
	t.Helper()
	tmp := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(tmp, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	lg, _ := logger.NewFmtLogger()
	SystemWideLogger = lg
	accessController, err = access.NewAccessController(&access.Options{
		Logger: *lg, ConfigFolder: filepath.Join(tmp, "access"),
		TrustedProxiesFile: filepath.Join(tmp, "tp.json"), Database: db,
	})
	if err != nil {
		t.Fatal(err)
	}
	blocklistImporter, _ = blocklistimport.NewManager(filepath.Join(tmp, "src.json"), accessController.GetAccessRuleByID)
	rule, _ := accessController.GetAccessRuleByID("default")
	return rule
}

func blPostForm(h http.HandlerFunc, vals url.Values) map[string]any {
	req := httptest.NewRequest("POST", "/x", strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, req)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestBlocklistImportAPI(t *testing.T) {
	rule := setupBlocklistImportTest(t)
	preview := func(w http.ResponseWriter, r *http.Request) { handleBlocklistImport(w, r, true) }
	apply := func(w http.ResponseWriter, r *http.Request) { handleBlocklistImport(w, r, false) }

	text := "# list\n1.1.1.1\n2.2.2.0/24 note\nbad\n1.1.1.1\n"
	out := blPostForm(preview, url.Values{"list": {"blacklist"}, "text": {text}})
	if out["accepted"] != float64(2) || out["invalid"] != float64(1) || out["duplicates"] != float64(1) || out["dryRun"] != true {
		t.Fatalf("preview = %v", out)
	}
	if rule.IPListSize(access.IPListBlack) != 0 {
		t.Fatal("preview changed the list")
	}
	out = blPostForm(apply, url.Values{"list": {"blacklist"}, "text": {text}, "comment": {"<b>my feed</b>"}})
	if out["accepted"] != float64(2) || rule.IPListSize(access.IPListBlack) != 2 {
		t.Fatalf("apply = %v", out)
	}
	if c := rule.IPListSnapshot(access.IPListBlack)["1.1.1.1"]; strings.Contains(c, "<") {
		t.Fatalf("markup stored in comment: %q", c)
	}

	// errors: bad list, no input, non-https URL, GET
	if out := blPostForm(apply, url.Values{"list": {"nope"}, "text": {text}}); out["error"] == nil {
		t.Fatal("bad list accepted")
	}
	if out := blPostForm(apply, url.Values{"list": {"blacklist"}}); out["error"] == nil {
		t.Fatal("empty input accepted")
	}
	if out := blPostForm(apply, url.Values{"list": {"blacklist"}, "url": {"http://example.com/l"}}); out["error"] == nil {
		t.Fatal("http url accepted")
	}
	if out := blPostForm(apply, url.Values{"list": {"blacklist"}, "url": {"https://127.0.0.1/l"}}); out["error"] == nil {
		t.Fatalf("loopback url accepted: %v", out)
	}
	w := httptest.NewRecorder()
	apply(w, httptest.NewRequest("GET", "/x", nil))
	if !strings.Contains(w.Body.String(), "POST required") {
		t.Fatalf("GET not refused: %s", w.Body.String())
	}
}
