package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/aicrawler"
)

func useTestAICrawlerEngine(t *testing.T) *aicrawler.Engine {
	t.Helper()
	aiCrawlerOnce.Do(func() {})
	old := aiCrawlerEngine
	dir := t.TempDir()
	aiCrawlerEngine = aicrawler.New(filepath.Join(dir, "aicrawler.json"), filepath.Join(dir, "r.json"))
	t.Cleanup(func() { aiCrawlerEngine = old })
	return aiCrawlerEngine
}

func TestAICrawlerAPIGetSetPreview(t *testing.T) {
	eng := useTestAICrawlerEngine(t)

	// default: off, registry present, nothing loaded
	w := httptest.NewRecorder()
	HandleAICrawlerGet(w, httptest.NewRequest("GET", "/api/aicrawler/get", nil))
	var got struct {
		Config          aicrawler.Config
		RegistryVersion string
		Registry        []map[string]interface{}
		Ranges          []aicrawler.SourceStatus
		Posture         []aicrawler.Finding
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	if got.Config.Enabled || got.RegistryVersion == "" || len(got.Registry) < 20 || len(got.Posture) == 0 {
		t.Fatalf("unexpected default answer: %s", w.Body.String())
	}
	for _, r := range got.Ranges {
		if r.Loaded {
			t.Fatal("no range may be loaded by default")
		}
	}

	set := func(cfg string) string {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/aicrawler/set", strings.NewReader(url.Values{"config": {cfg}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		HandleAICrawlerSet(w, r)
		return w.Body.String()
	}
	if out := set(`{"Enabled":true,"Global":{"Groups":{"training":"block"}}}`); strings.Contains(out, "error") {
		t.Fatalf("set: %s", out)
	}
	if !eng.Enabled() {
		t.Fatal("config not applied")
	}
	for _, bad := range []string{`{"Enabled":true,"Global":{"Groups":{"nope":"block"}}}`, `nonsense`, `{"Global":{"Crawlers":{"gptbot":"destroy"}}}`} {
		if out := set(bad); !strings.Contains(out, "error") {
			t.Errorf("%s accepted: %s", bad, out)
		}
	}
	if !eng.Config().Enabled || eng.Config().Global.Groups["training"] != "block" {
		t.Fatal("a refused save changed the configuration")
	}

	// GET on set
	w = httptest.NewRecorder()
	HandleAICrawlerSet(w, httptest.NewRequest("GET", "/api/aicrawler/set", nil))
	if !strings.Contains(w.Body.String(), "error") {
		t.Error("set must refuse GET")
	}

	// preview: crawler classification and generated robots.txt
	w = httptest.NewRecorder()
	HandleAICrawlerPreview(w, httptest.NewRequest("GET", "/api/aicrawler/preview?site=a.example&ua="+url.QueryEscape("GPTBot/1.0"), nil))
	var pv struct {
		Robots string
		Match  map[string]interface{}
	}
	json.Unmarshal(w.Body.Bytes(), &pv)
	if pv.Match["id"] != "gptbot" || pv.Match["action"] != "block" || !strings.Contains(pv.Robots, "User-agent: GPTBot") {
		t.Fatalf("preview: %s", w.Body.String())
	}
}

func TestAICrawlerRefreshRefusesGET(t *testing.T) {
	useTestAICrawlerEngine(t)
	w := httptest.NewRecorder()
	HandleAICrawlerRefresh(w, httptest.NewRequest("GET", "/api/aicrawler/ranges/refresh", nil))
	if !strings.Contains(w.Body.String(), "error") {
		t.Fatalf("refresh must be a POST: %s", w.Body.String())
	}
}
