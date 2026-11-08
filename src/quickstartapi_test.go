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

func TestQuickStartDecide(t *testing.T) {
	cases := []struct {
		dismissed bool
		rules     int
		running   bool
		show      bool
		cfg       bool
	}{
		{false, 0, false, true, false}, // fresh install
		{false, 3, false, true, false}, // rules but proxy not running
		{false, 0, true, true, false},  // running but no rule
		{false, 1, true, false, true},  // set up
		{true, 0, false, false, false}, // dismissed by hand
	}
	for i, c := range cases {
		s := quickStartDecide(c.dismissed, c.rules, c.running)
		if s.Show != c.show || s.Configured != c.cfg {
			t.Errorf("case %d: got show=%v configured=%v", i, s.Show, s.Configured)
		}
	}
}

func TestQuickStartDismissPersists(t *testing.T) {
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	old := sysdb
	sysdb = db
	t.Cleanup(func() { sysdb = old })

	get := func() quickStartState {
		w := httptest.NewRecorder()
		HandleQuickStartState(w, httptest.NewRequest("GET", "/api/quickstart", nil))
		var s quickStartState
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err, w.Body.String())
		}
		return s
	}
	post := func(v string) string {
		r := httptest.NewRequest("POST", "/api/quickstart", strings.NewReader(url.Values{"dismissed": {v}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		HandleQuickStartState(w, r)
		return w.Body.String()
	}
	if !get().Show {
		t.Fatal("fresh instance must show Quick Start")
	}
	post("true")
	if s := get(); s.Show || !s.Dismissed {
		t.Fatalf("dismissed state not kept: %+v", s)
	}
	post("false")
	if !get().Show {
		t.Fatal("Show Quick Start again must bring it back")
	}
	if !strings.Contains(post("maybe"), "error") {
		t.Fatal("a non boolean value must be rejected")
	}
}
