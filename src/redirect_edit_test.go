package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/redirection"
	"imuslab.com/zoraxy/mod/info/logger"
)

// Editing a redirect rule with a missing destination used to report an error but carry on,
// deleting the old rule and saving a new one with an empty target.
func TestEditRedirectWithoutDestinationKeepsRule(t *testing.T) {
	old := redirectTable
	t.Cleanup(func() { redirectTable = old })
	l, _ := logger.NewFmtLogger()
	table, err := redirection.NewRuleTable(t.TempDir(), false, false, l)
	if err != nil {
		t.Fatal(err)
	}
	redirectTable = table
	if err := table.AddRedirectRule("old.example.com", "https://target.example.com", true, 307, false, "all"); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"originalRedirectUrl": {"old.example.com"}, "newRedirectUrl": {"new.example.com"}}
	r := httptest.NewRequest(http.MethodPost, "/api/redirect/edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleEditRedirectionRule(w, r)

	if !strings.Contains(w.Body.String(), "error") {
		t.Fatalf("expected an error response, got %q", w.Body.String())
	}
	rules := table.GetAllRedirectRules()
	if len(rules) != 1 || rules[0].RedirectURL != "old.example.com" || rules[0].TargetURL != "https://target.example.com" {
		t.Fatalf("rule was modified by a rejected edit: %+v", *rules[0])
	}
}
