package main

import (
	"testing"

	"imuslab.com/zoraxy/mod/aiassist"
	"imuslab.com/zoraxy/mod/posture"
)

func TestAIPostureAdapterMapsChecksAndIsReadOnly(t *testing.T) {
	calls := 0
	ov := posture.Overview{}
	ov.Checks = []posture.CheckResult{
		{ID: "waf-off", Title: "WAF is off", Status: posture.StatusFail, Severity: "high", Evidence: []string{"2 rules", "no WAF"}},
		{ID: "tls", Title: "TLS ok", Status: posture.StatusOK, Severity: "low", Why: "because"},
		{ID: "unk", Title: "Unknown", Status: posture.StatusUnknown, Severity: "medium"},
		{ID: "na", Title: "No rules", Status: posture.StatusNA, Severity: "low"},
	}
	src := aiPosture{overview: func() posture.Overview { calls++; return ov }}
	var _ aiassist.PostureSource = src
	items := src.Items()
	if len(items) != 3 {
		t.Fatalf("want 3 items (not-applicable skipped), got %+v", items)
	}
	if items[0].Status != "fail" || items[0].Detail != "2 rules; no WAF" || items[1].Status != "pass" || items[1].Detail != "because" || items[2].Status != "warn" {
		t.Fatalf("bad mapping %+v", items)
	}
	if calls != 1 {
		t.Fatalf("one read per call, got %d", calls)
	}
	if (aiPosture{}).Items() != nil {
		t.Fatal("nil source must give no items")
	}
}
