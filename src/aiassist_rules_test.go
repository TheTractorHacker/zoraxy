package main

import (
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/aiassist"
)

// The rules engine judges AI proposals: real expressions pass, invented ones are refused, and wiring the hook does
// not change the fixed log-only mode of a proposal.
func TestAIProposalsValidatedByRulesEngine(t *testing.T) {
	withTestRulesEngine(t)
	old, oldHint := aiassist.ValidateProposal, aiassist.ExpressionGrammarHint
	t.Cleanup(func() { aiassist.ValidateProposal, aiassist.ExpressionGrammarHint = old, oldHint })
	wireAIRules()

	for _, act := range []string{"log", "block", "challenge", "rate_limit"} {
		p := aiassist.Proposal{Name: "Probe", Description: "d", Reason: "r", Expression: `http.path starts_with "/wp-login.php" and ip.country != "DE"`, Action: act}
		if err := p.Validate(); err != nil {
			t.Errorf("action %s: a valid proposal was rejected: %v", act, err)
		}
		if p.Mode != aiassist.ModeLogOnly {
			t.Errorf("action %s: mode must stay log_only, got %q", act, p.Mode)
		}
	}
	bad := []string{
		`(http.request.uri.path contains "/wp-login.php")`, // the generic grammar the model used to be told about
		`ip.asn == 123`,                                    // a field the build does not have
		`http.path matches "("`,                            // regex that does not compile
		`http.path in $nonexistent`,                        // list that is not there
		`http.path starts_with`,                            // incomplete
	}
	for _, e := range bad {
		p := aiassist.Proposal{Name: "x", Description: "d", Reason: "r", Expression: e, Action: "block"}
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "rejected by the rules engine") {
			t.Errorf("%q must be rejected by the rules engine, got %v", e, err)
		}
	}
	if !strings.Contains(aiassist.ExpressionGrammarHint, "http.path") || strings.Contains(aiassist.ExpressionGrammarHint, "http.request.uri") {
		t.Error("the grammar hint must describe the real fields")
	}
}
