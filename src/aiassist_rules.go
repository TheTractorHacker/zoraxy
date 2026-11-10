package main

import (
	"fmt"
	"strings"

	"imuslab.com/zoraxy/mod/aiassist"
	"imuslab.com/zoraxy/mod/ruleset"
)

/*
	aiassist_rules.go

	Connects the AI assistant's rule proposals to the rules engine:

	  - aiassist.ValidateProposal makes the real validator (mod/ruleset) the judge of every proposal, so an expression the
	    model invented (a field that does not exist, a bad regex, a list that is not there) never reaches the screen.
	  - aiassist.ExpressionGrammarHint tells the model the real language instead of a generic one.

	Nothing here creates or changes a rule. A proposal becomes a rule only through an explicit click in the admin UI that
	calls the normal /api/ruleset/ API in log-only mode (script/rulesbuilder.js and components/aiassist.html).
*/

// proposalAction is the action a proposal's action name stands for. The model only names a type; the parameters are
// fixed here (and repeated in components/aiassist.html, which shows them before anything is created).
func proposalAction(name string) ruleset.Action {
	switch name {
	case ruleset.ActBlock:
		return ruleset.Action{Type: ruleset.ActBlock}
	case ruleset.ActChallenge:
		return ruleset.Action{Type: ruleset.ActChallenge}
	case ruleset.ActRateLimit:
		return ruleset.Action{Type: ruleset.ActRateLimit, Rate: 10, Burst: 20}
	default:
		return ruleset.Action{Type: ruleset.ActLog}
	}
}

// validateAIProposal checks one proposal with the rules engine's validator
func validateAIProposal(p aiassist.Proposal) error {
	e := getRulesEngine()
	if e == nil {
		return fmt.Errorf("the rules engine is not available")
	}
	act := proposalAction(p.Action)
	res := e.Validate(ruleset.ValidateInput{Expression: p.Expression, Action: &act})
	if len(res.Errors) > 0 {
		return fmt.Errorf("%s", res.Errors[0].Error())
	}
	if res.ActionError != "" {
		return fmt.Errorf("%s", res.ActionError)
	}
	return nil
}

// aiGrammarHint describes the real expression language for the model
func aiGrammarHint() string {
	var fields []string
	for _, f := range ruleset.Fields() {
		name := f.Name
		if f.Indexed {
			name += `["name"]`
		}
		fields = append(fields, fmt.Sprintf("%s (%s)", name, f.Type))
	}
	var ops []string
	for _, o := range ruleset.Operators() {
		ops = append(ops, o.Text)
	}
	return "Expressions are single-line boolean conditions in this language. Fields: " + strings.Join(fields, ", ") +
		". Operators: " + strings.Join(ops, ", ") + ". A condition is field operator value, for example http.path starts_with \"/wp-login.php\" or ip.country in [\"CN\", \"RU\"] or lower(http.user_agent) contains \"sqlmap\"; " +
		"combine conditions with and / or / not and parentheses. Strings are double quoted, country codes are two upper case letters, http.path is the normalised path without a query. " +
		"Use only fields that exist and conditions that the summary supports. ip.asn does not exist."
}

// wireAIRules installs the hooks; idempotent
func wireAIRules() {
	aiassist.ValidateProposal = validateAIProposal
	aiassist.ExpressionGrammarHint = aiGrammarHint()
}
