package aiassist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

/*
	Every model output is untrusted. It is decoded with unknown fields rejected, checked against
	enums, sizes and types, and then (for actions) re-derived from the event it was about: the model
	picks a TYPE and a rule id out of the event's own rule hits; paths, endpoints and addresses always
	come from the event, never from the model. Any violation rejects the whole answer.
*/

// Explain verdicts and action types (the allow list)
const (
	VerdictAttack        = "likely_attack"
	VerdictFalsePositive = "likely_false_positive"
	VerdictUnclear       = "unclear"

	ActExcludeVariable    = "exclude_variable"
	ActExcludeRuleForPath = "exclude_rule_for_path"
	ActBlocklistProposal  = "add_to_blocklist_proposal"
	ActNoAction           = "no_action"
)

var (
	verdicts    = []string{VerdictAttack, VerdictFalsePositive, VerdictUnclear}
	actionTypes = []string{ActExcludeVariable, ActExcludeRuleForPath, ActBlocklistProposal, ActNoAction}
	ruleActions = []string{"log", "challenge", "block", "rate_limit"}
)

// Size limits
const (
	maxExplainWords = 120
	maxActions      = 3
	maxSteps        = 10
)

// ErrInvalidOutput is the error class for any validation failure of model output.
var ErrInvalidOutput = errors.New("the model answer was rejected (it did not match the expected format)")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOutput, fmt.Sprintf(format, a...))
}

func strictDecode(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return invalid("empty or oversized")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalid("%s", capRunes(err.Error(), 120))
	}
	if dec.More() {
		return invalid("trailing data")
	}
	return nil
}

func inList(v string, list []string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// cleanModelText checks a model supplied string: valid UTF-8, no control or invisible characters
// (newlines allowed when multiline), length cap.
func cleanModelText(field, s string, max int, multiline bool) (string, error) {
	if !utf8.ValidString(s) {
		return "", invalid("%s is not valid text", field)
	}
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		return "", invalid("%s is longer than %d characters", field, max)
	}
	for _, r := range s {
		if r == '\n' && multiline {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", invalid("%s contains control characters", field)
		}
	}
	return s, nil
}

// ---------- explain ----------

// ExplainAction is what the model may propose.
type ExplainAction struct {
	Type     string `json:"type"`
	RuleID   int    `json:"rule_id,omitempty"`
	Variable string `json:"variable,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// ExplainResult is the model's answer for one event.
type ExplainResult struct {
	Verdict     string          `json:"verdict"`
	Explanation string          `json:"explanation"`
	Actions     []ExplainAction `json:"actions"`
}

func (r *ExplainResult) validate() error {
	if !inList(r.Verdict, verdicts) {
		return invalid("unknown verdict")
	}
	var err error
	if r.Explanation, err = cleanModelText("explanation", r.Explanation, 1200, true); err != nil {
		return err
	}
	if r.Explanation == "" || len(strings.Fields(r.Explanation)) > maxExplainWords {
		return invalid("explanation is empty or longer than %d words", maxExplainWords)
	}
	if len(r.Actions) > maxActions {
		return invalid("too many actions")
	}
	for i := range r.Actions {
		a := &r.Actions[i]
		if !inList(a.Type, actionTypes) {
			return invalid("unknown action type")
		}
		if a.RuleID < 0 || a.RuleID > 99999999 {
			return invalid("rule id out of range")
		}
		if a.Variable, err = cleanModelText("variable", a.Variable, 120, false); err != nil {
			return err
		}
		if a.Reason, err = cleanModelText("reason", a.Reason, 200, false); err != nil {
			return err
		}
	}
	return nil
}

// ParseExplain decodes and validates an explain answer.
func ParseExplain(raw []byte) (*ExplainResult, error) {
	var r ExplainResult
	if err := strictDecode(raw, &r); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// ---------- rule proposals ----------

// Proposal is a rule suggestion. It is only displayed or copied until the rules engine integration
// sets ValidateProposal; Mode is always log_only on creation.
type Proposal struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Reason      string `json:"reason"`
	Expression  string `json:"expression"`
	Action      string `json:"action"`
	Mode        string `json:"mode"`
}

// ModeLogOnly is the only mode a proposal can have.
const ModeLogOnly = "log_only"

// ValidateProposal is the hook for the rules engine: it must return an error when the expression
// does not compile in the real engine. Until it is set, proposals are display-only.
var ValidateProposal func(p Proposal) error

// ExpressionGrammarHint is given to the model to describe the expression language. The rules engine
// integration may replace it with the real field list.
var ExpressionGrammarHint = `Expressions are single-line boolean conditions in the style (http.request.uri.path contains "/wp-login.php") and (ip.geoip.country eq "XX") or (http.user_agent contains "sqlmap"). Combine with and / or / not and parentheses. Use only conditions that the summary supports.`

type proposalsResult struct {
	Proposals []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Reason      string `json:"reason"`
		Expression  string `json:"expression"`
		Action      string `json:"action"`
	} `json:"proposals"`
}

// Validate checks one proposal (also used by tests and by the rules integration).
func (p *Proposal) Validate() error {
	var err error
	if p.Name, err = cleanModelText("name", p.Name, 80, false); err != nil || p.Name == "" {
		return invalid("proposal name")
	}
	if p.Description, err = cleanModelText("description", p.Description, 300, false); err != nil {
		return err
	}
	if p.Reason, err = cleanModelText("reason", p.Reason, 300, false); err != nil {
		return err
	}
	if p.Expression, err = cleanModelText("expression", p.Expression, 500, false); err != nil || p.Expression == "" {
		return invalid("proposal expression")
	}
	if !inList(p.Action, ruleActions) {
		return invalid("unknown rule action")
	}
	p.Mode = ModeLogOnly
	if h := ValidateProposal; h != nil {
		if herr := h(*p); herr != nil {
			return invalid("rejected by the rules engine: %s", capRunes(herr.Error(), 160))
		}
	}
	return nil
}

// ParseProposals decodes the answer; max bounds the number kept.
func ParseProposals(raw []byte, max int) ([]Proposal, error) {
	var r proposalsResult
	if err := strictDecode(raw, &r); err != nil {
		return nil, err
	}
	if len(r.Proposals) > max {
		return nil, invalid("too many proposals")
	}
	out := make([]Proposal, 0, len(r.Proposals))
	for _, x := range r.Proposals {
		p := Proposal{Name: x.Name, Description: x.Description, Reason: x.Reason, Expression: x.Expression, Action: x.Action}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ---------- audit plan ----------

// PlanStep is one item of the configuration audit plan.
type PlanStep struct {
	ItemID   string `json:"item_id,omitempty"`
	Priority int    `json:"priority"`
	Title    string `json:"title"`
	Why      string `json:"why"`
	How      string `json:"how"`
}

// Plan is the prioritised, plain-language plan.
type Plan struct {
	Summary string     `json:"summary"`
	Steps   []PlanStep `json:"steps"`
}

// ParsePlan decodes and validates a plan; item ids must be among known.
func ParsePlan(raw []byte, known map[string]bool) (*Plan, error) {
	var p Plan
	if err := strictDecode(raw, &p); err != nil {
		return nil, err
	}
	var err error
	if p.Summary, err = cleanModelText("summary", p.Summary, 600, true); err != nil {
		return nil, err
	}
	if len(p.Steps) > maxSteps {
		return nil, invalid("too many steps")
	}
	for i := range p.Steps {
		s := &p.Steps[i]
		if s.Priority < 1 || s.Priority > 3 {
			return nil, invalid("priority must be 1..3")
		}
		if s.ItemID != "" && !known[s.ItemID] {
			return nil, invalid("unknown item id")
		}
		if s.Title, err = cleanModelText("title", s.Title, 100, false); err != nil || s.Title == "" {
			return nil, invalid("step title")
		}
		if s.Why, err = cleanModelText("why", s.Why, 300, true); err != nil {
			return nil, err
		}
		if s.How, err = cleanModelText("how", s.How, 300, true); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

// ---------- JSON schemas given to the model ----------

func objSchema(props map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func enumOf(vals []string) map[string]any { return map[string]any{"type": "string", "enum": vals} }

func explainSchema() map[string]any {
	return objSchema(map[string]any{
		"verdict":     enumOf(verdicts),
		"explanation": str("Plain English, at most 100 words."),
		"actions": map[string]any{"type": "array", "maxItems": maxActions, "items": objSchema(map[string]any{
			"type":     enumOf(actionTypes),
			"rule_id":  map[string]any{"type": "integer", "description": "A rule id that appears in the event (for exclude_* actions)."},
			"variable": str("A variable name that appears in that rule's hit (for exclude_variable)."),
			"reason":   str("One short sentence."),
		}, "type")},
	}, "verdict", "explanation", "actions")
}

func proposalsSchema() map[string]any {
	return objSchema(map[string]any{
		"proposals": map[string]any{"type": "array", "maxItems": 5, "items": objSchema(map[string]any{
			"name": str("Short name."), "description": str("What the rule does."), "reason": str("Which numbers in the summary justify it."),
			"expression": str("Rule expression."), "action": enumOf(ruleActions),
		}, "name", "description", "reason", "expression", "action")},
	}, "proposals")
}

func planSchema() map[string]any {
	return objSchema(map[string]any{
		"summary": str("Two or three sentences."),
		"steps": map[string]any{"type": "array", "maxItems": maxSteps, "items": objSchema(map[string]any{
			"item_id":  str("The id of the posture item this step fixes, if any."),
			"priority": map[string]any{"type": "integer", "description": "1 = do first, 3 = optional."},
			"title":    str("Short imperative title."), "why": str("Why it matters, plain language."), "how": str("Where in the admin UI to change it."),
		}, "priority", "title", "why", "how")},
	}, "summary", "steps")
}
