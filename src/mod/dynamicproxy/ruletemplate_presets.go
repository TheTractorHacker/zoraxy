package dynamicproxy

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

/*
	ruletemplate_presets.go

	App presets: ready-made starting points for well known self-hosted apps, shipped as data
	(ruletemplate_presets.json, embedded) and offered through the normal rule template APIs, so the
	template editor, the bulk "apply template" action and the preview all work on them unchanged.

	A preset is an ordinary RuleTemplate with Category "app", a Note and NoDowngrade set: it never lowers
	what the rule already has (WAF source, rate limit, exploit blocking, HSTS, headers set by the operator)
	and, like every template, never touches upstreams, domains or authentication.

	To add a preset: append an object to ruletemplate_presets.json (see DEVELOPMENT.md). TestAppPresets
	validates every entry and applies it to a fresh rule and to a configured rule.
*/

//go:embed ruletemplate_presets.json
var appPresetsJSON []byte

func init() {
	// fail at start-up (and in every test) if the data file is broken
	for _, t := range AppPresets() {
		if err := t.Validate(); err != nil {
			panic(fmt.Sprintf("ruletemplate_presets.json: preset %q: %v", t.Name, err))
		}
	}
}

// AppPresets returns fresh copies of the shipped app presets
func AppPresets() []*RuleTemplate {
	var out []*RuleTemplate
	if err := json.Unmarshal(appPresetsJSON, &out); err != nil {
		panic(fmt.Sprintf("ruletemplate_presets.json: %v", err))
	}
	for _, t := range out {
		t.Builtin, t.Category, t.NoDowngrade = true, "app", true
	}
	return out
}
