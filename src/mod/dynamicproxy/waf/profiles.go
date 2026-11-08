package waf

/*
	profiles.go

	Built-in, read-only WAF profiles. Editable copies can be made by cloning.
*/

func builtinProfiles() map[string]Profile {
	wpEditorRules := []string{"941100-941999", "942100-942999"}
	list := []Profile{
		{
			Name:        "WordPress",
			Description: "Blocking at paranoia 1. Relaxes XSS / SQLi rules for the block editor, admin-ajax and the REST API, which post HTML and JSON that looks like attacks.",
			Mode:        ModeBlock, ParanoiaLevel: 1, InboundThreshold: 5,
			PathExclusions: []PathExclusion{
				{Path: "/wp-admin/post.php", Exact: true, RuleIDs: wpEditorRules},
				{Path: "/wp-admin/post-new.php", Exact: true, RuleIDs: wpEditorRules},
				{Path: "/wp-admin/admin-ajax.php", Exact: true, RuleIDs: wpEditorRules},
				{Path: "/wp-json/wp/v2/", RuleIDs: wpEditorRules},
			},
		},
		{
			Name:        "API-only",
			Description: "Blocking at paranoia 1 with a higher anomaly threshold (two critical rules) for JSON / REST back ends that are not browsed by humans.",
			Mode:        ModeBlock, ParanoiaLevel: 1, InboundThreshold: 10,
			ExcludedRuleIDs: []string{"920340"},
		},
		{
			Name:        "Strict",
			Description: "Blocking at paranoia 3. Catches more, expect false positives: tune with a detection profile first.",
			Mode:        ModeBlock, ParanoiaLevel: 3, InboundThreshold: 5,
		},
		{
			Name:        "Learning",
			Description: "Detection only at paranoia 2. Logs what would be blocked without blocking anything, for tuning before switching to a blocking profile.",
			Mode:        ModeDetectionOnly, ParanoiaLevel: 2, InboundThreshold: 5,
		},
	}
	m := make(map[string]Profile, len(list))
	for _, p := range list {
		p.BuiltIn = true
		m[profileKey(p.Name)] = p
	}
	return m
}
