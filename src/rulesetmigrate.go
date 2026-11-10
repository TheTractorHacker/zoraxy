package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/ruleset"
)

/*
	Migration helper (read-only). Turns what exists today (path rules, header rules, bot rules, access list
	entries) into proposals for the rules engine. Nothing is created and nothing is removed: the UI shows the
	proposals ("import into the new Rules page") and the admin picks. Proposals are log-only (dry_run) so they
	can be watched before they act, and every proposal is checked with the same validator as a saved rule.

	"exact" is only true when the proposal behaves like the original for every request; otherwise "notes"
	say how it differs. What cannot be expressed at all is listed under not_converted.
*/

type migrationProposal struct {
	Source    string            `json:"source"`     // path_rule | header_rule | bot_rule | access_list
	SourceRef string            `json:"source_ref"` // where the original lives
	Site      string            `json:"site"`       // "" = global rule set, else the proxy rule key
	Rule      ruleset.RuleInput `json:"rule"`
	Lists     []ruleset.List    `json:"lists,omitempty"` // named lists the rule needs, created first
	Exact     bool              `json:"exact"`
	Notes     []string          `json:"notes,omitempty"`
	Valid     bool              `json:"valid"`
	Problems  []string          `json:"problems,omitempty"`
}

type migrationSkipped struct {
	Source    string `json:"source"`
	SourceRef string `json:"source_ref"`
	Reason    string `json:"reason"`
}

type migrationResult struct {
	Statement    string              `json:"statement"`
	Proposals    []migrationProposal `json:"proposals"`
	NotConverted []migrationSkipped  `json:"not_converted"`
}

const migrationStatement = "Read-only: nothing was created, changed or removed. The existing rules keep working. " +
	"Importing a proposal adds a rule that does the same job as the original, so import it log-only first, compare, " +
	"then remove the original (the access lists run before the rules, the path / header / bot rules run after them)."

var listNameClean = regexp.MustCompile(`[^a-z0-9_]+`)

func migListName(prefix, id string, used map[string]bool) string {
	base := prefix + "_" + listNameClean.ReplaceAllString(strings.ToLower(id), "_")
	if len(base) > 28 {
		base = base[:28]
	}
	name := base
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	used[name] = true
	return name
}

func q(s string) string { return ruleset.Quote(s) }

func qlist(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = q(s)
	}
	return "[" + strings.Join(out, ", ") + "]"
}

func sortedKeysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pathRuleExpression converts one path rule; ok=false when it cannot be expressed
func pathRuleExpression(pr *dynamicproxy.PathRule) (expr string, notes []string, exact bool) {
	exact = true
	pat := pr.Pattern
	var cond string
	subject := "http.path"
	if pr.CaseInsensitive {
		subject = "lower(http.path)"
		pat = strings.ToLower(pat)
	}
	switch pr.MatchMode {
	case dynamicproxy.PathRuleMatchExact:
		cond = subject + " == " + q(strings.TrimSuffix(pat, "/"))
		if strings.TrimSuffix(pat, "/") == "" {
			cond = subject + ` == "/"`
		}
		if len(pr.Methods) > 0 || len(pr.CIDRs) > 0 || len(pr.Countries) > 0 {
			cond = "(" + cond + ")"
		}
	case dynamicproxy.PathRuleMatchRegex:
		re := "^(?:" + pat + ")$"
		if pr.CaseInsensitive {
			re = "(?i)" + re
			cond = "http.path matches " + q(re)
		} else {
			cond = "http.path matches " + q(re)
		}
	default:
		p := strings.TrimSuffix(pat, "/")
		if p == "" {
			cond = subject + ` starts_with "/"`
		} else {
			cond = "(" + subject + " == " + q(p) + " or " + subject + " starts_with " + q(p+"/") + ")"
		}
	}
	notes = append(notes, "Path rules test several readings of the path (double encoded, dot segments ...); the engine's http.path is read once (percent-decoded once and normalised), so a request that relies on multiple decoding rounds is not matched.")
	exact = false
	if len(pr.Methods) > 0 {
		ms := make([]string, len(pr.Methods))
		for i, m := range pr.Methods {
			ms[i] = strings.ToUpper(m)
		}
		cond += " and http.method in " + qlist(ms)
	}
	var scope []string
	if len(pr.CIDRs) > 0 {
		scope = append(scope, "ip.src in "+qlist(pr.CIDRs))
	}
	if len(pr.Countries) > 0 {
		cs := make([]string, len(pr.Countries))
		for i, c := range pr.Countries {
			cs[i] = strings.ToUpper(c)
		}
		scope = append(scope, "ip.country in "+qlist(cs))
	}
	if len(scope) > 0 {
		s := strings.Join(scope, " or ")
		if pr.ScopeInvert {
			cond += " and not (" + s + ")"
		} else if len(scope) > 1 {
			cond += " and (" + s + ")"
		} else {
			cond += " and " + s
		}
	}
	return cond, notes, exact
}

func buildRulesetMigration(e *ruleset.Engine) migrationResult {
	res := migrationResult{Statement: migrationStatement, Proposals: []migrationProposal{}, NotConverted: []migrationSkipped{}}
	usedLists := map[string]bool{}
	for _, l := range e.Lists() {
		usedLists[l.Name] = true
	}
	add := func(p migrationProposal) {
		if p.Rule.DryRun == nil {
			t := true
			p.Rule.DryRun = &t
		}
		v := e.Validate(ruleset.ValidateInput{Expression: p.Rule.Expression, Action: &p.Rule.Action})
		// a proposal that needs lists is validated with those lists in place
		if len(p.Lists) > 0 && !v.OK {
			probe := ruleset.NewMemory()
			for _, l := range p.Lists {
				probe.SaveList(l)
			}
			v = probe.Validate(ruleset.ValidateInput{Expression: p.Rule.Expression, Action: &p.Rule.Action})
		}
		p.Valid = v.OK
		for _, er := range v.Errors {
			p.Problems = append(p.Problems, er.Msg)
		}
		if v.ActionError != "" {
			p.Problems = append(p.Problems, v.ActionError)
		}
		if v.OK {
			p.Rule.Expression = v.Text
		}
		res.Proposals = append(res.Proposals, p)
	}
	skip := func(src, ref, why string) {
		res.NotConverted = append(res.NotConverted, migrationSkipped{src, ref, why})
	}

	/* proxy rules: path rules, header rules, access list attachments */
	type epInfo struct {
		key string
		ep  *dynamicproxy.ProxyEndpoint
	}
	var eps []epInfo
	if dynamicProxyRouter != nil {
		for _, k := range proxyRuleKeys() {
			if v, ok := dynamicProxyRouter.ProxyEndpoints.Load(k); ok {
				if ep, ok := v.(*dynamicproxy.ProxyEndpoint); ok {
					eps = append(eps, epInfo{k, ep})
				}
			}
		}
		if dynamicProxyRouter.Root != nil {
			eps = append(eps, epInfo{ruleset.DefaultSiteKey, dynamicProxyRouter.Root})
		}
	}
	for _, ei := range eps {
		for i, pr := range ei.ep.PathRules {
			ref := fmt.Sprintf("%s, path rule %d", ei.key, i+1)
			if pr.Name != "" {
				ref += " (" + pr.Name + ")"
			}
			name := "Path rule: " + firstNonEmpty(pr.Name, pr.Pattern)
			expr, notes, exact := pathRuleExpression(pr)
			var act ruleset.Action
			switch pr.Action {
			case dynamicproxy.PathRuleDeny:
				act = ruleset.Action{Type: ruleset.ActBlock}
			case dynamicproxy.PathRuleRateLimit:
				act = ruleset.Action{Type: ruleset.ActRateLimit, Rate: pr.RateLimit, Burst: pr.RateBurst}
				notes = append(notes, "The path rule counted requests per (site, rule, client); the engine rule counts per (rule, client): same behaviour.")
			case dynamicproxy.PathRuleAllow:
				act = ruleset.Action{Type: ruleset.ActAllow}
				notes = append(notes, "A path rule 'allow' stops the other path rules only. The engine's 'allow' stops the other rules of the engine; it does not stop the old path / header / bot rules, which still run.")
				exact = false
			default:
				skip("path_rule", ref, "'"+pr.Action+"' (require authentication on this path) has no equivalent: the engine can skip authentication but not require it. Keep this path rule.")
				continue
			}
			add(migrationProposal{Source: "path_rule", SourceRef: ref, Site: ei.key,
				Rule: ruleset.RuleInput{Name: clipName(name), Expression: expr, Action: act}, Exact: exact, Notes: notes})
		}
		for i, hr := range ei.ep.HeaderRules {
			ref := fmt.Sprintf("%s, header rule %d (%s)", ei.key, i+1, hr.Name)
			cond, status, notes, exact := headerRuleExpression(hr)
			add(migrationProposal{Source: "header_rule", SourceRef: ref, Site: ei.key,
				Rule: ruleset.RuleInput{Name: clipName("Require header " + hr.Name), Expression: cond, Action: ruleset.Action{Type: ruleset.ActBlock, Status: status}}, Exact: exact, Notes: notes})
		}
	}

	/* bot rules (global) */
	if be := getBotEngine(); be != nil {
		cfg := be.Config()
		if cfg.Enabled || len(cfg.Custom) > 0 {
			for i, cr := range cfg.Custom {
				ref := fmt.Sprintf("Bot rules, custom rule %d (%s)", i+1, cr.Name)
				var cond string
				if cr.Type == botrules.MatchRegex {
					re := cr.Pattern
					if cr.CaseInsensitive {
						re = "(?i)" + re
					}
					cond = "http.user_agent matches " + q(re)
				} else {
					cond = "lower(http.user_agent) contains " + q(strings.ToLower(cr.Pattern))
				}
				var act ruleset.Action
				var notes []string
				exact := true
				switch cr.Action {
				case botrules.ActionChallenge:
					act = ruleset.Action{Type: ruleset.ActChallenge}
				case botrules.ActionLog:
					act = ruleset.Action{Type: ruleset.ActLog}
				case botrules.ActionDrop:
					act = ruleset.Action{Type: ruleset.ActBlock}
					notes = append(notes, "The original closes the connection without an answer; the engine answers 403.")
					exact = false
				default:
					act = ruleset.Action{Type: ruleset.ActBlock}
				}
				if !cfg.Enabled {
					notes = append(notes, "Bot rules are switched off globally today (sites can opt in); the proposal would apply to every site.")
					exact = false
				}
				notes = append(notes, "Bot rules look at every User-Agent header of a request; the engine joins them with \", \".")
				add(migrationProposal{Source: "bot_rule", SourceRef: ref, Site: "",
					Rule: ruleset.RuleInput{Name: clipName("Bot: " + firstNonEmpty(cr.Name, cr.Pattern)), Expression: cond, Action: act}, Exact: exact, Notes: notes})
			}
			for id, cc := range cfg.Categories {
				if cc.Enabled {
					skip("bot_rule", "Bot rules, category "+id, "Managed category lists hold hundreds of patterns, more than one expression can carry, and are updated with Zoraxy. Keep the Bot rules page for categories.")
				}
			}
			if cfg.BlockEmptyUA != "" {
				act := ruleset.Action{Type: ruleset.ActBlock}
				if cfg.BlockEmptyUA == botrules.ActionChallenge {
					act = ruleset.Action{Type: ruleset.ActChallenge}
				} else if cfg.BlockEmptyUA == botrules.ActionLog {
					act = ruleset.Action{Type: ruleset.ActLog}
				}
				add(migrationProposal{Source: "bot_rule", SourceRef: "Bot rules, empty User-Agent", Site: "",
					Rule: ruleset.RuleInput{Name: "Bot: no User-Agent", Expression: `http.user_agent == ""`, Action: act}, Exact: cfg.Enabled,
					Notes: []string{"Same as the original when bot rules are on globally."}})
			}
			if len(cfg.AllowedBots) > 0 || cfg.VerifyBots {
				skip("bot_rule", "Bot rules, good bots", "Verification of search engine bots by reverse DNS cannot be expressed (no network lookups in expressions). Keep the Bot rules page for this.")
			}
		}
	}

	/* access lists */
	if accessController != nil {
		for _, ar := range accessController.ListAllAccessRules() {
			users := []string{}
			if ar.ID == "default" {
				users = nil // global
			} else {
				for _, ei := range eps {
					if ei.ep.AccessFilterUUID == ar.ID {
						users = append(users, ei.key)
					}
				}
				if len(users) == 0 {
					skip("access_list", "Access rule "+ar.Name, "No proxy rule uses this access rule, so there is no site to attach the proposals to.")
					continue
				}
			}
			sites := users
			if ar.ID == "default" {
				sites = []string{""}
			}
			mk := func(kind, label string, cond string, act ruleset.Action, lists []ruleset.List, extra []string) {
				for _, s := range sites {
					p := migrationProposal{Source: "access_list", SourceRef: fmt.Sprintf("Access rule %q, %s", ar.Name, label), Site: s,
						Rule: ruleset.RuleInput{Name: clipName("Access " + ar.Name + ": " + label), Expression: cond, Action: act}, Lists: lists, Exact: true, Notes: append([]string{}, extra...)}
					if ar.DropOnBlock {
						p.Notes = append(p.Notes, "The access rule drops the connection of blocked clients; the proposal answers 403.")
						p.Exact = false
					}
					if ar.ID == "default" {
						p.Notes = append(p.Notes, "The default access rule applies to proxy rules without an access rule of their own; a global engine rule applies to every site.")
						p.Exact = false
					}
					add(p)
				}
			}
			countries := func(m *map[string]string) []string {
				var out []string
				if m != nil {
					for _, k := range sortedKeysOf(*m) {
						out = append(out, strings.ToUpper(k))
					}
				}
				return out
			}
			ips := func(m *map[string]string) []string {
				if m == nil {
					return nil
				}
				return sortedKeysOf(*m)
			}
			if ar.BlacklistEnabled {
				if l := ips(ar.BlackListIP); len(l) > 0 {
					name := migListName("bl", ar.ID, usedLists)
					mk("bl", "blacklisted addresses", "ip.src in $"+name, ruleset.Action{Type: ruleset.ActBlock},
						[]ruleset.List{{Name: name, Type: ruleset.ListIP, Description: "Imported from the blacklist of access rule " + ar.Name, Items: l}}, nil)
				}
				if c := countries(ar.BlackListContryCode); len(c) > 0 {
					mk("blc", "blacklisted countries", "ip.country in "+qlist(c), ruleset.Action{Type: ruleset.ActBlock}, nil, nil)
				}
			}
			if ar.WhitelistEnabled {
				ipl, cl := ips(ar.WhiteListIP), countries(ar.WhiteListCountryCode)
				if len(ipl) > 0 || len(cl) > 0 {
					var parts []string
					var lists []ruleset.List
					if len(ipl) > 0 {
						name := migListName("wl", ar.ID, usedLists)
						parts = append(parts, "ip.src in $"+name)
						lists = append(lists, ruleset.List{Name: name, Type: ruleset.ListIP, Description: "Imported from the whitelist of access rule " + ar.Name, Items: ipl})
					}
					if len(cl) > 0 {
						parts = append(parts, "ip.country in "+qlist(cl))
					}
					if ar.WhitelistAllowLocalAndLoopback {
						parts = append(parts, "ip.is_private")
					}
					mk("wl", "not on the whitelist", "not ("+strings.Join(parts, " or ")+")", ruleset.Action{Type: ruleset.ActBlock}, lists, nil)
				} else {
					skip("access_list", fmt.Sprintf("Access rule %q, whitelist", ar.Name), "The whitelist is enabled but empty (it blocks everybody); not proposed.")
				}
			}
			if ar.ChallengeCountryCode != nil {
				if c := countries(ar.ChallengeCountryCode); len(c) > 0 {
					mk("chc", "challenged countries", "ip.country in "+qlist(c), ruleset.Action{Type: ruleset.ActChallenge}, nil,
						[]string{"The country challenge uses the shared CAPTCHA session; the engine challenge keeps its own signed pass cookie."})
				}
			}
		}
	}
	return res
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func clipName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > ruleset.MaxNameLen {
		s = s[:ruleset.MaxNameLen]
	}
	return s
}

// headerRuleExpression converts a "require header" rule into a block condition (the request is blocked when
// the header requirement is NOT met)
func headerRuleExpression(hr *dynamicproxy.HeaderRule) (cond string, status int, notes []string, exact bool) {
	exact = true
	var present string
	hk := fmt.Sprintf("http.header[%s]", q(hr.Name))
	switch hr.Match {
	case dynamicproxy.HeaderMatchPresent:
		present = hk + " exists"
	case dynamicproxy.HeaderMatchRegex:
		parts := make([]string, len(hr.Values))
		for j, v := range hr.Values {
			parts[j] = hk + " matches " + q("^(?:"+v+")$")
		}
		present = strings.Join(parts, " or ")
		if len(parts) > 1 {
			present = "(" + present + ")"
		}
	default:
		present = hk + " in " + qlist(hr.Values)
		notes = append(notes, "The original compares secrets by hash in constant time and never logs them. The proposal contains the secret value in plain text in the expression (visible in the rules page, the change history and Fleet files).")
		exact = false
	}
	cond = "not (" + present + ")"
	if p := strings.TrimSpace(hr.PathPrefix); p != "" && p != "/" {
		cond = "(http.path == " + q(strings.TrimSuffix(p, "/")) + " or http.path starts_with " + q(strings.TrimSuffix(p, "/")+"/") + ") and " + cond
		notes = append(notes, "Path scope read once, see the note on path rules.")
		exact = false
	}
	status = 403
	switch hr.Action {
	case dynamicproxy.HeaderActionNotFound:
		status = 404
	case dynamicproxy.HeaderActionDrop:
		notes = append(notes, "The original closes the connection without an answer; the engine answers 403.")
		exact = false
	}
	return
}
