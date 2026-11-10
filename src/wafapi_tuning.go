package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	wafapi_tuning.go

	WAF tuning assistant APIs. The aggregation and the exclusion grammar live in
	mod/dynamicproxy/waf (tuning.go, tuning_agg.go); this file is the HTTP layer
	and the persistence of variable scoped exclusions, which go through the same
	mutate helpers as the quick exclusion (wafcentral.go).
*/

func RegisterWAFTuningAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/waf/tuning", HandleWAFTuning)
	authRouter.HandleFunc("/api/waf/tuning/apply", HandleWAFTuningApply)
	authRouter.HandleFunc("/api/waf/tuning/remove", HandleWAFTuningRemove)
}

// HandleWAFTuning aggregates the stored WAF events into tuning suggestions.
// GET hours (default 24, max 168), endpoint (optional)
func HandleWAFTuning(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	sendWAFJSON(w, waf.Default.Tuning(time.Now().Add(-time.Duration(hours)*time.Hour), endpoint, hours))
}

// HandleWAFTuningApply applies one suggestion. POST
//
//	scope       "global" (policy), "endpoint" (with rootname) or the endpoint name itself
//	rootname    endpoint name, "/" = default site
//	suggestion  JSON {kind, rule_ids, target, path, exact} as returned by /api/waf/tuning
//	variable    optional, "COLLECTION:name" as shown in an event; used when the suggestion has no target
//
// Kind "variable" adds a TargetExclusion, "path-rule" a path exclusion and "rule" a whole rule exclusion.
func HandleWAFTuningApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	scope, err := utils.PostPara(r, "scope")
	if err != nil {
		utils.SendErrorResponse(w, "scope not defined")
		return
	}
	scope = strings.TrimSpace(scope)
	ep, _ := utils.PostPara(r, "rootname")
	ep = strings.TrimSpace(ep)
	switch {
	case strings.EqualFold(scope, "global"):
		scope, ep = "global", ""
	case strings.EqualFold(scope, "endpoint"):
		scope = "endpoint"
	default:
		if ep == "" {
			ep = scope // scope given as the endpoint name
		}
		scope = "endpoint"
	}
	if scope == "endpoint" && ep == "" {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	raw, err := utils.PostPara(r, "suggestion")
	if err != nil {
		utils.SendErrorResponse(w, "suggestion not defined")
		return
	}
	var s waf.TuningSuggestion
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		utils.SendErrorResponse(w, "Invalid suggestion: "+err.Error())
		return
	}
	variable, _ := utils.PostPara(r, "variable")
	if err := applyWAFTuning(scope, ep, s, strings.TrimSpace(variable)); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func applyWAFTuning(scope, endpoint string, s waf.TuningSuggestion, variable string) error {
	if len(s.RuleIDs) == 0 {
		return errors.New("suggestion has no rule IDs")
	}
	// The anomaly-score evaluation rules turn the score into a block; excluding one disables blocking.
	for _, id := range s.RuleIDs {
		if waf.SpecTouchesScoreRule(id) {
			return errors.New("rule " + id + " evaluates the anomaly score and decides whether a request is blocked; it cannot be excluded here")
		}
	}
	switch s.Kind {
	case "variable":
		target := s.Target
		if target == "" && variable != "" {
			t, ok := waf.TargetForVariable(variable, false)
			if !ok {
				return errors.New("this variable cannot be excluded on its own")
			}
			target = t
		}
		te := waf.TargetExclusion{RuleIDs: s.RuleIDs, Target: target, Path: s.Path, Exact: s.Exact}
		if err := te.Validate(); err != nil {
			return err
		}
		return addWAFTargetExclusion(scope, endpoint, te)
	case "path-rule":
		if s.Path == "" {
			return errors.New("path not defined")
		}
		for _, id := range s.RuleIDs {
			if err := addWAFExclusion(scope, endpoint, id, s.Path, s.Exact); err != nil {
				return err
			}
		}
		return nil
	case "rule":
		for _, id := range s.RuleIDs {
			if err := addWAFExclusion(scope, endpoint, id, "", false); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("invalid suggestion kind")
}

// addWAFTargetExclusion adds a variable scoped exclusion to the global policy (scope "global") or to an
// endpoint: into its own config for custom WAFs, into its additive overrides for every other source.
func addWAFTargetExclusion(scope, endpoint string, te waf.TargetExclusion) error {
	if err := te.Validate(); err != nil {
		return err
	}
	if scope == "global" {
		return mutateWAFCentral(func(p *waf.Policy, _ *[]waf.Profile) error {
			p.TargetExclusions = waf.AddTargetExclusion(p.TargetExclusions, te)
			return nil
		})
	}
	if endpoint == "" {
		return errors.New("Target proxy rule not defined")
	}
	return applyWAFEndpoint(endpoint, func(ep *dynamicproxy.ProxyEndpoint, st *waf.State) error {
		switch ep.WAFSetting().EffectiveSource() {
		case waf.SourceOff:
			return errors.New("WAF is switched off for this endpoint")
		case waf.SourceCustom:
			var cfg waf.Config
			if ep.WAF != nil {
				cfg = *ep.WAF
				cfg.ExcludedRuleIDs = append([]string(nil), cfg.ExcludedRuleIDs...)
				cfg.PathExclusions = append([]waf.PathExclusion(nil), cfg.PathExclusions...)
			}
			cfg.TargetExclusions = waf.AddTargetExclusion(cfg.TargetExclusions, te)
			ep.WAF = &cfg
			ep.WAFSource = waf.SourceCustom
		default:
			x := waf.Overrides{}
			if ep.WAFExtra != nil {
				x = *ep.WAFExtra
				x.ExcludedRuleIDs = append([]string(nil), x.ExcludedRuleIDs...)
				x.PathExclusions = append([]waf.PathExclusion(nil), x.PathExclusions...)
			}
			x.TargetExclusions = waf.AddTargetExclusion(x.TargetExclusions, te)
			ep.WAFExtra = &x
		}
		return nil
	})
}

// HandleWAFTuningRemove removes a variable scoped exclusion. POST scope ("global", "endpoint" + rootname or the
// endpoint name), target, path (optional), exact (optional), ruleid (optional: remove only this rule ID from the
// entry, otherwise the whole entry goes).
func HandleWAFTuningRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	scope, err := utils.PostPara(r, "scope")
	if err != nil {
		utils.SendErrorResponse(w, "scope not defined")
		return
	}
	scope = strings.TrimSpace(scope)
	ep, _ := utils.PostPara(r, "rootname")
	ep = strings.TrimSpace(ep)
	switch {
	case strings.EqualFold(scope, "global"):
		scope, ep = "global", ""
	case strings.EqualFold(scope, "endpoint"):
		scope = "endpoint"
	default:
		if ep == "" {
			ep = scope
		}
		scope = "endpoint"
	}
	if scope == "endpoint" && ep == "" {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	target, err := utils.PostPara(r, "target")
	if err != nil {
		utils.SendErrorResponse(w, "target not defined")
		return
	}
	path, _ := utils.PostPara(r, "path")
	exact, _ := utils.PostBool(r, "exact")
	ruleID, _ := utils.PostPara(r, "ruleid")
	if err := removeWAFTargetExclusion(scope, ep, strings.TrimSpace(target), path, exact, strings.TrimSpace(ruleID)); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// withoutTargetExclusion returns the list without the matching entry (or without ruleID in it)
func withoutTargetExclusion(list []waf.TargetExclusion, target, path string, exact bool, ruleID string) ([]waf.TargetExclusion, bool) {
	var out []waf.TargetExclusion
	found := false
	for _, te := range list {
		if strings.EqualFold(te.Target, target) && te.Path == path && te.Exact == exact {
			found = true
			if ruleID != "" {
				var ids []string
				for _, id := range te.RuleIDs {
					if strings.TrimSpace(id) != ruleID {
						ids = append(ids, id)
					}
				}
				if len(ids) > 0 {
					te.RuleIDs = ids
					out = append(out, te)
				}
			}
			continue
		}
		out = append(out, te)
	}
	return out, found
}

func removeWAFTargetExclusion(scope, endpoint, target, path string, exact bool, ruleID string) error {
	if scope == "global" {
		return mutateWAFCentral(func(p *waf.Policy, _ *[]waf.Profile) error {
			var found bool
			p.TargetExclusions, found = withoutTargetExclusion(p.TargetExclusions, target, path, exact, ruleID)
			if !found {
				return errors.New("exclusion not found")
			}
			return nil
		})
	}
	return applyWAFEndpoint(endpoint, func(ep *dynamicproxy.ProxyEndpoint, st *waf.State) error {
		var found bool
		if ep.WAFSetting().EffectiveSource() == waf.SourceCustom {
			if ep.WAF == nil {
				return errors.New("exclusion not found")
			}
			cfg := *ep.WAF
			cfg.TargetExclusions, found = withoutTargetExclusion(cfg.TargetExclusions, target, path, exact, ruleID)
			ep.WAF = &cfg
		} else {
			if ep.WAFExtra == nil {
				return errors.New("exclusion not found")
			}
			x := *ep.WAFExtra
			x.TargetExclusions, found = withoutTargetExclusion(x.TargetExclusions, target, path, exact, ruleID)
			ep.WAFExtra = &x
		}
		if !found {
			return errors.New("exclusion not found")
		}
		return nil
	})
}

// rawHasKey reports whether the JSON object has the top level key. The settings editors that predate the
// tuning assistant do not send TargetExclusions; saving must not wipe them.
func rawHasKey(raw, key string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &m) != nil {
		return true
	}
	_, ok := m[key]
	return ok
}
