package dynamicproxy

import (
	"errors"
	"fmt"
	"strings"
)

/*
	bulk.go

	Bulk edit of proxy rules (upstream #924): one action applied to many rules, one result per rule.

	Semantics: the request parameters are validated first and an invalid request changes nothing.
	After that every rule is processed independently on a copy of the rule (mutate, prepare, swap
	into the runtime, persist). A rule that fails is reported and left exactly as it was; the others
	are still applied (partial update). DryRun computes the same results without applying anything.
*/

const (
	BulkEnable        = "enable"
	BulkDisable       = "disable"
	BulkAddTags       = "add_tags"
	BulkRemoveTags    = "remove_tags"
	BulkSetWAF        = "set_waf"
	BulkSetRateLimit  = "set_ratelimit"
	BulkSetAuth       = "set_auth"
	BulkApplyTemplate = "apply_template"
	BulkDelete        = "delete"

	MaxBulkRules = 500
)

type BulkParams struct {
	Tags []string `json:",omitempty"`

	WAFSource  string `json:",omitempty"`
	WAFProfile string `json:",omitempty"`

	RateLimitEnabled bool  `json:",omitempty"`
	RateLimit        int64 `json:",omitempty"`
	RateLimitBurst   int64 `json:",omitempty"`

	AuthMethod string `json:",omitempty"` //"none", "oauth2" or "zorxauth"; basic and forward auth need per rule data and are refused

	Template *RuleTemplate `json:",omitempty"` //resolved template for apply_template

	Confirm bool `json:",omitempty"` //required for delete and for auth "none"
}

type BulkRequest struct {
	Rules  []string
	Action string
	Params BulkParams
	DryRun bool
}

type BulkResult struct {
	Rule    string
	OK      bool
	Error   string       `json:",omitempty"`
	Changes []RuleChange `json:",omitempty"`
}

// BulkHooks connect the engine to the persistence layer of the caller
type BulkHooks struct {
	Persist func(*ProxyEndpoint) error
	Remove  func(name string) error //delete the stored config of a rule
}

var wafBulkSources = map[string]bool{"inherit": true, "off": true, "detection_only": true, "block": true, "profile": true}

// ValidateBulk checks everything that does not depend on a particular rule
func (r *BulkRequest) Validate() error {
	if len(r.Rules) == 0 {
		return errors.New("no rules selected")
	}
	if len(r.Rules) > MaxBulkRules {
		return fmt.Errorf("too many rules selected (max %d)", MaxBulkRules)
	}
	p := &r.Params
	switch r.Action {
	case BulkEnable, BulkDisable:
	case BulkAddTags, BulkRemoveTags:
		if len(p.Tags) == 0 {
			return errors.New("no tags given")
		}
		for _, t := range p.Tags {
			if strings.TrimSpace(t) == "" || strings.ContainsAny(t, ",\r\n") || len(t) > 64 {
				return fmt.Errorf("invalid tag %q", t)
			}
		}
	case BulkSetWAF:
		if !wafBulkSources[p.WAFSource] {
			return errors.New("WAF source must be inherit, off, detection_only, block or profile")
		}
		if p.WAFSource == "profile" && p.WAFProfile == "" {
			return errors.New("a WAF profile name is required")
		}
	case BulkSetRateLimit:
		if p.RateLimitEnabled && p.RateLimit <= 0 {
			return errors.New("rate limit must be above 0")
		}
		if p.RateLimit < 0 || p.RateLimitBurst < 0 || p.RateLimit > 1000000 || p.RateLimitBurst > 10000000 {
			return errors.New("invalid rate limit values")
		}
	case BulkSetAuth:
		switch p.AuthMethod {
		case "none":
			if !p.Confirm {
				return errors.New("removing authentication needs confirmation")
			}
		case "oauth2", "zorxauth":
		default:
			return errors.New("bulk authentication change supports none, oauth2 and zorxauth only")
		}
	case BulkApplyTemplate:
		if p.Template == nil {
			return errors.New("template not found")
		}
		if err := p.Template.Validate(); err != nil {
			return err
		}
	case BulkDelete:
		if !p.Confirm {
			return errors.New("deleting rules needs confirmation")
		}
	default:
		return fmt.Errorf("unknown action %q", r.Action)
	}
	return nil
}

// BulkEdit runs the request. The returned error is only for an invalid request; per rule problems are in the results.
func (router *Router) BulkEdit(req *BulkRequest, hooks BulkHooks) ([]BulkResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	results := []BulkResult{}
	for _, name := range req.Rules {
		name = strings.ToLower(strings.TrimSpace(name))
		if seen[name] {
			continue
		}
		seen[name] = true
		res := BulkResult{Rule: name}
		changes, err := router.bulkOne(name, req, hooks)
		res.Changes = changes
		if err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
		results = append(results, res)
	}
	return results, nil
}

func (router *Router) bulkOne(name string, req *BulkRequest, hooks BulkHooks) ([]RuleChange, error) {
	if name == "" || name == "/" {
		return nil, errors.New("the default site cannot be bulk edited")
	}
	target, err := router.LoadProxy(name)
	if err != nil {
		return nil, err
	}
	p := &req.Params

	if req.Action == BulkDelete {
		ch := []RuleChange{{"Rule", "present", "deleted"}}
		if req.DryRun {
			return ch, nil
		}
		if err := router.RemoveProxyEndpointByRootname(name); err != nil {
			return nil, err
		}
		if hooks.Remove != nil {
			if err := hooks.Remove(name); err != nil {
				return ch, err
			}
		}
		return ch, nil
	}

	updated := CopyEndpoint(target)
	if updated == nil {
		return nil, errors.New("unable to copy the rule")
	}
	var changes []RuleChange
	note := func(field, old, nu string) {
		if old != nu {
			changes = append(changes, RuleChange{field, old, nu})
		}
	}

	switch req.Action {
	case BulkEnable, BulkDisable:
		want := req.Action == BulkDisable
		note("Enabled", yesNo(!updated.Disabled), yesNo(!want))
		updated.Disabled = want
	case BulkAddTags, BulkRemoveTags:
		before := strings.Join(updated.Tags, ", ")
		if req.Action == BulkAddTags {
			have := map[string]bool{}
			for _, t := range updated.Tags {
				have[t] = true
			}
			for _, t := range p.Tags {
				t = strings.TrimSpace(t)
				if !have[t] {
					updated.Tags = append(updated.Tags, t)
					have[t] = true
				}
			}
		} else {
			drop := map[string]bool{}
			for _, t := range p.Tags {
				drop[strings.TrimSpace(t)] = true
			}
			kept := []string{}
			for _, t := range updated.Tags {
				if !drop[t] {
					kept = append(kept, t)
				}
			}
			updated.Tags = kept
		}
		note("Tags", before, strings.Join(updated.Tags, ", "))
	case BulkSetWAF:
		old := updated.WAFSource
		if old == "" {
			old = "(default)"
		}
		nu := p.WAFSource
		if nu == "profile" {
			nu += ": " + p.WAFProfile
		}
		note("WAF source", old, nu)
		if p.WAFSource == "custom" {
			return nil, errors.New("custom WAF config cannot be set in bulk")
		}
		updated.WAFSource, updated.WAFProfile = p.WAFSource, ""
		if p.WAFSource == "profile" {
			updated.WAFProfile = p.WAFProfile
		}
		if st := router.WAFState(); st != nil {
			if err := st.ValidateSetting(updated.WAFSetting()); err != nil {
				return nil, err
			}
		}
	case BulkSetRateLimit:
		note("Rate limit (req/s)", rateString(updated), func() string {
			if !p.RateLimitEnabled {
				return "off"
			}
			return fmt.Sprint(p.RateLimit)
		}())
		updated.RequireRateLimit = p.RateLimitEnabled
		if p.RateLimitEnabled {
			updated.RateLimit, updated.RateLimitBurst = p.RateLimit, p.RateLimitBurst
		}
	case BulkSetAuth:
		if updated.AuthenticationProvider == nil {
			updated.AuthenticationProvider = &AuthenticationProvider{}
		}
		names := map[AuthMethod]string{AuthMethodNone: "none", AuthMethodBasic: "basic", AuthMethodForward: "forward", AuthMethodOauth2: "oauth2", AuthMethodZorxAuth: "zorxauth"}
		nu := map[string]AuthMethod{"none": AuthMethodNone, "oauth2": AuthMethodOauth2, "zorxauth": AuthMethodZorxAuth}[p.AuthMethod]
		note("Authentication", names[updated.AuthenticationProvider.AuthMethod], p.AuthMethod)
		updated.AuthenticationProvider.AuthMethod = nu
	case BulkApplyTemplate:
		changes, err = ApplyRuleTemplate(updated, p.Template)
		if err != nil {
			return nil, err
		}
	}

	if req.DryRun {
		return changes, nil
	}
	ready, err := router.PrepareProxyRoute(updated)
	if err != nil {
		return nil, err
	}
	if err := router.AddProxyRouteToRuntime(ready); err != nil {
		return nil, err
	}
	if hooks.Persist != nil {
		if err := hooks.Persist(updated); err != nil {
			return changes, fmt.Errorf("applied but not saved: %w", err)
		}
	}
	return changes, nil
}
