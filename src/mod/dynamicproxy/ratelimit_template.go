package dynamicproxy

import (
	"errors"
	"fmt"
	"strings"
)

/*
	ratelimit_template.go

	The rate limit parts of a RuleTemplate / app preset: per minute numbers, keying, WebSocket accounting and
	path scoped limits (PathRule entries with the rate_limit action; the existing per site path rule list is the
	least invasive place for them, see ratelimit_policy.go).

	With NoDowngrade (every app preset) nothing the operator has is made weaker:
	  - the site wide limit is only applied when there is none or a looser one (compared in requests per second,
	    so 60 req/min equals 1 req/s),
	  - a key choice is only set when the template also applies its limit and no key was chosen,
	  - the WebSocket cap only ever gets lower, and the WebSocket exemption is only allowed together with a cap,
	  - a path limit for a path that already has a rate_limit rule keeps the stricter of the two; new path limits
	    are appended at the END of the path rule list, so they can never shadow an existing deny / allow rule
	    (the first matching path rule decides),
	  - exemptions are never touched.
*/

const maxTemplatePathLimits = 20

// PathRateLimit is a path scoped limit a template adds to the rule's path rules
type PathRateLimit struct {
	Name      string
	Pattern   string   //Path prefix, starts with /
	Methods   []string `json:",omitempty"` //Empty = every method
	RateLimit int64
	RateUnit  string `json:",omitempty"` //"" = second, "minute"
	RateBurst int64  `json:",omitempty"` //0 = same as the number
}

func (p *PathRateLimit) asRule() *PathRule {
	return &PathRule{Name: p.Name, MatchMode: PathRuleMatchPrefix, Pattern: p.Pattern, Methods: append([]string(nil), p.Methods...),
		Action: PathRuleRateLimit, RateLimit: p.RateLimit, RateUnit: p.RateUnit, RateBurst: p.RateBurst}
}

func (t *RuleTemplate) rateUnit() string {
	if t.RateUnit == nil {
		return RateUnitSecond
	}
	u, _ := NormalizeRateUnit(*t.RateUnit)
	return u
}

// validateRateParts checks the rate limit related template fields
func (t *RuleTemplate) validateRateParts() error {
	if t.RateUnit != nil {
		if _, err := NormalizeRateUnit(*t.RateUnit); err != nil {
			return err
		}
		if t.RateLimit == nil {
			return errors.New("a rate unit needs a rate limit")
		}
	}
	kb, kh := "", ""
	if t.RateKeyBy != nil {
		kb = *t.RateKeyBy
	}
	if t.RateKeyHeader != nil {
		kh = *t.RateKeyHeader
	}
	if err := ValidateKeying(kb, kh); err != nil {
		return err
	}
	if k, _ := normalizeKeyBy(kb); k != RateKeyIP && t.RateLimit == nil {
		return errors.New("a rate limit key needs a rate limit")
	}
	if t.WSMaxConnsPerIP != nil && (*t.WSMaxConnsPerIP < 0 || *t.WSMaxConnsPerIP > maxWSConnsPerIP) {
		return errors.New("invalid WebSocket connection cap")
	}
	if t.WSExemptFromRateLimit != nil && *t.WSExemptFromRateLimit && (t.WSMaxConnsPerIP == nil || *t.WSMaxConnsPerIP <= 0) {
		return errors.New("exempting WebSocket handshakes from the rate limit needs a connection cap")
	}
	if len(t.PathRateLimits) > maxTemplatePathLimits {
		return errors.New("too many path limits")
	}
	for i := range t.PathRateLimits {
		p := &t.PathRateLimits[i]
		if _, err := compilePathRule(p.asRule()); err != nil {
			return fmt.Errorf("path limit %d: %w", i+1, err)
		}
	}
	return nil
}

func rateStringU(limit int64, unit string, on bool) string {
	if !on {
		return "off"
	}
	return FormatRate(limit, unit)
}

// applyRateTemplate is the rate limit part of ApplyRuleTemplateIn
func applyRateTemplate(ep *ProxyEndpoint, t *RuleTemplate, add func(field, old, nu string)) {
	rateApplied := false
	if t.RateLimit != nil {
		tu := t.rateUnit()
		curPerSec := RatePerSecond(ep.RateLimit, ep.RateUnit)
		keep := t.NoDowngrade && (*t.RateLimit <= 0 || (ep.RequireRateLimit && ep.RateLimit > 0 && curPerSec <= RatePerSecond(*t.RateLimit, tu)))
		if !keep {
			rateApplied = true
			if ep.RateUnit == RateUnitSecond && tu == RateUnitSecond {
				add("Rate limit (req/s)", rateString(ep), fmt.Sprint(*t.RateLimit))
			} else {
				add("Rate limit", rateStringU(ep.RateLimit, ep.RateUnit, ep.RequireRateLimit), rateStringU(*t.RateLimit, tu, *t.RateLimit > 0))
			}
			ep.RequireRateLimit = *t.RateLimit > 0
			ep.RateLimit = *t.RateLimit
			ep.RateUnit = tu
		}
	}
	if t.RateLimitBurst != nil && (!t.NoDowngrade || rateApplied) {
		add("Rate limit burst", fmt.Sprint(ep.RateLimitBurst), fmt.Sprint(*t.RateLimitBurst))
		ep.RateLimitBurst = *t.RateLimitBurst
	}

	//Options are edited on a copy: the rule may share the pointer with a live endpoint
	var o RateLimitOptions
	if ep.RateOptions != nil {
		o = *ep.RateOptions
	}
	before := o
	if t.RateKeyBy != nil && rateApplied {
		kb, _ := normalizeKeyBy(*t.RateKeyBy)
		if !t.NoDowngrade || o.KeyBy == RateKeyIP {
			if kb != o.KeyBy {
				name := func(k, h string) string {
					switch k {
					case RateKeyIP:
						return "client address"
					case RateKeyHeader:
						return "header " + h
					}
					return k
				}
				kh := ""
				if t.RateKeyHeader != nil {
					kh = *t.RateKeyHeader
				}
				add("Rate limit key", name(o.KeyBy, o.KeyHeader), name(kb, kh))
				o.KeyBy, o.KeyHeader = kb, ""
				if kb == RateKeyHeader {
					o.KeyHeader = kh
				}
			}
		}
	}
	if t.WSMaxConnsPerIP != nil && *t.WSMaxConnsPerIP > 0 {
		if !t.NoDowngrade || o.WSMaxConnsPerIP == 0 || o.WSMaxConnsPerIP > *t.WSMaxConnsPerIP {
			capStr := func(v int64) string {
				if v == 0 {
					return "no cap"
				}
				return fmt.Sprint(v)
			}
			add("WebSocket connections per client", capStr(o.WSMaxConnsPerIP), capStr(*t.WSMaxConnsPerIP))
			o.WSMaxConnsPerIP = *t.WSMaxConnsPerIP
		}
	}
	if t.WSExemptFromRateLimit != nil && o.WSExempt != *t.WSExemptFromRateLimit && !(t.NoDowngrade && !*t.WSExemptFromRateLimit) {
		add("WebSocket handshakes counted in the rate limit", yesNo(!o.WSExempt), yesNo(!*t.WSExemptFromRateLimit))
		o.WSExempt = *t.WSExemptFromRateLimit
	}
	if o.KeyBy != before.KeyBy || o.KeyHeader != before.KeyHeader || o.WSMaxConnsPerIP != before.WSMaxConnsPerIP || o.WSExempt != before.WSExempt {
		ep.RateOptions = o.Normalised()
	}

	for i := range t.PathRateLimits {
		applyPathRateLimit(ep, &t.PathRateLimits[i], t.NoDowngrade, add)
	}
}

func pathRuleSummary(r *PathRule) string {
	s := FormatRate(r.RateLimit, r.RateUnit)
	if r.RateBurst > 0 {
		s += fmt.Sprintf(", burst %d", r.RateBurst)
	}
	if len(r.Methods) > 0 {
		s += " (" + strings.Join(r.Methods, "/") + ")"
	}
	return s
}

func applyPathRateLimit(ep *ProxyEndpoint, p *PathRateLimit, noDowngrade bool, add func(field, old, nu string)) {
	want := p.asRule()
	field := "Path limit " + p.Pattern
	for i, ex := range ep.PathRules {
		if ex == nil || ex.Action != PathRuleRateLimit || strings.TrimSpace(ex.Pattern) != p.Pattern || ex.MatchMode == PathRuleMatchRegex || ex.MatchMode == PathRuleMatchExact {
			continue
		}
		//the same path already has a limit: keep the stricter one
		if noDowngrade && RatePerSecond(ex.RateLimit, ex.RateUnit) <= RatePerSecond(want.RateLimit, want.RateUnit) {
			return
		}
		if ex.RateLimit == want.RateLimit && ex.RateUnit == want.RateUnit && ex.RateBurst == want.RateBurst {
			return
		}
		add(field, pathRuleSummary(ex), pathRuleSummary(want))
		nr := *ex //copy: the rule pointer may be shared with a live endpoint
		nr.RateLimit, nr.RateUnit, nr.RateBurst = want.RateLimit, want.RateUnit, want.RateBurst
		rules := append([]*PathRule(nil), ep.PathRules...)
		rules[i] = &nr
		ep.PathRules = rules
		return
	}
	if len(ep.PathRules) >= maxPathRules {
		return
	}
	add(field, "(not set)", pathRuleSummary(want))
	ep.PathRules = append(append([]*PathRule(nil), ep.PathRules...), want)
}
