package aicrawler

import (
	"fmt"
	"sort"
)

// Finding is one informational line of the posture check. These are observations for the AI crawlers page only:
// they are not part of the Security Overview score and never change anything.
type Finding struct {
	ID    string `json:"id"`
	Level string `json:"level"` // ok | note | attention
	Text  string `json:"text"`
}

// Posture inspects the configuration and the loaded range data. proxyAIFlag counts proxy rules that still have the
// older all-or-nothing "block AI crawlers" switch on.
func (e *Engine) Posture(proxyAIFlag int) []Finding {
	c := e.cfg.Load()
	var out []Finding
	add := func(id, level, text string) { out = append(out, Finding{id, level, text}) }

	if !c.Enabled {
		add("policy-off", "note", "The AI crawler policy is off, so every AI crawler is handled exactly as before (the AI crawlers switch of a proxy rule and the bot rules, if you use them).")
		if proxyAIFlag > 0 {
			add("legacy-switch", "ok", fmt.Sprintf("%d proxy rules block all AI crawlers with the older switch.", proxyAIFlag))
		}
		return out
	}

	blocked, allowed, enforced := 0, 0, 0
	ef := c.effectiveFor("")
	for _, en := range registry {
		a := ef.actionFor(en)
		if a == ActBlock || a == ActChallenge {
			blocked++
			if !en.TokenOnly {
				enforced++
			}
		}
		if a == ActAllow {
			allowed++
		}
	}
	if blocked == 0 && allowed == 0 {
		add("no-global", "note", "The policy is on but the global policy sets no action, so crawlers without a per-site policy are still handled as before.")
	}
	if allowed > 0 && !c.Global.VerifiedOnly {
		add("allow-unverified", "attention", fmt.Sprintf("%d crawlers are allowed by User-Agent alone. The User-Agent is a claim any client can make; tick \"Verified crawlers only\" to let only verified ones in (crawlers whose operator publishes no method cannot be verified).", allowed))
	}
	if c.Global.BypassWAF {
		add("bypass-waf", "attention", "Verified, allowed crawlers skip the WAF. A verified address is trusted by this setting; turn it off if you want the WAF to inspect crawlers too.")
	}
	if c.Global.VerifiedOnly || c.Global.BypassWAF {
		missing := 0
		for _, s := range e.Ranges.Status() {
			if !s.Loaded {
				missing++
			}
		}
		if missing > 0 {
			add("ranges-missing", "attention", fmt.Sprintf("Verification needs the published address ranges and %d of %d lists are not loaded. Use \"Refresh ranges\" (nothing is fetched automatically).", missing, len(Sources())))
		}
	}
	robotsOn := c.Robots.Mode == RobotsMerge || c.Robots.Mode == RobotsServe
	siteKeys := make([]string, 0, len(c.Sites))
	for k := range c.Sites {
		siteKeys = append(siteKeys, k)
	}
	sort.Strings(siteKeys)
	for _, k := range siteKeys {
		s := c.Sites[k]
		if s.Mode == SiteOff {
			continue
		}
		if s.Robots.Mode == RobotsMerge || s.Robots.Mode == RobotsServe {
			robotsOn = true
		}
	}
	if robotsOn && enforced == 0 {
		add("robots-only", "attention", "robots.txt is served but no crawler is blocked or challenged. robots.txt is advisory: crawlers that ignore it are not stopped. Enforcement is the Block or Challenge action.")
	}
	if blocked > 0 && enforced > 0 {
		add("enforced", "ok", fmt.Sprintf("%d crawlers are blocked or challenged by default, not only asked through robots.txt.", enforced))
	}
	if proxyAIFlag > 0 {
		add("legacy-switch", "note", fmt.Sprintf("%d proxy rules still use the older all-or-nothing AI crawlers switch. It keeps working; an Allow here wins over it for that crawler.", proxyAIFlag))
	}
	return out
}
