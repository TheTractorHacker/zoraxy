package dynamicproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/dynamicproxy/rewrite"
)

func newTestHeader(k, v string) *rewrite.UserDefinedHeader {
	return &rewrite.UserDefinedHeader{Direction: rewrite.HeaderDirection_ZoraxyToDownstream, Key: k, Value: v}
}

func presetTestRule() *ProxyEndpoint {
	ep := GetDefaultProxyEndpoint()
	ep.RootOrMatchingDomain = "app.example.com"
	ep.MatchingDomainAlias = []string{"alias.example.com"}
	ep.ActiveOrigins = []*loadbalance.Upstream{{OriginIpOrDomain: "10.0.0.5:8080"}}
	return &ep
}

func TestAppPresetsCatalogue(t *testing.T) {
	want := []string{"WordPress", "Nextcloud", "Home Assistant", "Jellyfin", "Plex", "Grafana", "Vaultwarden",
		"Gitea or GitLab", "Portainer", "JSON API", "Static website", "Strict admin panel",
		"Public website", "Login page", "Admin dashboard", "Odoo ERP", "REST API per key", "Webhook receiver", "File upload", "WebSocket app limits", "Monitoring-friendly"}
	have := map[string]*RuleTemplate{}
	for _, p := range AppPresets() {
		have[p.Name] = p
	}
	for _, n := range want {
		if have[n] == nil {
			t.Errorf("preset %q is missing", n)
		}
	}
	// presets are part of the built in list, read only, and names are unique across the whole list
	seen := map[string]bool{}
	for _, b := range BuiltinRuleTemplates() {
		k := strings.ToLower(b.Name)
		if seen[k] {
			t.Errorf("duplicate built in template name %q", b.Name)
		}
		seen[k] = true
		if !b.Builtin {
			t.Errorf("%q must be read only", b.Name)
		}
	}
	for n := range have {
		if !seen[strings.ToLower(n)] {
			t.Errorf("preset %q is not in BuiltinRuleTemplates", n)
		}
	}
}

func TestAppPresetsValidateAndApply(t *testing.T) {
	for _, p := range AppPresets() {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			if p.Category != "app" || !p.NoDowngrade || p.Note == "" || p.Description == "" {
				t.Fatalf("preset needs category app, NoDowngrade, a note and a description: %+v", p)
			}
			if !strings.HasPrefix(p.Note, "A starting point, review it") {
				t.Errorf("note must tell the user to review the preset")
			}
			if p.WAFSource != nil && *p.WAFSource == "off" {
				t.Errorf("a preset must never turn the WAF off")
			}
			if p.RateLimit != nil && *p.RateLimit == 0 {
				t.Errorf("a preset must never turn a rate limit off")
			}
			if p.BlockExploits != nil && !*p.BlockExploits {
				t.Errorf("a preset must never turn exploit blocking off")
			}

			// fresh rule: changes are reported, upstreams / domains / auth are untouched
			fresh := presetTestRule()
			before, _ := json.Marshal([]interface{}{fresh.RootOrMatchingDomain, fresh.MatchingDomainAlias, fresh.ActiveOrigins, fresh.AuthenticationProvider, fresh.AccessFilterUUID})
			ch, err := ApplyRuleTemplate(fresh, p)
			if err != nil {
				t.Fatal(err)
			}
			if len(ch) == 0 {
				t.Errorf("a preset must change something on a fresh rule")
			}
			after, _ := json.Marshal([]interface{}{fresh.RootOrMatchingDomain, fresh.MatchingDomainAlias, fresh.ActiveOrigins, fresh.AuthenticationProvider, fresh.AccessFilterUUID})
			if string(before) != string(after) {
				t.Errorf("domains, upstreams, authentication or access rule changed:\n%s\n%s", before, after)
			}
			// idempotent
			ch2, err := ApplyRuleTemplate(fresh, p)
			if err != nil || len(ch2) != 0 {
				t.Errorf("second apply must change nothing, got %v %v", ch2, err)
			}

			// rule with existing settings: nothing is weakened
			strong := presetTestRule()
			strong.WAFSource = "block"
			strong.RequireRateLimit, strong.RateLimit, strong.RateLimitBurst = true, 1, 2
			strong.BlockCommonExploits = true
			strong.HeaderRewriteRules.HSTSMaxAge = 63072000
			strong.HeaderRewriteRules.UserDefinedHeaders = append(strong.HeaderRewriteRules.UserDefinedHeaders,
				newTestHeader("X-Content-Type-Options", "custom"))
			strong.UptimeMonitorURI = "/mine"
			strong.Tags = []string{"keep"}
			if _, err := ApplyRuleTemplate(strong, p); err != nil {
				t.Fatal(err)
			}
			if strong.WAFSource != "block" || strong.WAFProfile != "" {
				t.Errorf("WAF source weakened to %q", strong.WAFSource)
			}
			if !strong.RequireRateLimit || strong.RateLimit != 1 || strong.RateLimitBurst != 2 {
				t.Errorf("rate limit weakened: %v %d %d", strong.RequireRateLimit, strong.RateLimit, strong.RateLimitBurst)
			}
			if !strong.BlockCommonExploits {
				t.Errorf("exploit blocking turned off")
			}
			if strong.HeaderRewriteRules.HSTSMaxAge != 63072000 {
				t.Errorf("HSTS lowered")
			}
			for _, h := range strong.HeaderRewriteRules.UserDefinedHeaders {
				if strings.EqualFold(h.Key, "X-Content-Type-Options") && h.Value != "custom" {
					t.Errorf("operator header overwritten")
				}
			}
			if strong.UptimeMonitorURI != "/mine" {
				t.Errorf("uptime URI overwritten")
			}
			if len(strong.Tags) == 0 || strong.Tags[0] != "keep" {
				t.Errorf("tags lost: %v", strong.Tags)
			}
			if len(strong.ActiveOrigins) != 1 || strong.ActiveOrigins[0].OriginIpOrDomain != "10.0.0.5:8080" {
				t.Errorf("upstreams changed")
			}

			// a rule with a custom WAF and a profile is never replaced
			custom := presetTestRule()
			custom.WAFSource = "profile"
			custom.WAFProfile = "mine"
			_, _ = ApplyRuleTemplate(custom, p)
			if custom.WAFSource != "profile" || custom.WAFProfile != "mine" {
				t.Errorf("profile replaced by %q/%q", custom.WAFSource, custom.WAFProfile)
			}
		})
	}
}

func TestNoDowngradeRaisesWAF(t *testing.T) {
	var admin *RuleTemplate
	for _, p := range AppPresets() {
		if p.Name == "Strict admin panel" {
			admin = p
		}
	}
	ep := presetTestRule()
	ep.WAFSource = "detection_only"
	if _, err := ApplyRuleTemplate(ep, admin); err != nil {
		t.Fatal(err)
	}
	if ep.WAFSource != "block" {
		t.Errorf("detection only should be raised to block, got %q", ep.WAFSource)
	}
	if !admin.RequiresAuth {
		t.Errorf("the admin preset must ask for authentication")
	}
}

// The descriptions and notes are served by the API, so the i18n extractor cannot see them in the HTML or JS:
// they must be listed in tools/i18n/extra_keys.txt to be translatable.
func TestAppPresetTextsAreInI18nExtraKeys(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tools", "i18n", "extra_keys.txt"))
	if err != nil {
		t.Skip("tools/i18n/extra_keys.txt not available")
	}
	have := map[string]bool{}
	for _, l := range strings.Split(string(raw), "\n") {
		have[strings.TrimSpace(l)] = true
	}
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, p := range AppPresets() {
		for _, s := range []string{p.Description, p.Note} {
			if !have[norm(s)] {
				t.Errorf("preset %q: %q is not in tools/i18n/extra_keys.txt", p.Name, norm(s))
			}
		}
	}
}

func TestNoDowngradeKeepsInheritedBlock(t *testing.T) {
	var p *RuleTemplate
	for _, c := range AppPresets() {
		if c.WAFSource != nil && *c.WAFSource == "detection_only" {
			p = c
			break
		}
	}
	if p == nil {
		t.Skip("no detection_only preset")
	}
	for _, src := range []string{"", "inherit"} {
		ep := presetTestRule()
		ep.WAFSource = src
		if _, err := ApplyRuleTemplateIn(ep, p, "block"); err != nil {
			t.Fatal(err)
		}
		if ep.WAFSource != src {
			t.Errorf("source %q under an inherited block was replaced by %q", src, ep.WAFSource)
		}
		ep = presetTestRule()
		ep.WAFSource = src
		if _, err := ApplyRuleTemplateIn(ep, p, "detection_only"); err != nil {
			t.Fatal(err)
		}
		if ep.WAFSource != "detection_only" {
			t.Errorf("source %q under inherited detection should become detection_only, got %q", src, ep.WAFSource)
		}
	}
}
