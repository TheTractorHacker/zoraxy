package posture

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

/*
	Built-in checks. Every check inspects the Facts snapshot only, and states in its evidence what it looked at.
	A missing section of the snapshot means "unknown", never "ok". Adding a check: see DEVELOPMENT.md.
*/

func init() {
	for _, c := range builtinChecks() {
		Default.MustRegister(c)
	}
}

func hostRulesOrNA(f *Facts, what string) ([]RuleFacts, *Result) {
	if f.Proxy == nil {
		r := unknown("the proxy rules could not be read")
		return nil, &r
	}
	rules := f.Proxy.HostRules()
	if len(rules) == 0 {
		r := na("there are no enabled proxy rules, so " + what + " does not apply yet")
		return nil, &r
	}
	return rules, nil
}

func builtinChecks() []Check {
	return []Check{
		/* ---------------- Exposure ---------------- */
		{
			ID: "admin.auth", Title: "Admin interface requires a login", Category: CatExposure, Weight: 10, Critical: true,
			Why:         "Without a login anyone who can reach the admin port can change every setting, read private keys and take over the proxy.",
			Remediation: Remediation{Label: "Restart without -noauth", Hint: "Remove the -noauth start flag and create an admin account."},
			Run: func(f *Facts) Result {
				if f.Admin == nil {
					return unknown("the admin interface settings could not be read")
				}
				if !f.Admin.AuthRequired {
					return Result{Status: StatusFail, Evidence: []string{"Zoraxy was started with -noauth: the admin interface does not ask for a login"}}
				}
				return Result{Status: StatusOK, Evidence: []string{"the admin interface asks for a login"}}
			},
		},
		{
			ID: "admin.tls", Title: "Admin interface is served over HTTPS", Category: CatExposure, Weight: 6,
			Why:         "Over plain HTTP the admin password and session cookie cross the network readable by anyone on the path.",
			Remediation: Remediation{Label: "Start with -webui_tls=auto", Hint: "Start Zoraxy with -webui_tls=auto (self-signed) or -webui_tls=custom and your own certificate."},
			Run: func(f *Facts) Result {
				a := f.Admin
				if a == nil {
					return unknown("the admin interface settings could not be read")
				}
				switch {
				case a.TLSMode == "auto" || a.TLSMode == "custom":
					return Result{Status: StatusOK, Evidence: []string{"-webui_tls=" + a.TLSMode + ": the admin interface is served over HTTPS"}}
				case a.Loopback:
					return Result{Status: StatusOK, Evidence: []string{"plain HTTP, but the admin interface listens on " + a.ListenAddr + " (this machine only)"}}
				}
				return Result{Status: StatusFail, Evidence: []string{"-webui_tls is off and the admin interface listens on " + a.ListenAddr + ": logins are sent in clear text to anyone who can reach it"}}
			},
		},
		{
			ID: "admin.bind", Title: "Admin port is not open on every interface", Category: CatExposure, Weight: 4,
			Why:         "An admin port on all interfaces is reachable from every network the machine is on, including the internet if the firewall allows it.",
			Remediation: Remediation{Label: "Bind the admin port to one address", Hint: "Start Zoraxy with -port=127.0.0.1:8000 (or a LAN address) and reach it through a VPN or an SSH tunnel; or restrict the port in the firewall."},
			Run: func(f *Facts) Result {
				a := f.Admin
				if a == nil {
					return unknown("the admin interface settings could not be read")
				}
				switch {
				case a.AllInterfaces:
					return Result{Status: StatusWarn, Evidence: []string{"-port=" + a.ListenAddr + " listens on all interfaces"}}
				case a.Loopback:
					return Result{Status: StatusOK, Evidence: []string{"-port=" + a.ListenAddr + " listens on loopback only"}}
				}
				return Result{Status: StatusOK, Evidence: []string{"-port=" + a.ListenAddr + " listens on one specific address"}}
			},
		},
		{
			ID: "exposure.default_site", Title: "Unknown host names do not reach an application", Category: CatExposure, Weight: 3,
			Why:         "The default site answers requests for host names you did not configure (scanners use the bare IP address). If it forwards them to an application, that application is exposed to every scan.",
			Remediation: Remediation{Label: "Open Default Site", Page: "setroot"},
			Run: func(f *Facts) Result {
				if f.Proxy == nil {
					return unknown("the default site could not be read")
				}
				if f.Proxy.DefaultSiteProxies {
					return Result{Status: StatusWarn, Evidence: []string{"the default site is set to: " + f.Proxy.DefaultSite + " (requests for unknown host names are forwarded to it)"}}
				}
				return Result{Status: StatusOK, Evidence: []string{"the default site is set to: " + f.Proxy.DefaultSite}}
			},
		},
		{
			ID: "exposure.dev_mode", Title: "Development mode is off", Category: CatExposure, Weight: 2,
			Why:         "Development mode adds debugging details and disables caching; it is meant for testing, not for a public proxy.",
			Remediation: Remediation{Label: "Open Ingress settings", Page: "globalsettings"},
			Run: func(f *Facts) Result {
				if f.Proxy == nil {
					return unknown("the proxy settings could not be read")
				}
				if f.Proxy.DevelopmentMode {
					return Result{Status: StatusWarn, Evidence: []string{"development mode is switched on"}}
				}
				return Result{Status: StatusOK, Evidence: []string{"development mode is off"}}
			},
		},
		{
			ID: "exposure.forward_proxy", Title: "HTTP forward proxy is off", Category: CatExposure, Weight: 4,
			Why:         "A forward proxy lets clients browse through this server. If it is reachable from the internet it can be abused as an open proxy.",
			Remediation: Remediation{Label: "Open Network Tools", Page: "networktool"},
			Run: func(f *Facts) Result {
				if f.Tools == nil {
					return unknown("the forward proxy state could not be read")
				}
				if f.Tools.ForwardProxy {
					return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("the HTTP forward proxy is enabled on port %d", f.Tools.ForwardPort)}}
				}
				return Result{Status: StatusOK, Evidence: []string{"the HTTP forward proxy is disabled"}}
			},
		},
		{
			ID: "exposure.webssh_loopback", Title: "Web terminal to this machine is not allowed", Category: CatExposure, Weight: 5,
			Why:         "-sshlb lets the web terminal open a shell on the server that runs Zoraxy. Anyone who gets into the admin interface then gets a shell.",
			Remediation: Remediation{Label: "Restart without -sshlb", Hint: "Remove the -sshlb start flag."},
			Run: func(f *Facts) Result {
				if f.Tools == nil {
					return unknown("the start flags could not be read")
				}
				if f.Tools.WebSSHLoop {
					return Result{Status: StatusFail, Evidence: []string{"the -sshlb start flag allows web terminal connections to this machine"}}
				}
				return Result{Status: StatusOK, Evidence: []string{"-sshlb is not set"}}
			},
		},

		/* ---------------- Web attacks ---------------- */
		{
			ID: "waf.active", Title: "WAF inspects requests", Category: CatWeb, Weight: 10,
			Why:         "The WAF blocks or reports SQL injection, cross-site scripting and path traversal before they reach your applications. Detection-only already counts here: it records attacks without risking real traffic.",
			Remediation: Remediation{Label: "Open the WAF page", Page: "waf", Action: "waf.baseline"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "the WAF")
				if early != nil {
					return *early
				}
				var off, det, blk []string
				for _, r := range rules {
					switch r.WAFMode {
					case "off":
						off = append(off, r.Name)
					case "detection_only":
						det = append(det, r.Name)
					case "block":
						blk = append(blk, r.Name)
					default:
						return unknown("the WAF mode of " + r.Name + " could not be determined")
					}
				}
				res := ratio("WAF mode is off", off, len(rules), true, fmt.Sprintf("the WAF is active on all %d proxy %s (%d blocking, %d detection-only)", len(rules), plural(len(rules), "rule", "rules"), len(blk), len(det)))
				if f.WAF != nil && len(off) > 0 {
					res.Evidence = append(res.Evidence, fmt.Sprintf("central policy: enabled=%v, default mode %s", f.WAF.PolicyEnabled, f.WAF.DefaultMode))
				}
				return res
			},
		},
		{
			ID: "waf.blocking", Title: "WAF blocks attacks (not only logs them)", Category: CatWeb, Weight: 4,
			Why:         "In detection-only mode the WAF writes attacks to the log but lets them through. It is the right way to start; switch to block once the events show no false positives.",
			Remediation: Remediation{Label: "Open WAF coverage", Page: "waf", Anchor: "waf-coverage"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "WAF blocking")
				if early != nil {
					return *early
				}
				var det []string
				active := 0
				for _, r := range rules {
					switch r.WAFMode {
					case "detection_only":
						det = append(det, r.Name)
						active++
					case "block":
						active++
					case "off":
					default:
						return unknown("the WAF mode of " + r.Name + " could not be determined")
					}
				}
				if active == 0 {
					return na("the WAF is off for every proxy rule (see the previous check)")
				}
				if len(det) == 0 {
					return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("all %d protected proxy %s block attacks", active, plural(active, "rule", "rules"))}}
				}
				return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("detection-only (logs, does not block) for %d of %d protected proxy %s: %s", len(det), active, plural(active, "rule", "rules"), listNames(det, 8))}}
			},
		},
		{
			ID: "waf.analytics_cookies", Title: "WAF skips analytics cookie values", Category: CatWeb, Weight: 1,
			Why:         "Analytics cookies (Google Analytics, PostHog) contain long encoded values that often trigger false positives, which tempts people to switch the WAF off.",
			Remediation: Remediation{Label: "Open the WAF policy", Page: "waf", Anchor: "waf-policy", Action: "waf.cookies"},
			Run: func(f *Facts) Result {
				if f.WAF == nil || f.Proxy == nil {
					return unknown("the WAF policy could not be read")
				}
				active := 0
				for _, r := range f.Proxy.HostRules() {
					if r.WAFMode == "detection_only" || r.WAFMode == "block" {
						active++
					}
				}
				if active == 0 {
					return na("the WAF is not active on any proxy rule")
				}
				if f.WAF.IgnoreAnalyticsCookies {
					return Result{Status: StatusOK, Evidence: []string{"the central policy ignores analytics cookie values"}}
				}
				return Result{Status: StatusWarn, Evidence: []string{"the central policy inspects analytics cookie values; active on " + fmt.Sprint(active) + " proxy " + plural(active, "rule", "rules")}}
			},
		},
		{
			ID: "web.exploit_filter", Title: "Common exploit filter or WAF blocking on every rule", Category: CatWeb, Weight: 3,
			Why:         "The built-in exploit filter is a lightweight screen for well-known attack strings. It is useful where the WAF is not blocking.",
			Remediation: Remediation{Label: "Open HTTP Proxy", Page: "httprp"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "the exploit filter")
				if early != nil {
					return *early
				}
				var bad []string
				for _, r := range rules {
					if !r.BlockExploits && r.WAFMode != "block" {
						bad = append(bad, r.Name)
					}
				}
				return ratio("neither the exploit filter nor WAF blocking is on", bad, len(rules), false, "every proxy rule has the exploit filter or WAF blocking")
			},
		},
		{
			ID: "waf.challenge_ready", Title: "WAF challenge band has a CAPTCHA to show", Category: CatWeb, Weight: 2,
			Why:         "When the WAF challenge band is on but no CAPTCHA provider is configured on the proxy rule, suspicious visitors are blocked instead of challenged.",
			Remediation: Remediation{Label: "Open CAPTCHA", Page: "captcha"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "the challenge band")
				if early != nil {
					return *early
				}
				used, bad := 0, []string{}
				for _, r := range rules {
					if r.ChallengeBand {
						used++
						if !r.ChallengeReady {
							bad = append(bad, r.Name)
						}
					}
				}
				if used == 0 {
					return na("no proxy rule uses the WAF challenge band")
				}
				return ratio("the challenge band has no CAPTCHA provider", bad, used, false, fmt.Sprintf("%d %s with a challenge band can show a CAPTCHA", used, plural(used, "rule", "rules")))
			},
		},
		{
			ID: "captcha.keys", Title: "CAPTCHA rules have working provider keys", Category: CatWeb, Weight: 3,
			Why:         "A proxy rule that requires a CAPTCHA but has no site key or secret cannot verify anyone. Visitors are locked out or the gate is not enforced.",
			Remediation: Remediation{Label: "Open CAPTCHA", Page: "captcha"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "CAPTCHA")
				if early != nil {
					return *early
				}
				used, bad := 0, []string{}
				for _, r := range rules {
					if r.RequireCaptcha {
						used++
						if !r.CaptchaKeysOK {
							bad = append(bad, r.Name)
						}
					}
				}
				if used == 0 {
					return na("no proxy rule requires a CAPTCHA")
				}
				res := ratio("the CAPTCHA provider keys are missing", bad, used, true, fmt.Sprintf("%d %s with a CAPTCHA have provider keys", used, plural(used, "rule", "rules")))
				return res
			},
		},
		{
			ID: "bots.rules", Title: "Bot rules are on", Category: CatWeb, Weight: 3,
			Why:         "Bot rules turn away known scrapers, AI crawlers and vulnerability scanners by their User-Agent, which removes a lot of noise and probing.",
			Remediation: Remediation{Label: "Open Security Center", Page: "seccenter", Anchor: "bots"},
			Run: func(f *Facts) Result {
				if f.Bots == nil {
					return unknown("the bot rules could not be read")
				}
				if f.Bots.Enabled {
					return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("bot rules are on globally with %d categories enabled", f.Bots.EnabledCategories)}}
				}
				if f.Proxy != nil {
					on := 0
					for _, r := range f.Proxy.HostRules() {
						if r.BotPolicy == "on" {
							on++
						}
					}
					if on > 0 {
						return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("bot rules are off globally but switched on for %d proxy %s", on, plural(on, "rule", "rules"))}}
					}
				}
				return Result{Status: StatusWarn, Evidence: []string{"bot rules are off globally and no proxy rule turns them on"}}
			},
		},

		/* ---------------- Abuse ---------------- */
		{
			ID: "abuse.autoban", Title: "Auto-ban stops repeat offenders", Category: CatAbuse, Weight: 5,
			Why:         "Auto-ban blocks an address for a while after it keeps triggering WAF blocks, failed logins or scanner patterns, so attackers cannot simply retry.",
			Remediation: Remediation{Label: "Open Security Center", Page: "seccenter", Anchor: "abuse", Action: "autoban.enable"},
			Run: func(f *Facts) Result {
				if f.Abuse == nil {
					return unknown("the auto-ban configuration could not be read")
				}
				if !f.Abuse.Enabled {
					return Result{Status: StatusWarn, Evidence: []string{"auto-ban is switched off"}}
				}
				if len(f.Abuse.EnabledDetectors) == 0 {
					return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("auto-ban is on but none of its %d detectors is enabled", f.Abuse.TotalDetectors)}}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("auto-ban is on with %d of %d detectors: %s", len(f.Abuse.EnabledDetectors), f.Abuse.TotalDetectors, strings.Join(f.Abuse.EnabledDetectors, ", "))}}
			},
		},
		{
			ID: "abuse.ratelimit", Title: "Proxy rules have a rate limit", Category: CatAbuse, Weight: 5,
			Why:         "A rate limit keeps one client from flooding a site or trying passwords at machine speed. It is not switched on automatically because the right number depends on the application.",
			Remediation: Remediation{Label: "Open HTTP Proxy", Page: "httprp"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "rate limiting")
				if early != nil {
					return *early
				}
				var bad []string
				for _, r := range rules {
					if !r.RateLimit {
						bad = append(bad, r.Name)
					}
				}
				return ratio("rate limiting is off", bad, len(rules), true, fmt.Sprintf("all %d proxy %s have a rate limit", len(rules), plural(len(rules), "rule", "rules")))
			},
		},
		{
			// Informational only: it never changes the score and offers no fix. Rate limit numbers depend on the app.
			ID: "abuse.ratelimit_login_paths", Title: "Login and admin paths have a rate limit", Category: CatAbuse, Weight: 1, Heuristic: true,
			Why:         "Password guessing happens on login and admin pages. A per IP rate limit slows it down, but it is not account protection: the application still needs lockout or multi-factor sign-in, and admin interfaces are better behind a VPN or an IP restriction. Zoraxy cannot see which paths your applications use, so this is a hint, not a verdict.",
			Remediation: Remediation{Label: "Open HTTP Proxy", Page: "httprp", Hint: "Pick the Login page, Admin dashboard or Odoo ERP preset for a site (Apply preset), or add a rate limit path rule for the login path. Nothing is changed automatically."},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "rate limiting of login paths")
				if early != nil {
					return *early
				}
				var bare, siteOnly []string
				for _, r := range rules {
					pathLimited := false
					for _, p := range r.PathRateLimits {
						if LooksLikeLoginPath(p) {
							pathLimited = true
						}
					}
					switch {
					case pathLimited:
					case r.RateLimit:
						siteOnly = append(siteOnly, r.Name)
					default:
						bare = append(bare, r.Name)
					}
				}
				if len(bare) == 0 {
					ev := fmt.Sprintf("all %d proxy %s have a rate limit that covers login and admin paths", len(rules), plural(len(rules), "rule", "rules"))
					if len(siteOnly) > 0 {
						ev += fmt.Sprintf("; %d only through the site wide limit (a stricter limit on the login path is common): %s", len(siteOnly), listNames(siteOnly, 6))
					}
					return Result{Status: StatusOK, Evidence: []string{ev}}
				}
				ev := []string{fmt.Sprintf("no rate limit at all for %d of %d proxy %s: %s", len(bare), len(rules), plural(len(rules), "rule", "rules"), listNames(bare, 8))}
				if len(siteOnly) > 0 {
					ev = append(ev, fmt.Sprintf("%d more have only a site wide limit: %s", len(siteOnly), listNames(siteOnly, 6)))
				}
				return Result{Status: StatusInfo, Evidence: ev}
			},
		},
		{
			ID: "access.trusted_proxy_gating", Title: "Client address headers are only trusted from known proxies", Category: CatAbuse, Weight: 3,
			Why:         "Behind a CDN, the real visitor address comes in a header. If Zoraxy trusts that header from anyone, an attacker can forge it to dodge blocklists and rate limits.",
			Remediation: Remediation{Label: "Open Access Rules", Page: "access"},
			Run: func(f *Facts) Result {
				if f.Access == nil || f.Visitors == nil {
					return unknown("the access rule or visitor data could not be read")
				}
				if f.Visitors.Total == 0 {
					return unknown("no visitors have been recorded yet, so a CDN in front of the proxy cannot be detected")
				}
				cdn := f.Visitors.Via["cloudflare"] + f.Visitors.Via["proxy"]
				if cdn == 0 {
					return na(fmt.Sprintf("none of the %d recorded visitors arrived through a CDN or proxy", f.Visitors.Total))
				}
				if f.Access.TrustProxyHeadersOnly {
					return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("%d of %d visitors arrive through a CDN or proxy; the default access rule trusts client address headers only from the %d trusted proxies", cdn, f.Visitors.Total, f.Access.TrustedProxies)}}
				}
				return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("%d of %d visitors arrive through a CDN or proxy, but the default access rule does not restrict client address headers to trusted proxies", cdn, f.Visitors.Total)}}
			},
		},
		{
			ID: "access.sanitise_client_ip", Title: "Forged client address headers are dropped", Category: CatAbuse, Weight: 2,
			Why:         "Without sanitising, a visitor can send their own X-Forwarded-For header and applications that trust it (IP allow lists, audit logs) see a false address.",
			Remediation: Remediation{Label: "Open Ingress settings", Page: "globalsettings"},
			Run: func(f *Facts) Result {
				if f.Proxy == nil || f.Visitors == nil {
					return unknown("the proxy settings or visitor data could not be read")
				}
				rules := f.Proxy.HostRules()
				if len(rules) == 0 {
					return na("there are no enabled proxy rules")
				}
				if f.Visitors.Via["cloudflare"]+f.Visitors.Via["proxy"] > 0 {
					return na("visitors arrive through a CDN or proxy; sanitising needs the trusted proxy list set up first")
				}
				if f.Proxy.SanitiseClientIP {
					return Result{Status: StatusOK, Evidence: []string{"the global default drops client supplied X-Forwarded-For / X-Real-IP headers"}}
				}
				return Result{Status: StatusWarn, Evidence: []string{"the global default 'sanitise client IP headers' is off and no CDN was seen in front of the proxy"}}
			},
		},

		/* ---------------- Authentication ---------------- */
		{
			ID: "auth.admin_ui_exposed", Title: "Admin-looking sites are not open to everyone", Category: CatAuth, Weight: 6, Heuristic: true,
			Why:         "Dashboards and admin consoles (Grafana, Portainer, phpMyAdmin ...) are prime targets. This is a guess from the host name: it does not look inside the application.",
			Remediation: Remediation{Label: "Open HTTP Proxy", Page: "httprp"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "this check")
				if early != nil {
					return *early
				}
				var bad []string
				looked := 0
				for _, r := range rules {
					w, ok := LooksLikeAdminUI(r.Name)
					if !ok {
						continue
					}
					looked++
					if r.AuthMethod == "none" && !r.AccessLimited {
						bad = append(bad, r.Name+" (\""+w+"\")")
					}
				}
				if looked == 0 {
					return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("none of the %d host names looks like an admin interface (guess by name)", len(rules))}}
				}
				if len(bad) == 0 {
					return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("%d host %s look like admin interfaces and all have a login or an IP allow list (guess by name)", looked, plural(looked, "name", "names"))}}
				}
				return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("%d of %d admin-looking hosts have no login and no IP allow list: %s (guess by name)", len(bad), looked, listNames(bad, 8))}}
			},
		},
		{
			ID: "auth.stale_tokens", Title: "No stale API tokens", Category: CatAuth, Weight: 2,
			Why:         "An API token that is never used (or not for months) is access nobody is watching. Revoke what you do not need.",
			Remediation: Remediation{Label: "Open API Tokens", Page: "apitokens"},
			Run: func(f *Facts) Result {
				if f.Tokens == nil {
					return unknown("the API tokens could not be read")
				}
				var live, stale []string
				for _, t := range f.Tokens.Tokens {
					if t.Revoked || t.Expired {
						continue
					}
					live = append(live, t.Name)
					switch {
					case t.LastUsed.IsZero() && f.Now.Sub(t.Created) > 30*24*time.Hour:
						stale = append(stale, fmt.Sprintf("%s (never used, %d days old)", t.Name, int(f.Now.Sub(t.Created).Hours()/24)))
					case !t.LastUsed.IsZero() && f.Now.Sub(t.LastUsed) > 90*24*time.Hour:
						stale = append(stale, fmt.Sprintf("%s (last used %d days ago)", t.Name, int(f.Now.Sub(t.LastUsed).Hours()/24)))
					}
				}
				if len(live) == 0 {
					return na("there are no active API tokens")
				}
				if len(stale) == 0 {
					return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("%d active API %s, all used within 90 days or newer than 30 days", len(live), plural(len(live), "token", "tokens"))}}
				}
				return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("%d of %d active tokens look unused: %s", len(stale), len(live), listNames(stale, 6))}}
			},
		},
		{
			ID: "auth.sso_transport", Title: "SSO providers are reached over HTTPS", Category: CatAuth, Weight: 4,
			Why:         "Sign-in tokens and codes sent to an identity provider over plain HTTP can be read or changed by anyone on the path.",
			Remediation: Remediation{Label: "Open SSO / OAuth2", Page: "sso"},
			Run: func(f *Facts) Result {
				if f.SSO == nil {
					return unknown("the SSO settings could not be read")
				}
				if len(f.SSO.URLs) == 0 {
					return na("no OAuth2 provider or forward-auth URL is configured")
				}
				var fail, warn []string
				for _, u := range f.SSO.URLs {
					plain, where := urlTransport(u.URL)
					if !plain {
						continue
					}
					line := fmt.Sprintf("%s %s uses plain http (%s)", u.Owner, u.Kind, where)
					switch where {
					case "public":
						fail = append(fail, line)
					case "hostname":
						warn = append(warn, line)
					}
				}
				switch {
				case len(fail) > 0:
					return Result{Status: StatusFail, Evidence: append(fail, warn...)}
				case len(warn) > 0:
					return Result{Status: StatusWarn, Evidence: warn}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("%d SSO %s checked: none uses plain http to a public or unknown address", len(f.SSO.URLs), plural(len(f.SSO.URLs), "URL", "URLs"))}}
			},
		},

		/* ---------------- Certificates & TLS ---------------- */
		{
			ID: "tls.enabled", Title: "Proxy serves HTTPS", Category: CatCerts, Weight: 7,
			Why:         "Without TLS every request, cookie and password to your sites travels in clear text.",
			Remediation: Remediation{Label: "Open Ingress settings", Page: "globalsettings"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "HTTPS")
				if early != nil {
					return *early
				}
				if f.Proxy.UseTLS {
					return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("TLS is enabled on port %d for %d proxy %s", f.Proxy.Port, len(rules), plural(len(rules), "rule", "rules"))}}
				}
				return Result{Status: StatusFail, Evidence: []string{fmt.Sprintf("TLS is disabled: %d proxy %s answer on plain HTTP only", len(rules), plural(len(rules), "rule", "rules"))}}
			},
		},
		{
			ID: "tls.https_redirect", Title: "Plain HTTP is redirected to HTTPS", Category: CatCerts, Weight: 4,
			Why:         "Visitors who type http:// should land on the encrypted site instead of an unencrypted page.",
			Remediation: Remediation{Label: "Open Ingress settings", Page: "globalsettings", Action: "https.redirect"},
			Run: func(f *Facts) Result {
				if _, early := hostRulesOrNA(f, "the redirect"); early != nil {
					return *early
				}
				p := f.Proxy
				switch {
				case !p.UseTLS:
					return na("the proxy does not serve TLS")
				case !p.ListenOnPort80:
					return Result{Status: StatusOK, Evidence: []string{"no plain HTTP listener is running"}}
				case p.ForceHTTPSRedirect:
					return Result{Status: StatusOK, Evidence: []string{"the plain HTTP listener redirects to HTTPS"}}
				}
				return Result{Status: StatusWarn, Evidence: []string{"the plain HTTP listener is running and does not redirect to HTTPS"}}
			},
		},
		{
			ID: "tls.hsts", Title: "HSTS is on", Category: CatCerts, Weight: 3,
			Why:         "HSTS tells browsers to use HTTPS only for your site, which blocks downgrade attacks. Browsers remember it, so it is only offered for sites that already have a valid certificate.",
			Remediation: Remediation{Label: "Open HTTP Proxy", Page: "httprp", Action: "hsts.enable"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "HSTS")
				if early != nil {
					return *early
				}
				if !f.Proxy.UseTLS {
					return na("the proxy does not serve TLS")
				}
				var bad []string
				for _, r := range rules {
					if r.HSTSMaxAge <= 0 {
						bad = append(bad, r.Name)
					}
				}
				return ratio("HSTS is off", bad, len(rules), true, fmt.Sprintf("HSTS is on for all %d proxy %s", len(rules), plural(len(rules), "rule", "rules")))
			},
		},
		{
			ID: "cert.expiry", Title: "Certificates are not about to expire", Category: CatCerts, Weight: 7,
			Why:         "An expired certificate makes browsers refuse your site. Renewals fail silently more often than people expect.",
			Remediation: Remediation{Label: "Open Certificates", Page: "cert"},
			Run: func(f *Facts) Result {
				if f.Proxy == nil || f.Certs == nil {
					return unknown("the certificates could not be read")
				}
				if !f.Proxy.UseTLS {
					return na("the proxy does not serve TLS")
				}
				var fail, warn []string
				checked := 0
				for _, h := range f.Certs.Hosts {
					switch h.State {
					case "ok", "selfsigned", "expired":
					default:
						continue // no usable certificate: reported by the coverage check
					}
					checked++
					switch {
					case h.State == "expired" || h.DaysLeft < 0:
						fail = append(fail, h.Host+" (expired)")
					case h.DaysLeft < 14:
						fail = append(fail, fmt.Sprintf("%s (%d days left)", h.Host, h.DaysLeft))
					case h.DaysLeft < 30:
						warn = append(warn, fmt.Sprintf("%s (%d days left)", h.Host, h.DaysLeft))
					}
				}
				if checked == 0 {
					return na("no proxy rule has a certificate to check")
				}
				switch {
				case len(fail) > 0:
					return Result{Status: StatusFail, Evidence: []string{"expired or expiring within 14 days: " + listNames(fail, 8)}}
				case len(warn) > 0:
					return Result{Status: StatusWarn, Evidence: []string{"expiring within 30 days: " + listNames(warn, 8)}}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("%d served %s valid for at least 30 more days", checked, plural(checked, "certificate is", "certificates are"))}}
			},
		},
		{
			ID: "cert.coverage", Title: "Every site has a matching certificate", Category: CatCerts, Weight: 6,
			Why:         "A site without a matching certificate shows a browser warning (Zoraxy would present its built-in self-signed certificate), and a self-signed one is not trusted by visitors.",
			Remediation: Remediation{Label: "Open Certificates", Page: "cert"},
			Run: func(f *Facts) Result {
				if f.Proxy == nil || f.Certs == nil {
					return unknown("the certificates could not be read")
				}
				if !f.Proxy.UseTLS {
					return na("the proxy does not serve TLS")
				}
				if len(f.Certs.Hosts) == 0 && f.Certs.Skipped == 0 {
					return na("no proxy rule has a host name to check")
				}
				var fail, warn []string
				for _, h := range f.Certs.Hosts {
					switch h.State {
					case "missing", "fallback", "mismatch":
						fail = append(fail, h.Host+" ("+h.State+")")
					case "selfsigned":
						warn = append(warn, h.Host+" (self-signed)")
					}
				}
				note := ""
				if f.Certs.Skipped > 0 {
					note = fmt.Sprintf(" (%d wildcard or IP host names were not checked)", f.Certs.Skipped)
				}
				switch {
				case len(fail) > 0:
					return Result{Status: StatusFail, Evidence: []string{fmt.Sprintf("%d of %d host names have no matching certificate: %s%s", len(fail), len(f.Certs.Hosts), listNames(fail, 8), note)}}
				case len(warn) > 0:
					return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("%d of %d host names use a self-signed certificate: %s%s", len(warn), len(f.Certs.Hosts), listNames(warn, 8), note)}}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("all %d checked host %s have a valid, trusted certificate%s", len(f.Certs.Hosts), plural(len(f.Certs.Hosts), "name", "names"), note)}}
			},
		},
		{
			ID: "tls.min_version", Title: "Old TLS versions are refused", Category: CatCerts, Weight: 3,
			Why:         "TLS 1.0 and 1.1 are obsolete and have known weaknesses; every current browser speaks TLS 1.2 or newer.",
			Remediation: Remediation{Label: "Open Ingress settings", Page: "globalsettings"},
			Run: func(f *Facts) Result {
				if f.Proxy == nil {
					return unknown("the TLS settings could not be read")
				}
				if !f.Proxy.UseTLS {
					return na("the proxy does not serve TLS")
				}
				switch f.Proxy.MinTLSVersion {
				case "1.0", "1.1":
					return Result{Status: StatusWarn, Evidence: []string{"the minimum TLS version is " + f.Proxy.MinTLSVersion}}
				case "":
					return Result{Status: StatusOK, Evidence: []string{"no minimum set: the Go default (TLS 1.2) applies"}}
				}
				return Result{Status: StatusOK, Evidence: []string{"the minimum TLS version is " + f.Proxy.MinTLSVersion}}
			},
		},
		{
			ID: "ech.config", Title: "Encrypted Client Hello is set up correctly", Category: CatCerts, Weight: 2,
			Why:         "When ECH is on, clients that fail to use it fall back to the public name, which needs a valid certificate; otherwise Chrome shows ERR_ECH_FALLBACK_CERTIFICATE_INVALID.",
			Remediation: Remediation{Label: "Open Encrypted Client Hello", Page: "ech"},
			Run: func(f *Facts) Result {
				if f.ECH == nil {
					return unknown("the ECH settings could not be read")
				}
				if !f.ECH.Enabled {
					return na("Encrypted Client Hello is off")
				}
				if f.ECH.CertState == "ok" {
					return Result{Status: StatusOK, Evidence: []string{"ECH is on and the public name " + f.ECH.PublicName + " has a valid certificate"}}
				}
				ev := []string{"ECH is on but the certificate for the public name " + f.ECH.PublicName + " is " + f.ECH.CertState}
				if f.ECH.CertReason != "" {
					ev = append(ev, f.ECH.CertReason)
				}
				return Result{Status: StatusFail, Evidence: ev}
			},
		},

		/* ---------------- Operations ---------------- */
		{
			ID: "ops.updates", Title: "Zoraxy is up to date", Category: CatOps, Weight: 4,
			Why:         "Updates carry security fixes. Zoraxy does not check for updates on its own, so the Update page has to be opened now and then.",
			Remediation: Remediation{Label: "Open Update", Page: "updater"},
			Run: func(f *Facts) Result {
				u := f.Updater
				if u == nil {
					return unknown("the updater state could not be read")
				}
				if u.Offline {
					return na("offline mode is on, no update checks are made")
				}
				if !u.Checked {
					return unknown("Zoraxy has not checked for updates yet (it never does so on its own)")
				}
				age := int(f.Now.Sub(u.CheckedAt).Hours() / 24)
				if u.UpdateAvailable {
					return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("version %s is available (running %s, channel %s), last checked %d days ago", u.Latest, u.Current, u.Channel, age)}}
				}
				if age > 30 {
					return unknown(fmt.Sprintf("the last update check was %d days ago; open the Update page to check again", age))
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("running %s, no newer release on channel %s (checked %d days ago)", u.Current, u.Channel, age)}}
			},
		},
		{
			ID: "ops.backup", Title: "A recent backup exists", Category: CatOps, Weight: 3,
			Why:         "If the configuration is lost or a change goes wrong, a backup is the way back. Zoraxy only sees the backups it makes itself before an update; backups made elsewhere (VM snapshot, exported zip) are invisible to it.",
			Remediation: Remediation{Label: "Open Utilities", Page: "utils"},
			Run: func(f *Facts) Result {
				b := f.Backup
				if b == nil {
					return unknown("the backup folder could not be read")
				}
				if b.Count == 0 {
					return unknown("Zoraxy has made no backup that it can see (backups made outside Zoraxy are not visible to it)")
				}
				age := int(f.Now.Sub(b.Latest).Hours() / 24)
				if age > 30 {
					return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("the newest of %d pre-update backups is %d days old", b.Count, age)}}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("the newest of %d pre-update backups is %d days old", b.Count, age)}}
			},
		},
		{
			ID: "ops.notifications", Title: "You get told when something goes wrong", Category: CatOps, Weight: 3,
			Why:         "Without a notification channel nobody learns about an expiring certificate, a downed upstream or an attack until a user complains.",
			Remediation: Remediation{Label: "Open notification settings", Href: "snippet/notifications.html"},
			Run: func(f *Facts) Result {
				n := f.Notify
				if n == nil {
					return unknown("the notification settings could not be read")
				}
				total := n.Channels + n.Webhooks
				if n.Command {
					total++
				}
				if total == 0 {
					return Result{Status: StatusWarn, Evidence: []string{"no notification channel, webhook or command hook is enabled"}}
				}
				return Result{Status: StatusOK, Evidence: []string{fmt.Sprintf("%d channels, %d webhooks, command hook %v", n.Channels, n.Webhooks, n.Command)}}
			},
		},
		{
			ID: "ops.uptime", Title: "Uptime monitor covers every site", Category: CatOps, Weight: 3,
			Why:         "The uptime monitor notices a broken upstream within minutes and feeds the notifications. A site it does not watch can be down unnoticed.",
			Remediation: Remediation{Label: "Open Uptime Monitor", Page: "utm", Action: "uptime.enable"},
			Run: func(f *Facts) Result {
				rules, early := hostRulesOrNA(f, "the uptime monitor")
				if early != nil {
					return *early
				}
				var bad []string
				for _, r := range rules {
					if !r.UptimeMonitor {
						bad = append(bad, r.Name)
					}
				}
				return ratio("the uptime monitor is off", bad, len(rules), false, fmt.Sprintf("the uptime monitor watches all %d proxy %s", len(rules), plural(len(rules), "rule", "rules")))
			},
		},
	}
}

// CheckIDs lists the ids of the default registry (tests, docs)
func CheckIDs() []string {
	var ids []string
	for _, c := range Default.Checks() {
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)
	return ids
}
