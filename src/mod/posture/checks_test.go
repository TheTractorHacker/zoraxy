package posture

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func rule(name string) RuleFacts {
	return RuleFacts{Name: name, WAFMode: "block", WAFOrigin: "inherit", RateLimit: true, AuthMethod: "basic", UptimeMonitor: true,
		HSTSMaxAge: 31536000, Logging: true, BlockExploits: true}
}

// healthy returns a snapshot in which every check passes (or does not apply)
func healthy() *Facts {
	return &Facts{
		Now:   t0,
		Admin: &AdminFacts{AuthRequired: true, TLSMode: "auto", ListenAddr: "127.0.0.1:8000", Loopback: true},
		Proxy: &ProxyFacts{UseTLS: true, Port: 443, ListenOnPort80: true, ForceHTTPSRedirect: true, MinTLSVersion: "1.2", DefaultSite: "404 page",
			SanitiseClientIP: true, Rules: []RuleFacts{rule("a.example.com"), rule("b.example.com"), {Name: "/", IsDefault: true}}},
		Certs:    &CertFacts{Hosts: []HostCert{{Host: "a.example.com", State: "ok", DaysLeft: 80}, {Host: "b.example.com", State: "ok", DaysLeft: 80}}},
		WAF:      &WAFFacts{PolicyEnabled: true, DefaultMode: "block", ParanoiaLevel: 1, InboundThreshold: 5, IgnoreAnalyticsCookies: true},
		Abuse:    &AbuseFacts{Enabled: true, EnabledDetectors: []string{"waf_block"}, TotalDetectors: 9},
		Access:   &AccessFacts{TrustProxyHeadersOnly: true, TrustedProxies: 5},
		Bots:     &BotFacts{Enabled: true, EnabledCategories: 3},
		Tokens:   &TokenFacts{},
		SSO:      &SSOFacts{},
		Updater:  &UpdaterFacts{Checked: true, CheckedAt: t0.Add(-24 * time.Hour), Current: "v1", Latest: "v1", Channel: "stable"},
		Backup:   &BackupFacts{Count: 2, Latest: t0.Add(-48 * time.Hour)},
		Notify:   &NotifyFacts{Channels: 1},
		ECH:      &ECHFacts{},
		Tools:    &ToolFacts{},
		Visitors: &VisitorFacts{Via: map[string]int{"direct": 10}, Total: 10},
		Cluster:  &ClusterFacts{Role: "standalone"},
	}
}

func statusOf(t *testing.T, f *Facts, id string) CheckResult {
	t.Helper()
	rep := Default.Evaluate(f)
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %s is not registered", id)
	return CheckResult{}
}

type checkCase struct {
	name     string
	mutate   func(f *Facts)
	want     Status
	evidence string // substring expected in the evidence
}

func runCases(t *testing.T, id string, cases []checkCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(id+"/"+c.name, func(t *testing.T) {
			f := healthy()
			if c.mutate != nil {
				c.mutate(f)
			}
			got := statusOf(t, f, id)
			if got.Status != c.want {
				t.Fatalf("status = %s (%v), want %s", got.Status, got.Evidence, c.want)
			}
			if len(got.Evidence) == 0 {
				t.Fatal("a check must always state its evidence")
			}
			if c.evidence != "" && !strings.Contains(strings.Join(got.Evidence, " | "), c.evidence) {
				t.Fatalf("evidence %v lacks %q", got.Evidence, c.evidence)
			}
		})
	}
}

func setRules(f *Facts, fn func(r *RuleFacts)) {
	for i := range f.Proxy.Rules {
		if !f.Proxy.Rules[i].IsDefault {
			fn(&f.Proxy.Rules[i])
		}
	}
}

func TestHealthySnapshotPassesEverything(t *testing.T) {
	rep := Default.Evaluate(healthy())
	for _, c := range rep.Checks {
		if c.Status != StatusOK && c.Status != StatusNA {
			t.Errorf("%s = %s %v on a healthy snapshot", c.ID, c.Status, c.Evidence)
		}
	}
	if rep.Score.Value != 100 || rep.Score.Grade != "A" {
		t.Fatalf("healthy score = %d %s", rep.Score.Value, rep.Score.Grade)
	}
}

// A check may never pass or warn about something it did not look at.
func TestNothingKnownMeansNothingIsOK(t *testing.T) {
	rep := Default.Evaluate(&Facts{Now: t0})
	for _, c := range rep.Checks {
		if c.Status == StatusOK || c.Status == StatusWarn || c.Status == StatusFail {
			t.Errorf("%s reported %s without any data: %v", c.ID, c.Status, c.Evidence)
		}
	}
	if !rep.Score.Provisional || rep.Score.Value > CriticalCap {
		t.Fatalf("an empty snapshot must give a provisional, capped score: %+v", rep.Score)
	}
}

func TestEveryCheckIsDocumented(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Default.Checks() {
		if seen[c.ID] {
			t.Errorf("duplicate id %s", c.ID)
		}
		seen[c.ID] = true
		if c.Why == "" || c.Title == "" || c.Remediation.Label == "" {
			t.Errorf("%s lacks a why, a title or a remediation", c.ID)
		}
		if c.Remediation.Page == "" && c.Remediation.Href == "" && c.Remediation.Hint == "" {
			t.Errorf("%s: remediation points nowhere", c.ID)
		}
		if c.Remediation.Action != "" {
			if _, ok := DefaultActions.Get(c.Remediation.Action); !ok {
				t.Errorf("%s names the unknown action %s", c.ID, c.Remediation.Action)
			}
		}
	}
	if n := len(Default.Checks()); n < 20 || n > 40 {
		t.Errorf("%d checks, expected 20-40", n)
	}
	for _, a := range DefaultActions.All() {
		for _, id := range a.Covers {
			if !seen[id] {
				t.Errorf("action %s covers the unknown check %s", a.ID, id)
			}
		}
	}
}

func TestChecks_Exposure(t *testing.T) {
	runCases(t, "admin.auth", []checkCase{
		{"ok", nil, StatusOK, ""},
		{"noauth", func(f *Facts) { f.Admin.AuthRequired = false }, StatusFail, "-noauth"},
		{"unknown", func(f *Facts) { f.Admin = nil }, StatusUnknown, ""},
	})
	runCases(t, "admin.tls", []checkCase{
		{"https", func(f *Facts) { f.Admin.TLSMode = "auto"; f.Admin.Loopback = false; f.Admin.AllInterfaces = true }, StatusOK, "HTTPS"},
		{"plain loopback", func(f *Facts) { f.Admin.TLSMode = "off" }, StatusOK, "this machine only"},
		{"plain exposed", func(f *Facts) {
			f.Admin.TLSMode = "off"
			f.Admin.Loopback = false
			f.Admin.ListenAddr = ":8000"
			f.Admin.AllInterfaces = true
		}, StatusFail, ":8000"},
		{"unknown", func(f *Facts) { f.Admin = nil }, StatusUnknown, ""},
	})
	runCases(t, "admin.bind", []checkCase{
		{"loopback", nil, StatusOK, "loopback"},
		{"all", func(f *Facts) { f.Admin.AllInterfaces = true; f.Admin.Loopback = false; f.Admin.ListenAddr = ":8000" }, StatusWarn, "all interfaces"},
		{"one address", func(f *Facts) { f.Admin.Loopback = false; f.Admin.ListenAddr = "192.168.1.5:8000" }, StatusOK, "one specific"},
		{"unknown", func(f *Facts) { f.Admin = nil }, StatusUnknown, ""},
	})
	runCases(t, "exposure.default_site", []checkCase{
		{"closed", nil, StatusOK, "404"},
		{"proxies", func(f *Facts) {
			f.Proxy.DefaultSite = "reverse proxy to an upstream"
			f.Proxy.DefaultSiteProxies = true
		}, StatusWarn, "reverse proxy"},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "exposure.dev_mode", []checkCase{
		{"off", nil, StatusOK, ""},
		{"on", func(f *Facts) { f.Proxy.DevelopmentMode = true }, StatusWarn, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "exposure.forward_proxy", []checkCase{
		{"off", nil, StatusOK, ""},
		{"on", func(f *Facts) { f.Tools.ForwardProxy = true; f.Tools.ForwardPort = 5587 }, StatusWarn, "5587"},
		{"unknown", func(f *Facts) { f.Tools = nil }, StatusUnknown, ""},
	})
	runCases(t, "exposure.webssh_loopback", []checkCase{
		{"off", nil, StatusOK, ""},
		{"on", func(f *Facts) { f.Tools.WebSSHLoop = true }, StatusFail, "-sshlb"},
		{"unknown", func(f *Facts) { f.Tools = nil }, StatusUnknown, ""},
	})
}

func TestChecks_WebAttacks(t *testing.T) {
	runCases(t, "waf.active", []checkCase{
		{"block", nil, StatusOK, "all 2"},
		{"detection counts", func(f *Facts) { setRules(f, func(r *RuleFacts) { r.WAFMode = "detection_only" }) }, StatusOK, ""},
		{"some off", func(f *Facts) { f.Proxy.Rules[0].WAFMode = "off" }, StatusWarn, "1 of 2"},
		{"all off", func(f *Facts) {
			setRules(f, func(r *RuleFacts) { r.WAFMode = "off" })
		}, StatusFail, "off for 2 of 2"},
		{"no rules", func(f *Facts) { f.Proxy.Rules = nil }, StatusNA, ""},
		{"disabled rules do not count", func(f *Facts) { f.Proxy.Rules[0].Disabled = true; f.Proxy.Rules[0].WAFMode = "off" }, StatusOK, ""},
		{"mode missing", func(f *Facts) { f.Proxy.Rules[0].WAFMode = "" }, StatusUnknown, "a.example.com"},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "waf.blocking", []checkCase{
		{"block", nil, StatusOK, ""},
		{"detection only", func(f *Facts) { f.Proxy.Rules[0].WAFMode = "detection_only" }, StatusWarn, "1 of 2"},
		{"all off", func(f *Facts) { setRules(f, func(r *RuleFacts) { r.WAFMode = "off" }) }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "waf.analytics_cookies", []checkCase{
		{"ignored", nil, StatusOK, ""},
		{"inspected", func(f *Facts) { f.WAF.IgnoreAnalyticsCookies = false }, StatusWarn, ""},
		{"waf off", func(f *Facts) {
			f.WAF.IgnoreAnalyticsCookies = false
			setRules(f, func(r *RuleFacts) { r.WAFMode = "off" })
		}, StatusNA, ""},
		{"unknown", func(f *Facts) { f.WAF = nil }, StatusUnknown, ""},
	})
	runCases(t, "web.exploit_filter", []checkCase{
		{"ok", nil, StatusOK, ""},
		{"neither", func(f *Facts) { f.Proxy.Rules[0].BlockExploits = false; f.Proxy.Rules[0].WAFMode = "detection_only" }, StatusWarn, "a.example.com"},
		{"waf block is enough", func(f *Facts) { f.Proxy.Rules[0].BlockExploits = false }, StatusOK, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "waf.challenge_ready", []checkCase{
		{"not used", nil, StatusNA, ""},
		{"ready", func(f *Facts) { f.Proxy.Rules[0].ChallengeBand, f.Proxy.Rules[0].ChallengeReady = true, true }, StatusOK, ""},
		{"no provider", func(f *Facts) { f.Proxy.Rules[0].ChallengeBand = true }, StatusWarn, "no CAPTCHA provider"},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "captcha.keys", []checkCase{
		{"not used", nil, StatusNA, ""},
		{"keys", func(f *Facts) { f.Proxy.Rules[0].RequireCaptcha, f.Proxy.Rules[0].CaptchaKeysOK = true, true }, StatusOK, ""},
		{"one of two missing", func(f *Facts) {
			setRules(f, func(r *RuleFacts) { r.RequireCaptcha, r.CaptchaKeysOK = true, true })
			f.Proxy.Rules[0].CaptchaKeysOK = false
		}, StatusWarn, "a.example.com"},
		{"all missing", func(f *Facts) { setRules(f, func(r *RuleFacts) { r.RequireCaptcha = true }) }, StatusFail, "2 of 2"},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "bots.rules", []checkCase{
		{"global", nil, StatusOK, "3 categories"},
		{"per rule", func(f *Facts) { f.Bots.Enabled = false; f.Proxy.Rules[0].BotPolicy = "on" }, StatusOK, "1 proxy rule"},
		{"off", func(f *Facts) { f.Bots.Enabled = false }, StatusWarn, ""},
		{"unknown", func(f *Facts) { f.Bots = nil }, StatusUnknown, ""},
	})
}

func TestChecks_Abuse(t *testing.T) {
	runCases(t, "abuse.autoban", []checkCase{
		{"on", nil, StatusOK, "waf_block"},
		{"off", func(f *Facts) { f.Abuse.Enabled = false }, StatusWarn, "off"},
		{"no detectors", func(f *Facts) { f.Abuse.EnabledDetectors = nil }, StatusWarn, "none of its 9"},
		{"unknown", func(f *Facts) { f.Abuse = nil }, StatusUnknown, ""},
	})
	runCases(t, "abuse.ratelimit", []checkCase{
		{"all", nil, StatusOK, ""},
		{"some", func(f *Facts) { f.Proxy.Rules[0].RateLimit = false }, StatusWarn, "1 of 2"},
		{"none", func(f *Facts) { setRules(f, func(r *RuleFacts) { r.RateLimit = false }) }, StatusFail, "2 of 2"},
		{"no rules", func(f *Facts) { f.Proxy.Rules = nil }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "access.trusted_proxy_gating", []checkCase{
		{"no cdn seen", nil, StatusNA, "none of the 10"},
		{"cdn and gating", func(f *Facts) { f.Visitors.Via = map[string]int{"cloudflare": 4, "direct": 6} }, StatusOK, "4 of 10"},
		{"cdn without gating", func(f *Facts) {
			f.Visitors.Via = map[string]int{"cloudflare": 4, "direct": 6}
			f.Access.TrustProxyHeadersOnly = false
		}, StatusWarn, "does not restrict"},
		{"no visitors yet", func(f *Facts) { f.Visitors.Total = 0 }, StatusUnknown, "cannot be detected"},
		{"unknown", func(f *Facts) { f.Visitors = nil }, StatusUnknown, ""},
	})
	runCases(t, "access.sanitise_client_ip", []checkCase{
		{"on", nil, StatusOK, ""},
		{"off", func(f *Facts) { f.Proxy.SanitiseClientIP = false }, StatusWarn, "no CDN"},
		{"behind cdn", func(f *Facts) { f.Proxy.SanitiseClientIP = false; f.Visitors.Via = map[string]int{"proxy": 3} }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Visitors = nil }, StatusUnknown, ""},
	})
}

func TestChecks_Authentication(t *testing.T) {
	runCases(t, "auth.admin_ui_exposed", []checkCase{
		{"no admin names", nil, StatusOK, "none of the 2"},
		{"protected", func(f *Facts) { f.Proxy.Rules[0].Name = "grafana.example.com"; f.Proxy.Rules[0].AuthMethod = "oauth2" }, StatusOK, "1 host name"},
		{"allow list", func(f *Facts) {
			f.Proxy.Rules[0].Name = "grafana.example.com"
			f.Proxy.Rules[0].AuthMethod = "none"
			f.Proxy.Rules[0].AccessLimited = true
		}, StatusOK, ""},
		{"open", func(f *Facts) { f.Proxy.Rules[0].Name = "portainer.example.com"; f.Proxy.Rules[0].AuthMethod = "none" }, StatusWarn, "portainer.example.com"},
		{"no rules", func(f *Facts) { f.Proxy.Rules = nil }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	if !Default.Checks()[indexOf("auth.admin_ui_exposed")].Heuristic {
		t.Error("the admin UI check is a guess by name and must be labelled heuristic")
	}
	if w, ok := LooksLikeAdminUI("example.com"); ok {
		t.Errorf("example.com matched %q", w)
	}
	if _, ok := LooksLikeAdminUI("blog.example.com"); ok {
		t.Error("a blog is not an admin UI")
	}
	runCases(t, "auth.stale_tokens", []checkCase{
		{"none", nil, StatusNA, ""},
		{"fresh", func(f *Facts) { f.Tokens.Tokens = []Token{{Name: "ci", Created: t0.Add(-10 * 24 * time.Hour)}} }, StatusOK, ""},
		{"used", func(f *Facts) {
			f.Tokens.Tokens = []Token{{Name: "ci", Created: t0.Add(-400 * 24 * time.Hour), LastUsed: t0.Add(-2 * 24 * time.Hour)}}
		}, StatusOK, ""},
		{"never used", func(f *Facts) { f.Tokens.Tokens = []Token{{Name: "old", Created: t0.Add(-60 * 24 * time.Hour)}} }, StatusWarn, "never used"},
		{"idle", func(f *Facts) {
			f.Tokens.Tokens = []Token{{Name: "idle", Created: t0.Add(-300 * 24 * time.Hour), LastUsed: t0.Add(-120 * 24 * time.Hour)}}
		}, StatusWarn, "120 days"},
		{"revoked ignored", func(f *Facts) {
			f.Tokens.Tokens = []Token{{Name: "old", Created: t0.Add(-600 * 24 * time.Hour), Revoked: true}}
		}, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Tokens = nil }, StatusUnknown, ""},
	})
	runCases(t, "auth.sso_transport", []checkCase{
		{"none", nil, StatusNA, ""},
		{"https", func(f *Facts) { f.SSO.URLs = []SSOURL{{"idp", "issuer", "https://id.example.com"}} }, StatusOK, ""},
		{"http loopback", func(f *Facts) { f.SSO.URLs = []SSOURL{{"idp", "issuer", "http://127.0.0.1:9000"}} }, StatusOK, ""},
		{"http private ip", func(f *Facts) { f.SSO.URLs = []SSOURL{{"idp", "issuer", "http://192.168.1.4/auth"}} }, StatusOK, ""},
		{"http hostname", func(f *Facts) { f.SSO.URLs = []SSOURL{{"idp", "issuer", "http://authentik.lan/"}} }, StatusWarn, "plain http"},
		{"http public", func(f *Facts) { f.SSO.URLs = []SSOURL{{"idp", "issuer", "http://203.0.113.9/"}} }, StatusFail, "public"},
		{"unknown", func(f *Facts) { f.SSO = nil }, StatusUnknown, ""},
	})
}

func TestChecks_CertsAndTLS(t *testing.T) {
	runCases(t, "tls.enabled", []checkCase{
		{"on", nil, StatusOK, "443"},
		{"off", func(f *Facts) { f.Proxy.UseTLS = false }, StatusFail, "plain HTTP"},
		{"no rules", func(f *Facts) { f.Proxy.Rules = nil }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "tls.https_redirect", []checkCase{
		{"on", nil, StatusOK, "redirects"},
		{"no listener", func(f *Facts) { f.Proxy.ListenOnPort80 = false; f.Proxy.ForceHTTPSRedirect = false }, StatusOK, "no plain HTTP"},
		{"off", func(f *Facts) { f.Proxy.ForceHTTPSRedirect = false }, StatusWarn, "does not redirect"},
		{"no tls", func(f *Facts) { f.Proxy.UseTLS = false }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "tls.hsts", []checkCase{
		{"on", nil, StatusOK, ""},
		{"some", func(f *Facts) { f.Proxy.Rules[0].HSTSMaxAge = 0 }, StatusWarn, "1 of 2"},
		{"none", func(f *Facts) { setRules(f, func(r *RuleFacts) { r.HSTSMaxAge = 0 }) }, StatusFail, "2 of 2"},
		{"no tls", func(f *Facts) { f.Proxy.UseTLS = false }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "cert.expiry", []checkCase{
		{"fine", nil, StatusOK, "30 more days"},
		{"30 days", func(f *Facts) { f.Certs.Hosts[0].DaysLeft = 25 }, StatusWarn, "25 days"},
		{"14 days", func(f *Facts) { f.Certs.Hosts[0].DaysLeft = 9 }, StatusFail, "9 days"},
		{"expired", func(f *Facts) { f.Certs.Hosts[0].State = "expired"; f.Certs.Hosts[0].DaysLeft = -3 }, StatusFail, "expired"},
		{"missing certs are the other check", func(f *Facts) { f.Certs.Hosts = []HostCert{{Host: "a", State: "missing"}} }, StatusNA, ""},
		{"no tls", func(f *Facts) { f.Proxy.UseTLS = false }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Certs = nil }, StatusUnknown, ""},
	})
	runCases(t, "cert.coverage", []checkCase{
		{"all", nil, StatusOK, "all 2"},
		{"fallback", func(f *Facts) { f.Certs.Hosts[1].State = "fallback" }, StatusFail, "b.example.com (fallback)"},
		{"missing", func(f *Facts) { f.Certs.Hosts[1].State = "missing" }, StatusFail, ""},
		{"mismatch", func(f *Facts) { f.Certs.Hosts[1].State = "mismatch" }, StatusFail, ""},
		{"self signed", func(f *Facts) { f.Certs.Hosts[1].State = "selfsigned" }, StatusWarn, "self-signed"},
		{"wildcards noted", func(f *Facts) { f.Certs.Skipped = 2 }, StatusOK, "2 wildcard or IP"},
		{"nothing to check", func(f *Facts) { f.Certs.Hosts = nil }, StatusNA, ""},
		{"no tls", func(f *Facts) { f.Proxy.UseTLS = false }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Certs = nil }, StatusUnknown, ""},
	})
	runCases(t, "tls.min_version", []checkCase{
		{"1.2", nil, StatusOK, "1.2"},
		{"unset", func(f *Facts) { f.Proxy.MinTLSVersion = "" }, StatusOK, "Go default"},
		{"1.0", func(f *Facts) { f.Proxy.MinTLSVersion = "1.0" }, StatusWarn, "1.0"},
		{"1.1", func(f *Facts) { f.Proxy.MinTLSVersion = "1.1" }, StatusWarn, "1.1"},
		{"no tls", func(f *Facts) { f.Proxy.UseTLS = false }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
	runCases(t, "ech.config", []checkCase{
		{"off", nil, StatusNA, ""},
		{"ok", func(f *Facts) { f.ECH = &ECHFacts{Enabled: true, PublicName: "ech.example.com", CertState: "ok"} }, StatusOK, ""},
		{"broken", func(f *Facts) {
			f.ECH = &ECHFacts{Enabled: true, PublicName: "ech.example.com", CertState: "fallback", CertReason: "no certificate matches"}
		}, StatusFail, "fallback"},
		{"unknown", func(f *Facts) { f.ECH = nil }, StatusUnknown, ""},
	})
}

func TestChecks_Operations(t *testing.T) {
	runCases(t, "ops.updates", []checkCase{
		{"current", nil, StatusOK, "checked 1 days ago"},
		{"available", func(f *Facts) { f.Updater.UpdateAvailable = true; f.Updater.Latest = "v2" }, StatusWarn, "v2"},
		{"never checked", func(f *Facts) { f.Updater.Checked = false }, StatusUnknown, "has not checked"},
		{"stale check", func(f *Facts) { f.Updater.CheckedAt = t0.Add(-90 * 24 * time.Hour) }, StatusUnknown, "90 days"},
		{"offline", func(f *Facts) { f.Updater.Offline = true }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Updater = nil }, StatusUnknown, ""},
	})
	runCases(t, "ops.backup", []checkCase{
		{"recent", nil, StatusOK, "2 days old"},
		{"old", func(f *Facts) { f.Backup.Latest = t0.Add(-60 * 24 * time.Hour) }, StatusWarn, "60 days"},
		{"none seen", func(f *Facts) { f.Backup.Count = 0 }, StatusUnknown, "outside Zoraxy"},
		{"unknown", func(f *Facts) { f.Backup = nil }, StatusUnknown, ""},
	})
	runCases(t, "ops.notifications", []checkCase{
		{"channel", nil, StatusOK, "1 channels"},
		{"webhook", func(f *Facts) { f.Notify = &NotifyFacts{Webhooks: 1} }, StatusOK, ""},
		{"command", func(f *Facts) { f.Notify = &NotifyFacts{Command: true} }, StatusOK, ""},
		{"none", func(f *Facts) { f.Notify = &NotifyFacts{} }, StatusWarn, "no notification"},
		{"unknown", func(f *Facts) { f.Notify = nil }, StatusUnknown, ""},
	})
	runCases(t, "ops.uptime", []checkCase{
		{"all", nil, StatusOK, ""},
		{"some", func(f *Facts) { f.Proxy.Rules[0].UptimeMonitor = false }, StatusWarn, "1 of 2"},
		{"none", func(f *Facts) { setRules(f, func(r *RuleFacts) { r.UptimeMonitor = false }) }, StatusWarn, "2 of 2"},
		{"no rules", func(f *Facts) { f.Proxy.Rules = nil }, StatusNA, ""},
		{"unknown", func(f *Facts) { f.Proxy = nil }, StatusUnknown, ""},
	})
}

func indexOf(id string) int {
	for i, c := range Default.Checks() {
		if c.ID == id {
			return i
		}
	}
	return -1
}

func TestParseListenAddr(t *testing.T) {
	cases := []struct {
		in        string
		all, loop bool
	}{
		{":8000", true, false}, {"0.0.0.0:8000", true, false}, {"[::]:8000", true, false}, {"8000", true, false},
		{"127.0.0.1:8000", false, true}, {"[::1]:8000", false, true}, {"localhost:8000", false, true},
		{"192.168.1.5:8000", false, false}, {"", false, false}, {"nonsense:", false, false},
	}
	for _, c := range cases {
		all, loop := ParseListenAddr(c.in)
		if all != c.all || loop != c.loop {
			t.Errorf("%q = (%v,%v), want (%v,%v)", c.in, all, loop, c.all, c.loop)
		}
	}
}

func TestCheckPanicBecomesUnknown(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(Check{ID: "x.panic", Title: "t", Category: CatOps, Weight: 1, Run: func(f *Facts) Result { panic("boom") }})
	r.MustRegister(Check{ID: "x.badstatus", Title: "t", Category: CatOps, Weight: 1, Run: func(f *Facts) Result { return Result{Status: "great"} }})
	rep := r.Evaluate(&Facts{})
	for _, c := range rep.Checks {
		if c.Status != StatusUnknown {
			t.Errorf("%s = %s", c.ID, c.Status)
		}
	}
}

func TestRegistryRejectsBadChecks(t *testing.T) {
	r := NewRegistry()
	ok := func(f *Facts) Result { return Result{Status: StatusOK} }
	good := Check{ID: "a.b", Title: "t", Category: CatOps, Weight: 1, Run: ok}
	if err := r.Register(good); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Check{
		"duplicate": good, "no id": {Title: "t", Category: CatOps, Weight: 1, Run: ok}, "no run": {ID: "c", Title: "t", Category: CatOps, Weight: 1},
		"weight 0": {ID: "d", Title: "t", Category: CatOps, Weight: 0, Run: ok}, "weight 11": {ID: "e", Title: "t", Category: CatOps, Weight: 11, Run: ok},
		"category": {ID: "f", Title: "t", Category: "Nope", Weight: 1, Run: ok},
	} {
		if r.Register(c) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
