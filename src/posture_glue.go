package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/cluster"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/offline"
	"imuslab.com/zoraxy/mod/posture"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	posture_glue.go

	Connects the security overview (mod/posture) to the running system: it gathers the Facts snapshot from the
	modules that own the state, and implements the Backend by calling the same internal functions the admin
	APIs call (never a second copy of their logic). The checks, score and action planning live in mod/posture.
*/

const postureTable = "posture"

var (
	postureEngine  *posture.Engine
	postureMu      sync.Mutex
	postureMonitor *posture.Monitor
)

func getPostureEngine() *posture.Engine {
	postureMu.Lock()
	defer postureMu.Unlock()
	if postureEngine == nil {
		if sysdb != nil {
			sysdb.NewTable(postureTable)
		}
		e := posture.NewEngine(collectPostureFacts, postureBackend{})
		e.Journal = postureJournal{}
		e.Audit = func(who posture.Actor, event, target, detail string) {
			if authAgent != nil {
				authAgent.Audit(who.Name, event, target, who.IP, detail)
			}
		}
		postureEngine = e
		postureMonitor = &posture.Monitor{Store: postureBaselineStore{}, Emit: emitPostureNotification}
	}
	return postureEngine
}

/* ---------- persistence in the system database ---------- */

type postureJournal struct{}

func (postureJournal) Load() (map[string][]posture.Change, error) {
	m := map[string][]posture.Change{}
	if sysdb != nil && sysdb.KeyExists(postureTable, "journal") {
		if err := sysdb.Read(postureTable, "journal", &m); err != nil {
			return map[string][]posture.Change{}, err
		}
	}
	return m, nil
}

func (postureJournal) Save(m map[string][]posture.Change) error {
	if sysdb == nil {
		return nil
	}
	return sysdb.Write(postureTable, "journal", m)
}

type postureBaselineStore struct{}

func (postureBaselineStore) Load() (posture.Baseline, bool) {
	var b posture.Baseline
	if sysdb == nil || !sysdb.KeyExists(postureTable, "baseline") {
		return b, false
	}
	if sysdb.Read(postureTable, "baseline", &b) != nil {
		return b, false
	}
	return b, true
}

func (postureBaselineStore) Save(b posture.Baseline) {
	if sysdb != nil {
		sysdb.Write(postureTable, "baseline", b)
	}
}

func postureNotifyEnabled() bool {
	v := false
	if sysdb != nil && sysdb.KeyExists(postureTable, "notify") {
		sysdb.Read(postureTable, "notify", &v)
	}
	return v
}

/* ---------- facts ---------- */

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0301:
		return "1.0"
	case 0x0302:
		return "1.1"
	case 0x0303:
		return "1.2"
	case 0x0304:
		return "1.3"
	}
	return ""
}

func defaultSiteName(opt int) (string, bool) {
	switch opt {
	case dynamicproxy.DefaultSite_InternalStaticWebServer:
		return "internal static web server", false
	case dynamicproxy.DefaultSite_ReverseProxy:
		return "reverse proxy to an upstream", true
	case dynamicproxy.DefaultSite_Redirect:
		return "redirect", false
	case dynamicproxy.DefaultSite_NotFoundPage:
		return "404 page", false
	case dynamicproxy.DefaultSite_NoResponse:
		return "no response", false
	case dynamicproxy.DefaultSite_TeaPot:
		return "teapot page", false
	}
	return "custom", false
}

func authMethodName(ep *dynamicproxy.ProxyEndpoint) string {
	if ep.AuthenticationProvider == nil {
		return "none"
	}
	switch ep.AuthenticationProvider.AuthMethod {
	case dynamicproxy.AuthMethodBasic:
		return "basic"
	case dynamicproxy.AuthMethodForward:
		return "forward"
	case dynamicproxy.AuthMethodOauth2:
		return "oauth2"
	case dynamicproxy.AuthMethodZorxAuth:
		return "zorxauth"
	}
	return "none"
}

func isIPLiteral(host string) bool {
	h := strings.Trim(host, "[]")
	return strings.Count(h, ":") > 1 || (len(h) > 0 && strings.Trim(h, "0123456789.") == "")
}

// section runs one fact collector; a panic leaves the section unknown instead of breaking the whole page
func section(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil && SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("posture", "Unable to read "+name+" for the security overview", fmt.Errorf("%v", r))
		}
	}()
	fn()
}

func collectPostureFacts() *posture.Facts {
	f := &posture.Facts{Now: time.Now()}

	section("admin settings", func() {
		all, loop := posture.ParseListenAddr(*webUIPort)
		f.Admin = &posture.AdminFacts{AuthRequired: requireAuth, TLSMode: *webUITLSMode, ListenAddr: *webUIPort, AllInterfaces: all, Loopback: loop}
	})

	section("tool flags", func() {
		t := &posture.ToolFacts{WebSSHLoop: *allowSshLoopback}
		if sysdb != nil {
			en := false
			sysdb.Read("fwdproxy", "enabled", &en)
			t.ForwardProxy = en
		}
		if forwardProxy != nil {
			t.ForwardPort = forwardProxy.Port
		}
		f.Tools = t
	})

	var coverage = map[string]dynamicproxy.WAFCoverageEntry{}
	var hostNames []string
	section("proxy rules", func() {
		if dynamicProxyRouter == nil {
			return
		}
		opt := dynamicProxyRouter.Option
		p := &posture.ProxyFacts{UseTLS: opt.UseTls, Port: opt.Port, ListenOnPort80: opt.ListenOnPort80, ForceHTTPSRedirect: opt.ForceHttpsRedirect,
			MinTLSVersion: tlsVersionName(opt.MinTLSVersion), DevelopmentMode: opt.NoCache, SanitiseClientIP: opt.SanitiseClientIPHeaders}
		for _, c := range dynamicProxyRouter.WAFCoverage() {
			coverage[strings.ToLower(c.Endpoint)] = c
		}
		add := func(ep *dynamicproxy.ProxyEndpoint, isDefault bool) {
			r := posture.RuleFacts{Name: ep.RootOrMatchingDomain, Disabled: ep.Disabled, IsDefault: isDefault,
				RateLimit: ep.RequireRateLimit, AuthMethod: authMethodName(ep), UptimeMonitor: !ep.DisableUptimeMonitor,
				Logging: !ep.DisableLogging, BlockExploits: ep.BlockCommonExploits, RequireCaptcha: ep.RequireCaptcha,
				BotPolicy: ep.BotPolicy, Wildcard: strings.Contains(ep.RootOrMatchingDomain, "*")}
			if ep.HeaderRewriteRules != nil {
				r.HSTSMaxAge = ep.HeaderRewriteRules.HSTSMaxAge
			}
			if c, ok := coverage[strings.ToLower(ep.RootOrMatchingDomain)]; ok {
				r.WAFMode, r.WAFOrigin = c.Mode, c.Source
				r.ChallengeBand, r.ChallengeReady = c.ChallengeThreshold > 0, c.ChallengeReady
			}
			if ep.RequireCaptcha && ep.CaptchaConfig != nil {
				cc := ep.CaptchaConfig
				r.CaptchaKeysOK = cc.Provider == captcha.ProviderAltcha || (cc.SiteKey != "" && cc.SecretKey != "")
			}
			if ep.AuthenticationProvider != nil && ep.AuthenticationProvider.AuthMethod == dynamicproxy.AuthMethodForward {
				r.ForwardAuthURL = ep.AuthenticationProvider.ForwardAuthURL
			}
			if accessController != nil {
				id := ep.AccessFilterUUID
				if id == "" {
					id = "default"
				}
				if ar, err := accessController.GetAccessRuleByID(id); err == nil && ar != nil {
					r.AccessLimited = ar.WhitelistEnabled
				}
			}
			p.Rules = append(p.Rules, r)
		}
		if root := dynamicProxyRouter.Root; root != nil {
			p.DefaultSite, p.DefaultSiteProxies = defaultSiteName(root.DefaultSiteOption)
			add(root, true)
		}
		dynamicProxyRouter.ProxyEndpoints.Range(func(_, v interface{}) bool {
			ep, ok := v.(*dynamicproxy.ProxyEndpoint)
			if !ok || ep == nil || ep == dynamicProxyRouter.Root || ep.ProxyType == dynamicproxy.ProxyTypeRoot {
				return true
			}
			add(ep, false)
			if !ep.Disabled {
				hostNames = append(hostNames, ep.RootOrMatchingDomain)
				hostNames = append(hostNames, ep.MatchingDomainAlias...)
			}
			return true
		})
		f.Proxy = p
	})

	section("certificates", func() {
		if tlsCertManager == nil || f.Proxy == nil {
			return
		}
		c := &posture.CertFacts{}
		seen := map[string]bool{}
		for _, h := range hostNames {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			if strings.Contains(h, "*") || isIPLiteral(h) || h == "localhost" {
				c.Skipped++
				continue
			}
			chk := tlsCertManager.CheckHostCertificate(h, f.Now)
			hc := posture.HostCert{Host: h, State: chk.State, NotAfter: chk.NotAfter}
			if !chk.NotAfter.IsZero() {
				hc.DaysLeft = int(chk.NotAfter.Sub(f.Now).Hours() / 24)
			}
			c.Hosts = append(c.Hosts, hc)
		}
		if names, err := tlsCertManager.ListCertDomains(); err == nil {
			c.Stored = len(names)
		}
		f.Certs = c
	})

	section("WAF policy", func() {
		if dynamicProxyRouter == nil {
			return
		}
		pol := dynamicProxyRouter.WAFState().Policy
		f.WAF = &posture.WAFFacts{PolicyEnabled: pol.Enabled, DefaultMode: pol.DefaultMode, ParanoiaLevel: pol.ParanoiaLevel,
			InboundThreshold: pol.InboundThreshold, IgnoreAnalyticsCookies: pol.IgnoreAnalyticsCookies}
	})

	section("auto-ban", func() {
		cfg := getAbuseManager().Config()
		a := &posture.AbuseFacts{Enabled: cfg.Enabled, TotalDetectors: len(cfg.Detectors)}
		for k, d := range cfg.Detectors {
			if d.Enabled {
				a.EnabledDetectors = append(a.EnabledDetectors, string(k))
			}
		}
		sort.Strings(a.EnabledDetectors)
		f.Abuse = a
	})

	section("access rules", func() {
		if accessController == nil {
			return
		}
		ar, err := accessController.GetGlobalAccessRule()
		if err != nil {
			return
		}
		f.Access = &posture.AccessFacts{TrustProxyHeadersOnly: ar.TrustProxyHeadersOnly, BlacklistEnabled: ar.BlacklistEnabled,
			WhitelistEnabled: ar.WhitelistEnabled, TrustedProxies: len(accessController.ListTrustedProxies())}
	})

	section("bot rules", func() {
		cfg := getBotEngine().Config()
		b := &posture.BotFacts{Enabled: cfg.Enabled}
		for _, c := range cfg.Categories {
			if c.Enabled {
				b.EnabledCategories++
			}
		}
		f.Bots = b
	})

	section("API tokens", func() {
		if apiTokenManager == nil {
			return
		}
		t := &posture.TokenFacts{}
		for _, i := range apiTokenManager.List() {
			tok := posture.Token{Name: i.Name, Scope: i.Scope, Revoked: i.Revoked, Expired: i.Expired}
			if i.Created > 0 {
				tok.Created = time.Unix(i.Created, 0)
			}
			if i.LastUsed > 0 {
				tok.LastUsed = time.Unix(i.LastUsed, 0)
			}
			if i.Expires > 0 {
				tok.Expires = time.Unix(i.Expires, 0)
			}
			t.Tokens = append(t.Tokens, tok)
		}
		f.Tokens = t
	})

	section("SSO providers", func() {
		if f.Proxy == nil {
			return
		}
		s := &posture.SSOFacts{}
		if oauth2Router != nil {
			s.Providers = len(oauth2Router.ProviderIDs())
			for _, u := range oauth2Router.ProviderURLs() {
				s.URLs = append(s.URLs, posture.SSOURL{Owner: u.Provider, Kind: u.Kind, URL: u.URL})
			}
		}
		for _, r := range f.Proxy.Rules {
			if r.ForwardAuthURL != "" && !r.Disabled {
				s.URLs = append(s.URLs, posture.SSOURL{Owner: r.Name, Kind: "forward-auth URL", URL: r.ForwardAuthURL})
			}
		}
		f.SSO = s
	})

	section("updater", func() {
		if updateManager == nil {
			return
		}
		st := updateManager.CachedState()
		f.Updater = &posture.UpdaterFacts{Offline: offline.Enabled(), Checked: st.Cached, CheckedAt: st.FetchedAt,
			UpdateAvailable: st.UpdateAvailable, Latest: st.Latest, Current: st.Current, Channel: st.Channel}
	})

	section("backups", func() {
		if updateManager == nil {
			return
		}
		b, err := updateManager.Backups()
		if err != nil {
			return
		}
		f.Backup = &posture.BackupFacts{Count: b.Count, Latest: b.Latest}
	})

	section("notifications", func() {
		if notifyManager == nil {
			return
		}
		ch, wh, cmd := notifyManager.Summary()
		f.Notify = &posture.NotifyFacts{Channels: ch, Webhooks: wh, Command: cmd}
	})

	section("Encrypted Client Hello", func() {
		if echMgr == nil {
			return
		}
		s := echMgr.Settings()
		e := &posture.ECHFacts{Enabled: s.Enabled, PublicName: s.PublicName}
		if s.Enabled {
			chk := echPublicNameCheck(s.PublicName)
			e.CertState, e.CertReason = chk.State, chk.Reason
		}
		f.ECH = e
	})

	section("visitors", func() {
		if visitorTracker == nil {
			return
		}
		sm := visitorTracker.Summary(f.Now)
		f.Visitors = &posture.VisitorFacts{Via: sm.Via, Total: sm.IPs}
	})

	section("cluster role", func() {
		if clusterMgr != nil {
			f.Cluster = &posture.ClusterFacts{Role: clusterMgr.Role()}
		}
	})
	return f
}

/* ---------- backend: the same functions the admin APIs use ---------- */

type postureBackend struct{}

func (postureBackend) Managed() string {
	if clusterMgr == nil {
		return ""
	}
	switch clusterMgr.Role() {
	case cluster.RoleFollower:
		if !*clusterAllowLocalEdit {
			return "This node is a cluster follower: settings are managed by the primary. Apply the fix there."
		}
	case cluster.RoleNode:
		return "This node is managed by a Fleet hub: apply the fix on the hub."
	}
	return ""
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func isOn(v string) bool { return v == "on" || v == "true" }

func (postureBackend) Get(key string) (string, bool) {
	switch {
	case strings.HasPrefix(key, "waf."):
		if dynamicProxyRouter == nil {
			return "", false
		}
		p := dynamicProxyRouter.WAFState().Policy
		switch key {
		case "waf.enabled":
			return onOff(p.Enabled), true
		case "waf.mode":
			return p.DefaultMode, true
		case "waf.paranoia":
			return strconv.Itoa(p.ParanoiaLevel), true
		case "waf.threshold":
			return strconv.Itoa(p.InboundThreshold), true
		case "waf.cookies":
			return onOff(p.IgnoreAnalyticsCookies), true
		}
	case key == "autoban.enabled":
		return onOff(getAbuseManager().Config().Enabled), true
	case strings.HasPrefix(key, "autoban.detector."):
		d, ok := getAbuseManager().Config().Detectors[abuse.Kind(strings.TrimPrefix(key, "autoban.detector."))]
		return onOff(d.Enabled), ok
	case key == "https.redirect":
		if dynamicProxyRouter == nil {
			return "", false
		}
		return onOff(dynamicProxyRouter.Option.ForceHttpsRedirect), true
	case strings.HasPrefix(key, "uptime."):
		if ep := proxyRuleByName(strings.TrimPrefix(key, "uptime.")); ep != nil {
			return onOff(!ep.DisableUptimeMonitor), true
		}
	case strings.HasPrefix(key, "hsts."):
		if ep := proxyRuleByName(strings.TrimPrefix(key, "hsts.")); ep != nil {
			if ep.HeaderRewriteRules == nil {
				return "", false //the admin handler cannot set HSTS on a rule without header settings
			}
			return strconv.FormatInt(ep.HeaderRewriteRules.HSTSMaxAge, 10), true
		}
	}
	return "", false
}

func proxyRuleByName(name string) *dynamicproxy.ProxyEndpoint {
	if dynamicProxyRouter == nil {
		return nil
	}
	// rules are stored under the ASCII (punycode) form of their host name, a rule named in Unicode is not found by that name
	ep, err := dynamicProxyRouter.LoadProxy(utils.NormalizeHostname(name))
	if err != nil {
		return nil
	}
	return ep
}

func (postureBackend) Set(key, value string) error {
	switch {
	case strings.HasPrefix(key, "waf."):
		return mutateWAFCentral(func(p *waf.Policy, _ *[]waf.Profile) error {
			switch key {
			case "waf.enabled":
				p.Enabled = isOn(value)
			case "waf.mode":
				p.DefaultMode = value
			case "waf.paranoia":
				n, err := strconv.Atoi(value)
				if err != nil {
					return err
				}
				p.ParanoiaLevel = n
			case "waf.threshold":
				n, err := strconv.Atoi(value)
				if err != nil {
					return err
				}
				p.InboundThreshold = n
			case "waf.cookies":
				p.IgnoreAnalyticsCookies = isOn(value)
			default:
				return fmt.Errorf("unknown setting %s", key)
			}
			return nil
		})
	case key == "autoban.enabled" || strings.HasPrefix(key, "autoban.detector."):
		m := getAbuseManager()
		cfg := m.Config()
		if key == "autoban.enabled" {
			cfg.Enabled = isOn(value)
		} else {
			k := abuse.Kind(strings.TrimPrefix(key, "autoban.detector."))
			d, ok := cfg.Detectors[k]
			if !ok {
				return fmt.Errorf("unknown detector %s", k)
			}
			d.Enabled = isOn(value)
			cfg.Detectors[k] = d
		}
		return m.SetConfig(cfg)
	case key == "https.redirect":
		return runInternalHandler(HandleUpdateHttpsRedirect, url.Values{"set": {strconv.FormatBool(isOn(value))}})
	case strings.HasPrefix(key, "uptime."):
		return runInternalHandler(ReverseProxyHandleEditEndpoint, url.Values{
			"rootname": {strings.TrimPrefix(key, "uptime.")}, "dutm": {strconv.FormatBool(!isOn(value))}})
	case strings.HasPrefix(key, "hsts."):
		if ep := proxyRuleByName(strings.TrimPrefix(key, "hsts.")); ep == nil || ep.HeaderRewriteRules == nil {
			return fmt.Errorf("this proxy rule has no header settings")
		}
		return runInternalHandler(HandleHSTSState, url.Values{"domain": {utils.NormalizeHostname(strings.TrimPrefix(key, "hsts."))}, "maxage": {value}})
	}
	return fmt.Errorf("unknown setting %s", key)
}

// runInternalHandler runs an existing admin handler with form values, exactly as the UI would call it, and
// turns its {"error": ...} answer into an error. The caller already passed authentication and the cluster guard.
func runInternalHandler(h http.HandlerFunc, form url.Values) error {
	r := httptest.NewRequest(http.MethodPost, "/internal", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, r)
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &e) == nil && e.Error != "" {
		return fmt.Errorf("%s", e.Error)
	}
	if rec.Code >= 400 {
		return fmt.Errorf("%s", strings.TrimSpace(rec.Body.String()))
	}
	return nil
}
