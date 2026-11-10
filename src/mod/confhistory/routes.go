package confhistory

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type routeLabel struct {
	Prefix string
	Label  string
}

// routeTable maps admin API routes to a friendly summary. The longest
// matching prefix wins. Routes that are not listed still create a version
// (when the configuration really changed) with a generic summary.
var routeTable = []routeLabel{
	{"/api/proxy/add", "Proxy rule added"},
	{"/api/proxy/del", "Proxy rule deleted"},
	{"/api/proxy/edit", "Proxy rule edited"},
	{"/api/proxy/toggle", "Proxy rule enabled or disabled"},
	{"/api/proxy/enable", "Proxy service switched"},
	{"/api/proxy/bulk", "Proxy rules changed in bulk"},
	{"/api/proxy/setTags", "Proxy rule tags changed"},
	{"/api/proxy/setAlias", "Proxy rule aliases changed"},
	{"/api/proxy/setTlsConfig", "Proxy rule TLS options changed"},
	{"/api/proxy/setHostname", "Proxy rule hostname changed"},
	{"/api/proxy/updateCredentials", "Proxy rule basic auth credentials changed"},
	{"/api/proxy/upstream/", "Proxy rule upstreams changed"},
	{"/api/proxy/vdir/", "Virtual directory changed"},
	{"/api/proxy/header/", "Custom headers changed"},
	{"/api/proxy/captcha/", "CAPTCHA settings changed"},
	{"/api/proxy/auth/", "Proxy authentication exceptions changed"},
	{"/api/proxy/networking/", "Proxy networking options changed"},
	{"/api/proxy/ops/", "Proxy operations settings changed"},
	{"/api/proxy/script/", "Proxy script changed"},
	{"/api/proxy/sablier/", "Sablier settings changed"},
	{"/api/proxy/templates/", "Rule template changed"},
	{"/api/proxy/listeningPorts/", "Listening ports changed"},
	{"/api/proxy/", "Proxy settings changed"},
	{"/api/waf/profile/", "WAF profile changed"},
	{"/api/waf/policy", "WAF policy changed"},
	{"/api/waf/endpoint/", "WAF protection of a proxy rule changed"},
	{"/api/waf/", "WAF settings changed"},
	{"/api/redirect/", "Redirect rule changed"},
	{"/api/access/import/", "Blocklist import changed"},
	{"/api/access/", "Access rule changed"},
	{"/api/blacklist/", "Blacklist changed"},
	{"/api/whitelist/", "Whitelist changed"},
	{"/api/quickban/", "Quick ban changed"},
	{"/api/trustedproxy/", "Trusted proxies changed"},
	{"/api/pathrule/", "Path rule changed"},
	{"/api/streamprox/", "Stream proxy changed"},
	{"/api/security/posture/undo", "Security fix undone"},
	{"/api/security/posture/apply", "Security fixes applied"},
	{"/api/security/posture/", "Security overview settings changed"},
	{"/api/cert/", "Certificate settings changed"},
	{"/api/acme/", "ACME settings changed"},
	{"/api/abuse/", "Auto-ban settings changed"},
	{"/api/botrules/", "Bot rules changed"},
	{"/api/aicrawler/", "AI crawler policy changed"},
	{"/api/basicauth/", "Basic auth lists changed"},
	{"/api/headerrules/", "Header rules changed"},
	{"/api/sso/", "Single sign-on settings changed"},
	{"/api/notify/", "Notification settings changed"},
	{"/api/plugins/", "Plugin settings changed"},
	{"/api/webserv/", "Static web server changed"},
	{"/api/tools/", "Tool settings changed"},
	{"/api/ech/", "Encrypted Client Hello changed"},
	{"/api/log/sites/", "Site logging changed"},
	{"/api/logger/", "Logging settings changed"},
	{"/api/blocked/settings", "Blocked-request log settings changed"},
	{"/api/visitors/settings", "Visitor tracking settings changed"},
	{"/api/stats/settings", "Statistics settings changed"},
	{"/api/utm/", "Uptime monitor changed"},
	{"/api/geodb/", "GeoIP settings changed"},
	{"/api/zrok/", "Tunnel settings changed"},
	{"/api/conf/import", "Configuration imported"},
	{"/api/v1/proxy-rules", "Proxy rule changed through the REST API"},
}

// skipPrefixes never trigger a snapshot: read-only helpers, logs, statistics,
// accounts and the history API itself (no recursion).
var skipPrefixes = []string{
	"/api/history/",
	"/api/auth/", "/api/users/", "/api/apitoken/",
	"/api/log/", "/api/stats/", "/api/analytic/", "/api/visitors/delete", "/api/visitors/purge", "/api/blocked/clear",
	"/api/info/", "/api/sysinfo/", "/api/ping", "/api/metrics", "/api/updater/", "/api/cluster/", "/api/fleet/",
	"/api/proxy/testupstream", "/api/proxy/tlscheck", "/api/proxy/script/test", "/api/proxy/sablier/test",
	"/api/proxy/templates/preview", "/api/proxy/ops/errorpreview", "/api/proxy/captcha/preview",
	"/api/waf/validate", "/api/security/posture/preview", "/api/i18n/", "/api/docker/", "/api/mdns/", "/api/conf/export",
	"/api/cert/download", "/api/authaudit/",
}

// labelFields name the request fields that identify the changed object.
var labelFields = []string{"rootname", "domain", "host", "hostname", "name", "id", "uuid", "filename", "ep"}

// SkipPath reports whether a path must not trigger a snapshot.
func SkipPath(p string) bool {
	for _, s := range skipPrefixes {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

// Mutating reports whether a method can change configuration.
func Mutating(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete || method == http.MethodPatch
}

// Summary builds the human summary of a request, e.g. "Proxy rule edited: example.com".
func Summary(r *http.Request) string { return summaryOf(r, nil) }

func summaryOf(r *http.Request, form url.Values) string {
	get := func(k string) string {
		if v := r.URL.Query().Get(k); v != "" {
			return v
		}
		if v := form.Get(k); v != "" {
			return v
		}
		return r.Form.Get(k)
	}
	p := r.URL.Path
	best := routeLabel{}
	for _, rt := range routeTable {
		if strings.HasPrefix(p, rt.Prefix) && len(rt.Prefix) > len(best.Prefix) {
			best = rt
		}
	}
	label := best.Label
	if label == "" {
		// never show a raw API path to the person reading the history
		label = "Configuration changed"
	}
	if best.Label != "" {
		if strings.HasPrefix(p, "/api/v1/proxy-rules/") {
			if n := strings.Split(strings.TrimPrefix(p, "/api/v1/proxy-rules/"), "/")[0]; n != "" {
				return trim(label+": "+n, 120)
			}
		}
		for _, f := range labelFields {
			if v := strings.TrimSpace(get(f)); v != "" && len(v) <= 120 {
				return trim(label+": "+v, 160)
			}
		}
	}
	return label
}

// RouteLabels lists the known routes (docs, tests).
func RouteLabels() []string {
	out := make([]string, 0, len(routeTable))
	for _, r := range routeTable {
		out = append(out, r.Prefix+" -> "+r.Label)
	}
	sort.Strings(out)
	return out
}
