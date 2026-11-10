package posture

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// ParseListenAddr tells whether a listen address (the -port flag) binds every interface or only loopback
func ParseListenAddr(addr string) (all bool, loopback bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false, false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if !strings.Contains(addr, ":") { // a bare port such as "8000"
			return true, false
		}
		return false, false
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true, false
	}
	if host == "localhost" {
		return false, true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsUnspecified(), ip.IsLoopback()
	}
	return false, false
}

// listNames renders up to max names, then "and N more"
func listNames(names []string, max int) string {
	sort.Strings(names)
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:max], ", ") + fmt.Sprintf(" and %d more", len(names)-max)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func unknown(why string) Result { return Result{Status: StatusUnknown, Evidence: []string{why}} }
func na(why string) Result      { return Result{Status: StatusNA, Evidence: []string{why}} }

// ratio builds the standard "X is off for N of M proxy rules" result: ok when none are affected, warn when some are,
// fail when all are. When failAll is false the worst case is a warning.
func ratio(what string, bad []string, total int, failAll bool, okText string) Result {
	switch {
	case len(bad) == 0:
		return Result{Status: StatusOK, Evidence: []string{okText}}
	case len(bad) == total && failAll:
		return Result{Status: StatusFail, Evidence: []string{fmt.Sprintf("%s for %d of %d proxy %s: %s", what, len(bad), total, plural(total, "rule", "rules"), listNames(bad, 8))}}
	}
	return Result{Status: StatusWarn, Evidence: []string{fmt.Sprintf("%s for %d of %d proxy %s: %s", what, len(bad), total, plural(total, "rule", "rules"), listNames(bad, 8))}}
}

// loginPathWords are path words that usually mean a login or administration page. Only a guess.
var loginPathWords = []string{"login", "signin", "sign-in", "logon", "auth", "admin", "wp-login", "xmlrpc", "password", "account", "session", "token", "oauth"}

// LooksLikeLoginPath reports whether a path pattern looks like a login or admin path
func LooksLikeLoginPath(p string) bool {
	p = strings.ToLower(p)
	for _, w := range loginPathWords {
		if strings.Contains(p, w) {
			return true
		}
	}
	return false
}

// hostWordSet splits a host name into lower case words ("grafana.home-lab.example.com" -> grafana, home, lab, example, com)
func hostWordSet(host string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(host), func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
		out[w] = true
	}
	return out
}

// adminUIWords are host name words that usually mean an administration interface. Only a guess.
var adminUIWords = []string{
	"admin", "administrator", "grafana", "portainer", "phpmyadmin", "pgadmin", "adminer", "proxmox", "pve", "unifi",
	"pihole", "pi-hole", "kibana", "jenkins", "traefik", "prometheus", "cockpit", "webmin", "vault", "opnsense",
	"pfsense", "truenas", "netdata", "router", "firewall", "dashboard", "console", "phpldapadmin", "rancher",
}

// LooksLikeAdminUI reports the word that makes a host name look like an administration interface
func LooksLikeAdminUI(host string) (string, bool) {
	words := hostWordSet(host)
	for _, w := range adminUIWords {
		if words[w] {
			return w, true
		}
	}
	return "", false
}

// urlTransport classifies a URL used by an SSO integration. insecure is true for plain http; where tells how far it travels.
func urlTransport(raw string) (plainHTTP bool, where string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || !strings.EqualFold(u.Scheme, "http") {
		return false, ""
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true, "loopback"
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsLoopback() {
			return true, "loopback"
		}
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true, "private"
		}
		return true, "public"
	}
	return true, "hostname" // a name: where it points was not resolved
}
