package dynamicproxy

import (
	"fmt"
	"sort"
	"strings"
)

/*
	authaudit.go

	Authentication audit (upstream #1109 follow-up): for every proxy rule, the effective authentication
	provider and everything that weakens it (exception rules that skip the check, a basic auth scope
	that leaves part of the host open, exceptions that trust forwarded headers). Report only, nothing
	here changes behaviour except the optional auto-tagging done by the admin API.
*/

// AuthTagPrefix is the prefix of the tags written by the auto-tagger
const AuthTagPrefix = "auth:"

// AuthAuditRow is one proxy rule in the audit
type AuthAuditRow struct {
	Name       string
	Disabled   bool
	Method     string   // none, basic, forward, oauth2, zorxauth
	Weaknesses []string // empty = no known weakening
	Tags       []string
	WantedTag  string // auth:<method>
}

// AuthMethodName returns the stable audit name of an auth method
func AuthMethodName(m AuthMethod) string {
	switch m {
	case AuthMethodBasic:
		return "basic"
	case AuthMethodForward:
		return "forward"
	case AuthMethodOauth2:
		return "oauth2"
	case AuthMethodZorxAuth:
		return "zorxauth"
	}
	return "none"
}

// AuditAuth analyses one endpoint. It never mutates the endpoint.
func AuditAuth(pe *ProxyEndpoint) AuthAuditRow {
	row := AuthAuditRow{Name: pe.RootOrMatchingDomain, Disabled: pe.Disabled, Method: "none", Tags: append([]string(nil), pe.Tags...)}
	ap := pe.AuthenticationProvider
	if ap != nil {
		row.Method = AuthMethodName(ap.AuthMethod)
	}
	row.WantedTag = AuthTagPrefix + row.Method
	if ap == nil || ap.AuthMethod == AuthMethodNone {
		return row
	}
	add := func(f string, a ...interface{}) { row.Weaknesses = append(row.Weaknesses, fmt.Sprintf(f, a...)) }

	switch ap.AuthMethod {
	case AuthMethodBasic:
		if n := len(ap.BasicAuthExceptionRules); n > 0 {
			paths, cidrs, trusting := 0, 0, 0
			for _, r := range ap.BasicAuthExceptionRules {
				if r == nil {
					continue
				}
				if r.RuleType == AuthExceptionType_Paths {
					paths++
				} else {
					cidrs++
					if r.UseTrustedProxy {
						trusting++
					}
				}
			}
			add("%d exception rule(s) skip basic auth (%d path, %d address)", n, paths, cidrs)
			if trusting > 0 {
				add("%d address exception(s) trust forwarded client IP headers", trusting)
			}
		}
		if len(ap.BasicAuthScopePrefixes) > 0 {
			add("basic auth only covers: %s (the rest of the host is open)", strings.Join(ap.BasicAuthScopePrefixes, ", "))
		}
		if len(ap.BasicAuthCredentials) == 0 && len(ap.BasicAuthListNames) == 0 {
			add("no users configured (nobody can log in)")
		}
	case AuthMethodZorxAuth:
		if n := len(ap.ZorxAuthExceptionRules); n > 0 {
			trusting := 0
			for _, r := range ap.ZorxAuthExceptionRules {
				if r != nil && r.RuleType == AuthExceptionType_CIDR && r.UseTrustedProxy {
					trusting++
				}
			}
			add("%d exception rule(s) skip ZorxAuth", n)
			if trusting > 0 {
				add("%d address exception(s) trust forwarded client IP headers", trusting)
			}
		}
	case AuthMethodForward, AuthMethodOauth2:
		if n := len(ap.ExternalAuthExceptionRules); n > 0 {
			add("%d exception rule(s) skip %s", n, row.Method)
		}
	}
	return row
}

// AuditAllAuth analyses every endpoint, sorted by name
func (router *Router) AuditAllAuth() []AuthAuditRow {
	rows := []AuthAuditRow{}
	for _, ep := range router.GetProxyEndpointsAsMap() {
		rows = append(rows, AuditAuth(ep))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// RetagAuth returns tags with every "auth:*" tag replaced by wanted
func RetagAuth(tags []string, wanted string) []string {
	out := make([]string, 0, len(tags)+1)
	for _, t := range tags {
		if strings.HasPrefix(t, AuthTagPrefix) {
			continue
		}
		out = append(out, t)
	}
	return append(out, wanted)
}
