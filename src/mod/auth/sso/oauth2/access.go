package oauth2

import (
	"fmt"
	"strings"
)

/*
	access.go

	Authorisation of a signed-in user beyond "authenticated" (upstream #884, #1162). All checks are
	AND-combined and every one of them is optional (empty = not checked), so existing setups behave
	exactly as before:

	  - OAuth2AllowedGroups      group allow-list on the groups claim (existing)
	  - OAuth2AllowedClaims      generalised allow-list on ANY claim, e.g. roles, department:
	                             "roles=admin,editor; department=it"
	                             Every rule (separated by ';') must be satisfied, a rule is satisfied
	                             when the claim (string or list, nested paths like realm_access.roles
	                             work) contains any of its values. Values are compared exactly.
	  - OAuth2AllowedEmails      exact e-mail addresses (case insensitive)
	  - OAuth2AllowedEmailDomains  e-mail domains, exact domain only: "example.com" does not match
	                             "sub.example.com" or "evil-example.com"

	When an e-mail list is set the "email" claim must be present and the provider must not report
	"email_verified": false, otherwise anybody could register someone else's address at a permissive IdP.
*/

const (
	maxClaimRules   = 20
	maxClaimValues  = 50
	maxClaimItemLen = 256
)

// ClaimRule is one "claim=v1,v2" rule
type ClaimRule struct {
	Claim  string
	Values []string
}

// ParseClaimRules parses "claim=v1,v2; claim2=v3"
func ParseClaimRules(s string) ([]ClaimRule, error) {
	var out []ClaimRule
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i := strings.Index(part, "=")
		if i <= 0 {
			return nil, fmt.Errorf("invalid rule %q, expected claim=value1,value2", part)
		}
		claim := strings.TrimSpace(part[:i])
		vals := splitList(part[i+1:])
		if claim == "" || len(claim) > maxClaimItemLen {
			return nil, fmt.Errorf("invalid claim name in %q", part)
		}
		if len(vals) == 0 {
			return nil, fmt.Errorf("rule %q has no values (an empty rule would allow nobody)", part)
		}
		if len(vals) > maxClaimValues {
			return nil, fmt.Errorf("too many values in %q", part)
		}
		for _, v := range vals {
			if len(v) > maxClaimItemLen {
				return nil, fmt.Errorf("value too long in %q", part)
			}
		}
		out = append(out, ClaimRule{claim, vals})
	}
	if len(out) > maxClaimRules {
		return nil, fmt.Errorf("too many claim rules (max %d)", maxClaimRules)
	}
	return out, nil
}

func claimRulesAllowed(claims map[string]any, rules []ClaimRule) bool {
	for _, r := range rules {
		v, ok := claimValue(claims, r.Claim)
		if !ok {
			return false
		}
		have := claimStrings(v)
		hit := false
		for _, h := range have {
			for _, want := range r.Values {
				if h == want {
					hit = true
				}
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func cleanEmail(e string) (local, domain string, ok bool) {
	e = strings.TrimSpace(e)
	if e == "" || len(e) > 320 {
		return "", "", false
	}
	for _, c := range e {
		if c <= 0x20 || c == 0x7f || c == ',' || c == ';' || c == '<' || c == '>' || c == '"' {
			return "", "", false
		}
	}
	if strings.Count(e, "@") != 1 {
		return "", "", false
	}
	i := strings.Index(e, "@")
	if i <= 0 || i == len(e)-1 {
		return "", "", false
	}
	return strings.ToLower(e[:i]), strings.ToLower(e[i+1:]), true
}

func emailAllowed(claims map[string]any, emails, domains []string) bool {
	if len(emails) == 0 && len(domains) == 0 {
		return true
	}
	raw, ok := claims["email"].(string)
	if !ok {
		return false
	}
	switch v := claims["email_verified"].(type) {
	case bool:
		if !v {
			return false
		}
	case string:
		if strings.EqualFold(v, "false") {
			return false
		}
	}
	local, domain, ok := cleanEmail(raw)
	if !ok {
		return false
	}
	full := local + "@" + domain
	for _, e := range emails {
		if strings.EqualFold(strings.TrimSpace(e), full) {
			return true
		}
	}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d != "" && d == domain {
			return true
		}
	}
	return false
}

// accessAllowed combines every authorisation check of the provider configuration
func accessAllowed(o *OAuth2RouterOptions, claims map[string]any) bool {
	if !groupsAllowed(claims, o.OAuth2GroupsClaim, splitList(o.OAuth2AllowedGroups)) {
		return false
	}
	rules, err := ParseClaimRules(o.OAuth2AllowedClaims)
	if err != nil {
		return false //a broken rule set never opens access
	}
	if !claimRulesAllowed(claims, rules) {
		return false
	}
	return emailAllowed(claims, splitList(o.OAuth2AllowedEmails), splitList(o.OAuth2AllowedEmailDomains))
}
