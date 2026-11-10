package main

/*
	Input validation shared by the admin API handlers (hostnames of proxy rules, upstream targets of
	the default site). Kept in one place so the Raw rule form, the New proxy rule dialog, the site
	editor rename and the Default Site form all give the same answer.
*/

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"imuslab.com/zoraxy/mod/utils"
)

// A config file is named after the hostname (+ ".config", "*" becomes "(ST)"), file names are capped at 255 bytes
const maxRuleHostnameLength = 240

var ruleHostLabelRe = regexp.MustCompile(`^[a-z0-9_*]([a-z0-9_*-]*[a-z0-9_*])?$`)

// normalizeRuleHostname trims and lower-cases a hostname and reports why it cannot be used as the
// matching domain of a proxy rule. Wildcards ("*.example.com") are allowed, ports, schemes, spaces and paths are not.
func normalizeRuleHostname(raw string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if h == "" {
		return "", errors.New("hostname cannot be empty")
	}
	if len(h) > maxRuleHostnameLength {
		return "", fmt.Errorf("hostname is too long (%d characters, the limit is %d)", len(h), maxRuleHostnameLength)
	}
	//Internationalised names (upstream #458) are stored as typed; they are valid when their punycode form is
	ascii := utils.NormalizeHostname(h)
	for _, c := range ascii {
		if c > 127 {
			return "", fmt.Errorf("%q is not a valid internationalised hostname", raw)
		}
	}
	for _, l := range strings.Split(ascii, ".") {
		if len(l) > 63 || !ruleHostLabelRe.MatchString(l) {
			return "", fmt.Errorf("%q is not a valid hostname", raw)
		}
	}
	return h, nil
}

// validateDefaultSiteTarget checks the value of the Default Site: a reverse proxy target (host:port, no scheme)
// or the URL of a redirect (http:// or https:// only).
func validateDefaultSiteTarget(option int, target string) error {
	target = strings.TrimSpace(target)
	switch option {
	case 1:
		if target == "" {
			return errors.New("the reverse proxy target cannot be empty")
		}
		if len(target) > 300 || strings.ContainsAny(target, " \t\r\n\x00\\'\"`<>{}|^()") {
			return errors.New("the reverse proxy target is not a valid host or host:port")
		}
		if strings.Contains(target, "://") {
			u, err := url.Parse(target)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return errors.New("the reverse proxy target is not a valid host or host:port")
			}
		}
	case 2:
		u, err := url.Parse(target)
		if target == "" || len(target) > 2000 || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("the redirect target must be a full URL starting with http:// or https://")
		}
	}
	return nil
}
