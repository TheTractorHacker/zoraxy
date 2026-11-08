package dynamicproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/pathmatch"
)

/*
	headerrules.go

	Header based access rules per proxy endpoint (upstream #1356): "require header X
	with value V (or matching a pattern), otherwise deny / drop / answer 404". They
	complement path rules and are evaluated right after them. Opt-in: an endpoint
	without HeaderRules behaves exactly as before.

	All rules of an endpoint must be satisfied (AND). A rule is satisfied when any of its
	alternative Values matches (OR), which allows rotating secrets: add the new value, deploy,
	remove the old one.

	Security notes
	  - "equals" compares SHA-256 digests with subtle.ConstantTimeCompare and always checks
	    every alternative, so neither the length nor a common prefix of a secret leaks through timing.
	  - Header values are never logged, only the rule number and the header name.
	  - "regex" uses RE2 (linear time) on a value capped at 4 KiB and is matched in full.
	  - A rule can be limited to a path prefix; the scope is matched with the same path
	    confusion hardening as path rules (encoded dots / slashes, ;params, ...).
	  - The Host header is not a valid rule target (it is part of routing).
*/

const (
	HeaderMatchEquals  = "equals"
	HeaderMatchRegex   = "regex"
	HeaderMatchPresent = "present"

	HeaderActionDeny     = "deny"     //403 (default)
	HeaderActionDrop     = "drop"     //close the connection without a response
	HeaderActionNotFound = "notfound" //404, hides that the resource exists

	maxHeaderRules     = 50
	maxHeaderValues    = 20
	maxHeaderValueLen  = 512
	maxHeaderRegexLen  = 200
	maxPresentedValue  = 4096
	maxPresentedValues = 8
)

// HeaderRule is one entry of ProxyEndpoint.HeaderRules
type HeaderRule struct {
	Name       string   //Header name
	Match      string   //equals (default), regex, present
	Values     []string //Alternatives (equals: exact secrets, regex: patterns); unused for present
	PathPrefix string   //Optional: only requests below this path are checked
	Action     string   //deny (default), drop, notfound
	Comment    string   //Free text
}

type compiledHeaderRule struct {
	HeaderRule
	canon  string
	hashes [][sha256.Size]byte
	res    []*regexp.Regexp
	scope  *compiledPathRule
}

var headerNameRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")

func compileHeaderRule(r *HeaderRule) (*compiledHeaderRule, error) {
	if r == nil {
		return nil, errors.New("empty rule")
	}
	c := &compiledHeaderRule{HeaderRule: *r}
	if !headerNameRe.MatchString(r.Name) {
		return nil, errors.New("invalid header name")
	}
	c.canon = http.CanonicalHeaderKey(r.Name)
	if strings.EqualFold(c.canon, "Host") {
		return nil, errors.New("the Host header cannot be used")
	}
	switch c.Match {
	case "":
		c.Match = HeaderMatchEquals
	case HeaderMatchEquals, HeaderMatchRegex, HeaderMatchPresent:
	default:
		return nil, errors.New("match must be equals, regex or present")
	}
	switch c.Action {
	case "":
		c.Action = HeaderActionDeny
	case HeaderActionDeny, HeaderActionDrop, HeaderActionNotFound:
	default:
		return nil, errors.New("action must be deny, drop or notfound")
	}
	if len(r.Values) > maxHeaderValues {
		return nil, fmt.Errorf("too many values (max %d)", maxHeaderValues)
	}
	switch c.Match {
	case HeaderMatchEquals:
		if len(r.Values) == 0 {
			return nil, errors.New("at least one value is required")
		}
		for _, v := range r.Values {
			if v == "" || len(v) > maxHeaderValueLen {
				return nil, errors.New("values must be 1-512 characters")
			}
			c.hashes = append(c.hashes, sha256.Sum256([]byte(v)))
		}
	case HeaderMatchRegex:
		if len(r.Values) == 0 {
			return nil, errors.New("at least one pattern is required")
		}
		for _, v := range r.Values {
			if v == "" || len(v) > maxHeaderRegexLen {
				return nil, errors.New("patterns must be 1-200 characters")
			}
			re, err := regexp.Compile("^(?:" + v + ")$")
			if err != nil {
				return nil, fmt.Errorf("invalid regular expression: %v", err)
			}
			c.res = append(c.res, re)
		}
	}
	if p := strings.TrimSpace(r.PathPrefix); p != "" && p != "/" {
		s, err := compilePathRule(&PathRule{MatchMode: PathRuleMatchPrefix, Pattern: p, Action: PathRuleDeny})
		if err != nil {
			return nil, err
		}
		c.scope = s
	}
	return c, nil
}

// ValidateHeaderRules checks a list before it is stored
func ValidateHeaderRules(rules []*HeaderRule) error {
	if len(rules) > maxHeaderRules {
		return fmt.Errorf("too many rules (max %d)", maxHeaderRules)
	}
	for i, r := range rules {
		if _, err := compileHeaderRule(r); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

func (pe *ProxyEndpoint) initHeaderRules() {
	pe.headerRules, pe.headerRulesErr = nil, nil
	if len(pe.HeaderRules) == 0 {
		return
	}
	if len(pe.HeaderRules) > maxHeaderRules {
		pe.headerRulesErr = errors.New("too many header rules")
		return
	}
	for i, r := range pe.HeaderRules {
		c, err := compileHeaderRule(r)
		if err != nil {
			pe.headerRulesErr = fmt.Errorf("header rule %d: %w", i+1, err)
			pe.headerRules = nil
			return
		}
		pe.headerRules = append(pe.headerRules, c)
	}
}

// satisfied reports whether the request carries an acceptable header value
func (c *compiledHeaderRule) satisfied(h http.Header) bool {
	vals := h.Values(c.canon)
	if len(vals) > maxPresentedValues {
		vals = vals[:maxPresentedValues]
	}
	switch c.Match {
	case HeaderMatchPresent:
		for _, v := range vals {
			if v != "" {
				return true
			}
		}
		return false
	case HeaderMatchRegex:
		for _, v := range vals {
			if len(v) > maxPresentedValue {
				continue
			}
			for _, re := range c.res {
				if re.MatchString(v) {
					return true
				}
			}
		}
		return false
	}
	//equals: constant time, no early exit over values or alternatives
	ok := 0
	for _, v := range vals {
		if len(v) > maxPresentedValue {
			continue
		}
		d := sha256.Sum256([]byte(v))
		for i := range c.hashes {
			ok |= subtle.ConstantTimeCompare(d[:], c.hashes[i][:])
		}
	}
	return ok == 1
}

// handleHeaderRules enforces the endpoint's header rules. Returns true when the request was answered.
func (h *ProxyHandler) handleHeaderRules(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if sep.headerRulesErr != nil {
		h.Parent.Option.Logger.PrintAndLog("proxy-headerrule", "Header rules of "+sep.RootOrMatchingDomain+" are invalid, refusing requests", sep.headerRulesErr)
		http.Error(w, "503 - Header rules misconfigured", http.StatusServiceUnavailable)
		return true
	}
	if len(sep.headerRules) == 0 {
		return false
	}
	var target string
	for i, rule := range sep.headerRules {
		if rule.scope != nil {
			if target == "" {
				target = pathmatch.RequestTarget(r)
			}
			if !rule.scope.matchesRequest(target, r.Method) {
				continue
			}
		}
		if rule.satisfied(r.Header) {
			continue
		}
		//Log the rule, never the presented value
		reason := fmt.Sprintf("header-rule-%d-%s", i+1, rule.canon)
		switch rule.Action {
		case HeaderActionDrop:
			h.Parent.logRequest(r, false, 444, reason+"-dropped", r.Host, "", sep)
			abuseNoteKind(r, abuse.KindForbidden)
			dropConnection(w)
		case HeaderActionNotFound:
			h.Parent.logRequest(r, false, 404, reason, r.Host, "", sep)
			serveProxyRequestError(w, http.StatusNotFound, h.Parent, ErrorTemplateHostError)
		default:
			h.Parent.logRequest(r, false, 403, reason, r.Host, "", sep)
			serveProxyRequestError(w, http.StatusForbidden, h.Parent, ErrorTemplateForbidden)
		}
		return true
	}
	return false
}

// MaskHeaderRuleSecrets blanks the secret values of "equals" rules. Call it on a COPY of the
// endpoint (CopyEndpoint) before the endpoint is serialised for the admin API.
func (pe *ProxyEndpoint) MaskHeaderRuleSecrets() {
	for i, hr := range pe.HeaderRules {
		if hr == nil || (hr.Match != "" && hr.Match != HeaderMatchEquals) {
			continue
		}
		c := *hr
		c.Values = make([]string, len(hr.Values))
		pe.HeaderRules[i] = &c
	}
}
