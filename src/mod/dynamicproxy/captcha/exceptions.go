package captcha

import (
	"errors"
	"path"
	"regexp"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/pathmatch"
)

/*
	exceptions.go

	Path exception modes of the CAPTCHA gate (fork #222 / upstream #1161). A path rule is a prefix
	(default, matches on segment boundaries, unchanged behaviour), an exact path or a regular
	expression. exact and regex are hardened like the SSO exceptions: they only ever match a request
	target that is already canonical, so "/webhook/../admin" or "/ok/%2e%2e/admin" are challenged
	instead of being normalised into an exemption.
*/

const (
	ExceptionMatchPrefix = "prefix"
	ExceptionMatchExact  = "exact"
	ExceptionMatchRegex  = "regex"

	MaxExceptionPatternLen = 512
)

var exceptionRegexCache sync.Map // "s:"/"i:"+pattern -> *regexp.Regexp (nil = invalid)

func exceptionRegex(pattern string, fold bool) *regexp.Regexp {
	key := "s:" + pattern
	if fold {
		key = "i:" + pattern
	}
	if v, ok := exceptionRegexCache.Load(key); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	expr := "^(?:" + pattern + ")$"
	if fold {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		re = nil
	}
	exceptionRegexCache.Store(key, re)
	return re
}

// ValidateExceptionPattern checks a path rule's mode and pattern.
func ValidateExceptionPattern(mode, pattern string) error {
	if len(pattern) > MaxExceptionPatternLen {
		return errors.New("pattern is too long")
	}
	switch mode {
	case "", ExceptionMatchPrefix, ExceptionMatchExact:
		return nil
	case ExceptionMatchRegex:
		if exceptionRegex(pattern, false) == nil {
			return errors.New("invalid regular expression")
		}
		return nil
	}
	return errors.New("match mode must be prefix, exact or regex")
}

// pathRuleMatches evaluates one path rule against the raw request target.
func pathRuleMatches(rule *ExceptionRule, requestTarget string) bool {
	switch rule.MatchMode {
	case ExceptionMatchExact, ExceptionMatchRegex:
		p, ok := pathmatch.CanonicalPath(requestTarget)
		if !ok {
			return false
		}
		pat := strings.TrimSpace(rule.PathPrefix)
		if pat == "" || len(pat) > MaxExceptionPatternLen {
			return false
		}
		if rule.MatchMode == ExceptionMatchRegex {
			re := exceptionRegex(pat, rule.CaseInsensitive)
			return re != nil && re.MatchString(p)
		}
		want := path.Clean("/" + pat)
		if rule.CaseInsensitive {
			return strings.EqualFold(p, want)
		}
		return p == want
	}
	if rule.CaseInsensitive {
		return pathmatch.RequestPathWithinPrefixFold(requestTarget, rule.PathPrefix)
	}
	return pathmatch.RequestPathWithinPrefix(requestTarget, rule.PathPrefix)
}
