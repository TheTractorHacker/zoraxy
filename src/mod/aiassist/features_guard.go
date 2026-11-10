package aiassist

import (
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

// exclusionPathOK is true for paths that may be excluded: absolute, short, without delimiters or
// wildcards. "/" and "/*" would switch a rule off for the whole site and are refused.
func exclusionPathOK(p string) bool {
	return strings.HasPrefix(p, "/") && len(p) <= 200 && !strings.ContainsAny(p, "\"'\\\r\n\x00;,?#*") && !strings.Contains(p, "%{") &&
		strings.Trim(p, "/") != ""
}

// criticalRuleFamily is true for the CRS attack families whose rules must not be switched off for a whole
// path (local file inclusion 930, remote file inclusion 931, remote code execution 932, PHP 933,
// generic attacks 934, SQL injection 942, Java 944). For these only the narrow variable form is offered.
func criticalRuleFamily(id int) bool {
	switch id / 1000 {
	case 930, 931, 932, 933, 934, 942, 944:
		return true
	}
	return false
}

// unsafeExclusion returns a code-written explanation when an exclusion action must never be offered,
// whatever the model said. The score-rule predicate is the one the WAF tuning code uses
// (waf.IsScoreRule), and the tuning apply endpoint checks again.
func unsafeExclusion(a ExplainAction, in EventInput) string {
	if a.Type != ActExcludeRuleForPath && a.Type != ActExcludeVariable {
		return ""
	}
	id := strconv.Itoa(a.RuleID)
	if waf.IsScoreRule(a.RuleID) {
		return "Refused: rule " + id + " evaluates the anomaly score and decides whether a request is blocked. Excluding it would disable blocking, so it is never offered."
	}
	if a.Type == ActExcludeRuleForPath {
		if criticalRuleFamily(a.RuleID) {
			return "Refused: rule " + id + " detects code execution, file inclusion or SQL injection. It is not switched off for a whole path; use the variable exclusion instead."
		}
		if in.WAF != nil && !exclusionPathOK(in.WAF.Path) {
			return "Refused: the path " + capRunes(stripInvisible(in.WAF.Path), 60) + " is too broad or not allowed for a path exclusion."
		}
	}
	return ""
}
