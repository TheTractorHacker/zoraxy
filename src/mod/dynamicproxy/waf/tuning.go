package waf

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
)

/*
	tuning.go

	WAF tuning assistant, part 1: variable scoped exclusions.

	A TargetExclusion tells the engine that the given rules must not inspect one
	request variable (one cookie, one argument, one header ...), optionally only
	on one path, instead of switching the rule off for the whole request. It is
	rendered as ctl:ruleRemoveTargetById=<id>;<TARGET> before the CRS is loaded.

	Everything that ends up inside the generated SecLang is validated strictly
	here: the target grammar is a fixed allow-list of collections plus an optional
	":name" or ":/regex/" selector, and no character that could end the quoted
	string or an action is accepted.

	Part 2 (tuning_agg.go) turns stored events into suggestions.
*/

// TargetExclusion removes one request variable from the inspection of some rules.
type TargetExclusion struct {
	RuleIDs []string `json:"RuleIDs"`         // Rule IDs or ranges (e.g. "942290" or "942100-942199")
	Target  string   `json:"Target"`          // COLLECTION, COLLECTION:name or COLLECTION:/regex/ (see targetCollections)
	Path    string   `json:"Path,omitempty"`  // Only for requests on this path ("" = every path)
	Exact   bool     `json:"Exact,omitempty"` // Path must match exactly instead of as a prefix
}

const (
	maxTargetExclusions = 500
	maxTargetRuleIDs    = 100
	maxTargetLen        = 160
	maxTargetRegexLen   = 120
	maxTargetNameLen    = 100
	maxTargetPathLen    = 512
)

// targetCollections are the collections an exclusion may name. The value says whether a ":selector" is allowed.
var targetCollections = map[string]bool{
	"ARGS": true, "ARGS_NAMES": true, "ARGS_GET": true, "ARGS_GET_NAMES": true, "ARGS_POST": true, "ARGS_POST_NAMES": true,
	"REQUEST_COOKIES": true, "REQUEST_COOKIES_NAMES": true,
	"REQUEST_HEADERS": true, "REQUEST_HEADERS_NAMES": true,
	"FILES": true, "FILES_NAMES": true,
	"XML": true,
	// no selector possible
	"REQUEST_URI": false, "REQUEST_URI_RAW": false, "REQUEST_FILENAME": false, "REQUEST_BASENAME": false,
	"REQUEST_BODY": false, "QUERY_STRING": false,
}

// safeNameChars are the characters of a literal selector name
var safeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]$@+~:!]+$`)

// SplitTarget splits "COLLECTION:selector" into its parts. The selector keeps its slashes.
func SplitTarget(target string) (collection, selector string, hasSelector bool) {
	if i := strings.IndexByte(target, ':'); i >= 0 {
		return target[:i], target[i+1:], true
	}
	return target, "", false
}

// ValidateTarget checks a target against the grammar documented on TargetExclusion.
func ValidateTarget(target string) error {
	if target == "" || len(target) > maxTargetLen {
		return fmt.Errorf("invalid exclusion target (1 to %d characters)", maxTargetLen)
	}
	for i := 0; i < len(target); i++ {
		c := target[i]
		if c < 0x20 || c > 0x7e {
			return fmt.Errorf("invalid exclusion target %q: only printable ASCII is allowed", target)
		}
	}
	if strings.ContainsAny(target, ",;\"'") || strings.Contains(target, "%{") {
		return fmt.Errorf("invalid exclusion target %q: commas, semicolons, quotes and macros are not allowed", target)
	}
	coll, sel, has := SplitTarget(target)
	allowSel, known := targetCollections[coll]
	if !known {
		return fmt.Errorf("invalid exclusion target %q: unknown collection %q", target, coll)
	}
	if !has {
		return nil
	}
	if !allowSel {
		return fmt.Errorf("invalid exclusion target %q: %s takes no selector", target, coll)
	}
	if sel == "" {
		return fmt.Errorf("invalid exclusion target %q: empty selector", target)
	}
	if coll == "XML" && sel == "/*" {
		return nil
	}
	if strings.HasPrefix(sel, "/") {
		if len(sel) < 3 || !strings.HasSuffix(sel, "/") {
			return fmt.Errorf("invalid exclusion target %q: a regular expression selector must look like /regex/", target)
		}
		pat := sel[1 : len(sel)-1]
		if len(pat) > maxTargetRegexLen {
			return fmt.Errorf("invalid exclusion target: regular expression longer than %d characters", maxTargetRegexLen)
		}
		// Coraza treats /foo\/ as a literal, never as a regex: refuse an odd trailing backslash run
		bs := 0
		for i := len(pat) - 1; i >= 0 && pat[i] == '\\'; i-- {
			bs++
		}
		if bs%2 == 1 {
			return fmt.Errorf("invalid exclusion target %q: regular expression ends with a backslash", target)
		}
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("invalid exclusion target regular expression: %v", err)
		}
		return nil
	}
	if len(sel) > maxTargetNameLen || !safeNamePattern.MatchString(sel) {
		return fmt.Errorf("invalid exclusion target %q: the name may only contain letters, digits and _ . - [ ] $ @ + ~ : ! (use a /regex/ otherwise)", target)
	}
	return nil
}

func validateTargetExclusions(list []TargetExclusion) error {
	if len(list) > maxTargetExclusions {
		return fmt.Errorf("too many variable exclusions (max %d)", maxTargetExclusions)
	}
	for _, te := range list {
		if err := te.validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks one exclusion
func (te TargetExclusion) Validate() error { return te.validate() }

func (te TargetExclusion) validate() error {
	if len(te.RuleIDs) == 0 {
		return fmt.Errorf("variable exclusion for %q has no rule IDs", te.Target)
	}
	if len(te.RuleIDs) > maxTargetRuleIDs {
		return fmt.Errorf("variable exclusion has too many rule IDs (max %d)", maxTargetRuleIDs)
	}
	for _, id := range te.RuleIDs {
		if !ruleIDPattern.MatchString(strings.TrimSpace(id)) {
			return fmt.Errorf("invalid rule ID %q", id)
		}
	}
	if err := ValidateTarget(te.Target); err != nil {
		return err
	}
	if te.Path != "" {
		if !strings.HasPrefix(te.Path, "/") || len(te.Path) > maxTargetPathLen || strings.ContainsAny(te.Path, "\"'\\\r\n\x00;,") || strings.Contains(te.Path, "%{") {
			return fmt.Errorf("invalid exclusion path %q (must start with / and not contain quotes, backslashes, commas or semicolons)", te.Path)
		}
	}
	return nil
}

func (te TargetExclusion) key() string {
	return strings.ToLower(te.Target) + "|" + te.Path + "|" + fmt.Sprint(te.Exact)
}

// dedupeTargetExclusions merges entries with the same target and path, so the compiled rule set (and its cache
// key) does not depend on how often an exclusion was added. The input is not modified.
func dedupeTargetExclusions(in []TargetExclusion) []TargetExclusion {
	if len(in) == 0 {
		return in
	}
	idx := map[string]int{}
	var out []TargetExclusion
	for _, te := range in {
		k := te.key()
		if i, ok := idx[k]; ok {
			out[i].RuleIDs = dedupe(append(append([]string(nil), out[i].RuleIDs...), te.RuleIDs...))
			continue
		}
		te.RuleIDs = dedupe(append([]string(nil), te.RuleIDs...))
		idx[k] = len(out)
		out = append(out, te)
	}
	return out
}

// AddTargetExclusion adds te to the list, merging rule IDs into an existing entry for the same target and path.
func AddTargetExclusion(list []TargetExclusion, te TargetExclusion) []TargetExclusion {
	return dedupeTargetExclusions(append(append([]TargetExclusion(nil), list...), te))
}

// writeTargetExclusions renders the exclusions and returns the next free generated rule ID
func writeTargetExclusions(b *strings.Builder, list []TargetExclusion, id int) int {
	for _, te := range list {
		var ctls []string
		for _, rid := range te.RuleIDs {
			ctls = append(ctls, "ctl:ruleRemoveTargetById="+strings.TrimSpace(rid)+";"+te.Target)
		}
		if te.Path == "" {
			fmt.Fprintf(b, "SecAction \"id:%d,phase:1,pass,nolog,%s\"\n", id, strings.Join(ctls, ","))
		} else {
			op := "@beginsWith"
			if te.Exact {
				op = "@streq"
			}
			fmt.Fprintf(b, "SecRule REQUEST_FILENAME \"%s %s\" \"id:%d,phase:1,pass,nolog,%s\"\n", op, te.Path, id, strings.Join(ctls, ","))
		}
		id++
	}
	return id
}

/*
	Matched variable of a rule hit
*/

// normCollection folds the split GET / POST collections into the one the CRS rules name
func normCollection(c string) string {
	switch c {
	case "ARGS_GET", "ARGS_POST":
		return "ARGS"
	case "ARGS_GET_NAMES", "ARGS_POST_NAMES":
		return "ARGS_NAMES"
	}
	return c
}

// matchedVariable returns the first request variable a rule matched, as "COLLECTION:key" and its normalised form
func matchedVariable(mr types.MatchedRule) (variable, norm string) {
	for _, md := range mr.MatchedDatas() {
		coll := md.Variable().Name()
		if coll == "" || coll == "TX" || coll == "UNKNOWN" {
			continue
		}
		key := md.Key()
		if len(key) > maxTargetNameLen {
			key = key[:maxTargetNameLen]
		}
		variable, norm = coll, normCollection(coll)
		if key != "" {
			variable += ":" + key
			norm += ":" + strings.ToLower(key)
		}
		return variable, norm
	}
	return "", ""
}
