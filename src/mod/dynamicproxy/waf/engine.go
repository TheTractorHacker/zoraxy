package waf

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
)

/*
	engine.go

	Translates a Config into SecLang directives and compiles them into a
	Coraza WAF using the embedded OWASP Core Rule Set. Only the REQUEST-*
	rule files are loaded: response inspection is not supported.

	The rule file system is the read-only embedded CRS, so no directive
	(including user supplied custom rules) can read from the host disk.
*/

// Generated rule IDs live in this range. Custom rules should use IDs above 1000000.
const generatedRuleIDBase = 190000

const corazaBase = `
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off
SecArgumentsLimit 1000
SecRequestBodyJsonDepthLimit 64
SecRequestBodyLimitAction ProcessPartial
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecAction "id:900990,phase:1,pass,t:none,nolog,tag:'OWASP_CRS',setvar:tx.crs_setup_version=4250"
`

// Content types accepted by CRS rule 920420. Wider than the CRS default
// because a reverse proxy fronts arbitrary applications (APIs, uploads).
const allowedContentTypes = "|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/merge-patch+json| |application/json-patch+json| |application/problem+json| |application/ld+json| |application/vnd.api+json| |application/x-ndjson| |application/csp-report| |application/octet-stream| |text/plain| |application/pdf| |application/zip| |application/gzip| |image/png| |image/jpeg| |image/gif| |image/webp|"

// Cookie names (regular expression, no commas or semicolons) and the CRS rule families that must not
// inspect their values when Config.IgnoreAnalyticsCookies is set.
const analyticsCookieNames = "^(ph_.+_posthog|ph_.+_window_id|_ga(_.+)?|_gid|_gat.*|__utm[a-z]+|_fbp|_fbc|_gcl_.+|_hj.+|mp_.+_mixpanel|ajs_.+|amplitude_.+|_clck|_clsk|_pk_.+|_uet.+|_rdt_uuid|_tt_.+|_ttp)$"

var analyticsCookieTags = []string{"attack-sqli", "attack-xss", "attack-generic", "attack-rce", "attack-injection-php", "attack-lfi"}

func crsRuleFiles() ([]string, error) {
	files, err := fs.Glob(coreruleset.FS, "@owasp_crs/REQUEST-*.conf")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("embedded core rule set not found")
	}
	return files, nil
}

// buildDirectives renders the full SecLang program for the config
func buildDirectives(n Config) (string, error) {
	files, err := crsRuleFiles()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SecRequestBodyLimit %d\nSecRequestBodyInMemoryLimit %d\n", n.MaxBodyBytes, n.MaxBodyBytes)
	b.WriteString(corazaBase)
	fmt.Fprintf(&b, "SecAction \"id:900000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=%d\"\n", n.ParanoiaLevel)
	fmt.Fprintf(&b, "SecAction \"id:900001,phase:1,pass,nolog,t:none,setvar:tx.detection_paranoia_level=%d\"\n", n.ParanoiaLevel)
	b.WriteString("SecAction \"id:900200,phase:1,pass,nolog,t:none,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'\"\n")
	b.WriteString("SecAction \"id:900220,phase:1,pass,nolog,t:none,setvar:'tx.allowed_request_content_type=" + allowedContentTypes + "'\"\n")
	fmt.Fprintf(&b, "SecAction \"id:900110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", n.InboundThreshold)

	// Exclusions must be defined before the rules they remove
	id := generatedRuleIDBase
	if len(n.ExcludedRuleIDs) > 0 {
		var ctls []string
		for _, rid := range n.ExcludedRuleIDs {
			ctls = append(ctls, "ctl:ruleRemoveById="+strings.TrimSpace(rid))
		}
		fmt.Fprintf(&b, "SecAction \"id:%d,phase:1,pass,nolog,%s\"\n", id, strings.Join(ctls, ","))
		id++
	}
	if n.IgnoreAnalyticsCookies {
		var ctls []string
		for _, tag := range analyticsCookieTags {
			ctls = append(ctls, "ctl:ruleRemoveTargetByTag="+tag+";REQUEST_COOKIES:/"+analyticsCookieNames+"/")
		}
		fmt.Fprintf(&b, "SecAction \"id:%d,phase:1,pass,nolog,%s\"\n", id, strings.Join(ctls, ","))
		id++
	}
	for _, pe := range n.PathExclusions {
		var ctls []string
		for _, rid := range pe.RuleIDs {
			ctls = append(ctls, "ctl:ruleRemoveById="+strings.TrimSpace(rid))
		}
		op := "@beginsWith"
		if pe.Exact {
			op = "@streq"
		}
		fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"%s %s\" \"id:%d,phase:1,pass,nolog,%s\"\n", op, pe.Path, id, strings.Join(ctls, ","))
		id++
	}
	id = writeTargetExclusions(&b, n.TargetExclusions, id)

	for _, f := range files {
		fmt.Fprintf(&b, "Include %s\n", f)
	}
	if n.CustomRules != "" {
		b.WriteString("\n")
		b.WriteString(n.CustomRules)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// compile builds a Coraza WAF from the config. Syntax errors in the rules are
// returned as errors; nothing here panics on bad input.
func compile(n Config) (waf coraza.WAF, err error) {
	defer func() {
		if r := recover(); r != nil {
			waf, err = nil, fmt.Errorf("rule compilation failed: %v", r)
		}
	}()
	directives, err := buildDirectives(n)
	if err != nil {
		return nil, err
	}
	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithRequestBodyAccess().
		WithRequestBodyLimit(int(n.MaxBodyBytes)).
		WithRequestBodyInMemoryLimit(int(n.MaxBodyBytes)).
		WithDirectives(directives)
	waf, err = coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid WAF rules: %w", err)
	}
	return waf, nil
}
