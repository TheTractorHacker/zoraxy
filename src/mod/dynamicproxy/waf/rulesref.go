package waf

import (
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

/*
	rulesref.go

	Rule ID -> description reference built from the embedded CRS files, for the
	"Rules reference" page and for labelling events.
*/

// RuleInfo describes one CRS rule
type RuleInfo struct {
	ID       int      `json:"id"`
	Message  string   `json:"msg"`
	Category string   `json:"category"` // CRS file group, e.g. "SQL Injection"
	Paranoia int      `json:"paranoia"` // 0 when not specified
	Severity string   `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

var (
	refOnce sync.Once
	refList []RuleInfo
	refIdx  map[int]RuleInfo

	reRuleID   = regexp.MustCompile(`\bid:(\d+)`)
	reRuleMsg  = regexp.MustCompile(`\bmsg:'([^']*)'`)
	reRuleTag  = regexp.MustCompile(`\btag:'([^']*)'`)
	reRuleSev  = regexp.MustCompile(`\bseverity:'?([A-Za-z]+)'?`)
	reParanoia = regexp.MustCompile(`^paranoia-level/(\d)$`)
	reFileName = regexp.MustCompile(`REQUEST-\d+-([A-Z0-9-]+?)\.conf$`)
)

func loadRuleRef() {
	refIdx = map[int]RuleInfo{}
	files, err := crsRuleFiles()
	if err != nil {
		return
	}
	for _, f := range files {
		raw, err := fs.ReadFile(coreruleset.FS, f)
		if err != nil {
			continue
		}
		category := ""
		if m := reFileName.FindStringSubmatch(f); m != nil {
			category = strings.Title(strings.ToLower(strings.ReplaceAll(m[1], "-", " "))) //nolint:staticcheck
		}
		// Join backslash continued lines into logical directives
		text := strings.ReplaceAll(string(raw), "\\\r\n", " ")
		text = strings.ReplaceAll(text, "\\\n", " ")
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "SecRule") && !strings.HasPrefix(line, "SecAction") {
				continue
			}
			idm := reRuleID.FindStringSubmatch(line)
			if idm == nil {
				continue
			}
			id, _ := strconv.Atoi(idm[1])
			msg := ""
			if m := reRuleMsg.FindStringSubmatch(line); m != nil {
				msg = m[1]
			}
			if msg == "" || id < 910000 {
				continue // bookkeeping / setup rule
			}
			info := RuleInfo{ID: id, Message: msg, Category: category}
			if m := reRuleSev.FindStringSubmatch(line); m != nil {
				info.Severity = strings.ToUpper(m[1])
			}
			for _, t := range reRuleTag.FindAllStringSubmatch(line, -1) {
				if pm := reParanoia.FindStringSubmatch(t[1]); pm != nil {
					info.Paranoia, _ = strconv.Atoi(pm[1])
				} else if strings.HasPrefix(t[1], "attack-") {
					info.Tags = append(info.Tags, t[1])
				}
			}
			if _, dup := refIdx[id]; !dup {
				refIdx[id] = info
				refList = append(refList, info)
			}
		}
	}
	sort.Slice(refList, func(i, j int) bool { return refList[i].ID < refList[j].ID })
}

// RuleReference returns every documented CRS request rule, sorted by ID
func RuleReference() []RuleInfo {
	refOnce.Do(loadRuleRef)
	return refList
}

// LookupRule returns the description of a rule ID, if known
func LookupRule(id int) (RuleInfo, bool) {
	refOnce.Do(loadRuleRef)
	r, ok := refIdx[id]
	return r, ok
}
