package blocklistimport

import (
	"errors"
	"fmt"
	"strings"

	"imuslab.com/zoraxy/mod/access"
)

// Report is the validation / import result shown to the admin. Counts are
// exact; the issue lists are capped at MaxIssuesReported.
type Report struct {
	DryRun          bool     `json:"dryRun"`
	Lines           int      `json:"lines"`
	Accepted        int      `json:"accepted"`       //new entries added (or that would be added)
	Duplicates      int      `json:"duplicates"`     //repeated inside the input
	AlreadyPresent  int      `json:"alreadyPresent"` //already in the list
	Invalid         int      `json:"invalid"`
	Removed         int      `json:"removed"` //stale entries of the same source removed (refresh only)
	Sample          []Entry  `json:"-"`
	SampleValues    []string `json:"sample"`
	InvalidIssues   []Issue  `json:"invalidIssues"`
	DuplicateIssues []Issue  `json:"duplicateIssues"`
	PresentIssues   []Issue  `json:"presentIssues"`
	ListSizeBefore  int      `json:"listSizeBefore"`
	ListSizeAfter   int      `json:"listSizeAfter"`
}

// Tag returns the comment prefix that marks entries added by a source
func Tag(sourceID string) string { return "[src:" + sourceID + "] " }

func hasTag(comment, sourceID string) bool {
	return strings.HasPrefix(comment, "[src:"+sourceID+"]")
}

// ErrWouldEmpty is returned when a refresh would remove every entry of a source
// because the download contained no valid entry (broken upstream, HTML error page, ...)
var ErrWouldEmpty = errors.New("refusing to replace the source's entries with an empty list")

func kindOf(list string) (access.IPListKind, error) {
	switch list {
	case "blacklist":
		return access.IPListBlack, nil
	case "whitelist":
		return access.IPListWhite, nil
	}
	return 0, errors.New("list must be blacklist or whitelist")
}

// plan classifies the parsed input against the current list m. When mutate
// is true m is modified (adds and, for a source, stale removals).
// sourceID == "" is a one-shot import: entries are not tagged and nothing is removed.
func plan(m map[string]string, p *Parsed, sourceID string, mutate bool) (*Report, error) {
	rep := &Report{
		DryRun: !mutate, Lines: p.Lines, Duplicates: p.DuplicateN, Invalid: p.InvalidN,
		InvalidIssues: p.Invalid, DuplicateIssues: p.Duplicates, PresentIssues: []Issue{},
		ListSizeBefore: len(m),
	}
	fresh := make(map[string]struct{}, len(p.Entries))
	for _, e := range p.Entries {
		fresh[e.Value] = struct{}{}
	}

	var stale []string
	if sourceID != "" {
		tagged := 0
		for k, c := range m {
			if hasTag(c, sourceID) {
				tagged++
				if _, ok := fresh[k]; !ok {
					stale = append(stale, k)
				}
			}
		}
		if tagged > 0 && len(p.Entries) == 0 {
			return nil, ErrWouldEmpty
		}
	}

	for _, e := range p.Entries {
		if cur, ok := m[e.Value]; ok {
			if sourceID != "" && hasTag(cur, sourceID) {
				continue //unchanged, owned by this source
			}
			rep.AlreadyPresent++
			if len(rep.PresentIssues) < MaxIssuesReported {
				rep.PresentIssues = append(rep.PresentIssues, Issue{e.Line, e.Value, "already in the list"})
			}
			continue
		}
		rep.Accepted++
		if len(rep.SampleValues) < 20 {
			rep.SampleValues = append(rep.SampleValues, e.Value)
		}
		if mutate {
			c := e.Comment
			if sourceID != "" {
				c = strings.TrimSpace(Tag(sourceID) + c)
			}
			m[e.Value] = c
		}
	}
	rep.Removed = len(stale)
	if mutate {
		for _, k := range stale {
			delete(m, k)
		}
	}
	rep.ListSizeAfter = len(m)
	if !mutate {
		rep.ListSizeAfter = len(m) + rep.Accepted - rep.Removed
	}
	return rep, nil
}

// Preview is the dry run: nothing is changed
func Preview(rule *access.AccessRule, list string, p *Parsed, sourceID string) (*Report, error) {
	kind, err := kindOf(list)
	if err != nil {
		return nil, err
	}
	return plan(rule.IPListSnapshot(kind), p, sourceID, false)
}

// Apply imports the parsed entries into the rule's list with one save
func Apply(rule *access.AccessRule, list string, p *Parsed, sourceID string) (*Report, error) {
	kind, err := kindOf(list)
	if err != nil {
		return nil, err
	}
	var rep *Report
	err = rule.BulkEditIPList(kind, func(m map[string]string) error {
		var perr error
		rep, perr = plan(m, p, sourceID, true)
		return perr
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// RemoveSourceEntries deletes every entry tagged with the source id
func RemoveSourceEntries(rule *access.AccessRule, list, sourceID string) (int, error) {
	kind, err := kindOf(list)
	if err != nil {
		return 0, err
	}
	n := 0
	err = rule.BulkEditIPList(kind, func(m map[string]string) error {
		for k, c := range m {
			if hasTag(c, sourceID) {
				delete(m, k)
				n++
			}
		}
		return nil
	})
	return n, err
}

// CountSourceEntries counts the entries tagged with the source id
func CountSourceEntries(rule *access.AccessRule, list, sourceID string) int {
	kind, err := kindOf(list)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range rule.IPListSnapshot(kind) {
		if hasTag(c, sourceID) {
			n++
		}
	}
	return n
}

func (r *Report) String() string {
	return fmt.Sprintf("accepted=%d duplicates=%d present=%d invalid=%d removed=%d", r.Accepted, r.Duplicates, r.AlreadyPresent, r.Invalid, r.Removed)
}
