// Package posture computes the security posture of a Zoraxy instance: a list of
// evidence based checks, a transparent 0-100 score and a small set of safe,
// previewable, reversible fixes.
//
// The package never reads Zoraxy state by itself. The host (src/posture_glue.go)
// gathers a Facts snapshot and implements the Backend that applies settings, which
// keeps every check and every action testable with plain fakes.
//
// What the checks are, how the score is computed and the rules every action must
// follow are documented in DEVELOPMENT.md ("Security posture").
package posture

import "time"

// Status of one check
type Status string

const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusNA      Status = "not-applicable" // nothing to inspect (e.g. no proxy rules); not counted
	StatusUnknown Status = "unknown"        // the state could not be determined; never treated as ok
	StatusInfo    Status = "info"           // a hint with no pass / fail verdict and no fix; not counted in the score
)

// Category groups checks in the UI
type Category string

const (
	CatExposure Category = "Exposure"
	CatWeb      Category = "Web attacks"
	CatAbuse    Category = "Abuse"
	CatAuth     Category = "Authentication"
	CatCerts    Category = "Certificates & TLS"
	CatOps      Category = "Operations"
)

// Categories in display order
var Categories = []Category{CatExposure, CatWeb, CatAbuse, CatAuth, CatCerts, CatOps}

// Remediation tells the user where to fix a finding
type Remediation struct {
	Label  string `json:"label"`            // e.g. "Open the WAF page"
	Page   string `json:"page,omitempty"`   // menu tab id the admin UI opens (e.g. "waf"); empty = nothing to open (start-up flag)
	Anchor string `json:"anchor,omitempty"` // optional tab inside the page (data-tab value), best effort
	Action string `json:"action,omitempty"` // id of a one-click fix in the action registry
	Href   string `json:"href,omitempty"`   // a standalone page that opens in a new tab (e.g. snippet/notifications.html)
	Hint   string `json:"hint,omitempty"`   // text for fixes that are not in the UI (start-up flags)
}

// Result is what a check returns for a Facts snapshot
type Result struct {
	Status   Status
	Evidence []string // the concrete facts that were looked at
}

// Check is one entry of the registry
type Check struct {
	ID          string
	Title       string
	Category    Category
	Weight      int    // 1..10, share of the score
	Critical    bool   // while it fails, the score is capped (see CriticalCap)
	Why         string // one or two plain sentences: why this matters
	Heuristic   bool   // the finding is a guess by name, not an inspection; labelled in the UI
	Remediation Remediation
	Run         func(f *Facts) Result `json:"-"`
}

// CheckResult is a check together with its evaluation (the API shape)
type CheckResult struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Category    Category    `json:"category"`
	Weight      int         `json:"weight"`
	Severity    string      `json:"severity"`
	Critical    bool        `json:"critical,omitempty"`
	Status      Status      `json:"status"`
	Evidence    []string    `json:"evidence"`
	Why         string      `json:"why"`
	Heuristic   bool        `json:"heuristic,omitempty"`
	Remediation Remediation `json:"remediation"`
	LostPoints  float64     `json:"lostPoints"` // points this check costs in the final score
}

// Severity word for a weight
func Severity(weight int) string {
	switch {
	case weight >= 8:
		return "critical"
	case weight >= 5:
		return "high"
	case weight >= 3:
		return "medium"
	}
	return "low"
}

// Report is one evaluation
type Report struct {
	Generated time.Time     `json:"generated"`
	Score     Score         `json:"score"`
	Checks    []CheckResult `json:"checks"`
	Notes     []string      `json:"notes,omitempty"`
}
