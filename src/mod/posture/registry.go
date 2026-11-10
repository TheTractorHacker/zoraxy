package posture

import (
	"fmt"
	"sync"
	"time"
)

// Registry holds the checks. Other modules add their own with Register.
type Registry struct {
	mu     sync.RWMutex
	checks []Check
	index  map[string]int
}

// NewRegistry returns an empty registry
func NewRegistry() *Registry { return &Registry{index: map[string]int{}} }

// Register adds a check. IDs are unique; a check needs a title, a category, a weight 1..10 and a Run function.
func (r *Registry) Register(c Check) error {
	if c.ID == "" || c.Title == "" || c.Run == nil || c.Weight < 1 || c.Weight > 10 {
		return fmt.Errorf("posture: invalid check %q", c.ID)
	}
	ok := false
	for _, cat := range Categories {
		if cat == c.Category {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("posture: check %s has unknown category %q", c.ID, c.Category)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.index[c.ID]; dup {
		return fmt.Errorf("posture: duplicate check id %s", c.ID)
	}
	r.index[c.ID] = len(r.checks)
	r.checks = append(r.checks, c)
	return nil
}

// MustRegister is Register for init functions
func (r *Registry) MustRegister(c Check) {
	if err := r.Register(c); err != nil {
		panic(err)
	}
}

// Checks returns a copy of the registered checks in registration order
func (r *Registry) Checks() []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Check(nil), r.checks...)
}

// Evaluate runs every check on the snapshot and scores the result. A check that panics is reported as unknown.
func (r *Registry) Evaluate(f *Facts) Report {
	if f.Now.IsZero() {
		f.Now = time.Now()
	}
	checks := r.Checks()
	out := make([]CheckResult, 0, len(checks))
	for _, c := range checks {
		res := runSafely(c, f)
		if res.Evidence == nil {
			res.Evidence = []string{}
		}
		out = append(out, CheckResult{
			ID: c.ID, Title: c.Title, Category: c.Category, Weight: c.Weight, Severity: Severity(c.Weight),
			Critical: c.Critical, Status: res.Status, Evidence: res.Evidence, Why: c.Why, Heuristic: c.Heuristic,
			Remediation: c.Remediation,
		})
	}
	return Report{Generated: f.Now, Score: Compute(out), Checks: out}
}

func runSafely(c Check, f *Facts) (res Result) {
	defer func() {
		if p := recover(); p != nil {
			res = Result{Status: StatusUnknown, Evidence: []string{fmt.Sprintf("the check failed internally: %v", p)}}
		}
	}()
	res = c.Run(f)
	switch res.Status {
	case StatusOK, StatusWarn, StatusFail, StatusNA, StatusUnknown:
	default:
		res = Result{Status: StatusUnknown, Evidence: []string{"the check returned an invalid status"}}
	}
	return res
}

// Default is the registry used by Zoraxy; the built-in checks register into it in init().
var Default = NewRegistry()

// Register adds a check to the default registry (for other modules)
func Register(c Check) error { return Default.Register(c) }
