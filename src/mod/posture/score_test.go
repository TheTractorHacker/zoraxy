package posture

import (
	"math"
	"strings"
	"testing"
)

func cr(id string, w int, st Status) CheckResult {
	return CheckResult{ID: id, Title: id, Weight: w, Status: st}
}

func TestScoreArithmetic(t *testing.T) {
	// weights 10 + 10 + 20 + 60 = 100 applicable
	res := []CheckResult{cr("a", 10, StatusFail), cr("b", 10, StatusWarn), cr("c", 20, StatusOK), cr("d", 60, StatusOK)}
	s := Compute(res)
	// lost: 10 (fail) + 5 (warn) = 15
	if s.Value != 85 || s.Lost != 15 || s.Grade != "B" || s.Label != "Good" {
		t.Fatalf("%+v", s)
	}
	if res[0].LostPoints != 10 || res[1].LostPoints != 5 || res[2].LostPoints != 0 {
		t.Fatalf("per check points: %v %v %v", res[0].LostPoints, res[1].LostPoints, res[2].LostPoints)
	}
	if len(s.Losses) != 2 || s.Losses[0].ID != "a" {
		t.Fatalf("losses not sorted by size: %+v", s.Losses)
	}
	sum := 0.0
	for _, l := range s.Losses {
		sum += l.Points
	}
	if math.Abs(sum-s.Lost) > 0.11 {
		t.Fatalf("breakdown %.1f does not add up to %.1f", sum, s.Lost)
	}
}

func TestScoreNotApplicableIsIgnored(t *testing.T) {
	a := Compute([]CheckResult{cr("a", 5, StatusOK), cr("b", 5, StatusFail)})
	b := Compute([]CheckResult{cr("a", 5, StatusOK), cr("b", 5, StatusFail), cr("n", 9, StatusNA), cr("m", 9, StatusNA)})
	if a.Value != b.Value || a.Applicable != b.Applicable {
		t.Fatalf("not-applicable checks changed the score: %d vs %d", a.Value, b.Value)
	}
	if b.Counts[StatusNA] != 2 {
		t.Fatalf("counts: %v", b.Counts)
	}
}

func TestScoreAllNotApplicable(t *testing.T) {
	s := Compute([]CheckResult{cr("n", 5, StatusNA)})
	if s.Label != "Nothing to assess" || !s.Provisional || s.Grade != "?" {
		t.Fatalf("%+v", s)
	}
	s = Compute(nil)
	if s.Label != "Nothing to assess" {
		t.Fatalf("%+v", s)
	}
}

func TestScoreUnknownIsNotFree(t *testing.T) {
	// 80 ok, 20 unknown: unknown costs half => 90, exactly at the 25% limit => not provisional
	s := Compute([]CheckResult{cr("a", 80, StatusOK), cr("u", 20, StatusUnknown)})
	if s.Value != 90 || s.Provisional || s.Grade != "A" {
		t.Fatalf("%+v", s)
	}
	// an all-ok result of the same weight scores higher
	if o := Compute([]CheckResult{cr("a", 80, StatusOK), cr("u", 20, StatusOK)}); o.Value <= s.Value {
		t.Fatal("unknown must cost points")
	}
}

func TestScoreTooManyUnknownIsProvisionalAndNeverHigh(t *testing.T) {
	// everything that is known is perfect, but 40% is unknown
	s := Compute([]CheckResult{cr("a", 60, StatusOK), cr("u", 40, StatusUnknown)})
	if !s.Provisional || s.Grade != "?" || s.Label != "Incomplete" {
		t.Fatalf("%+v", s)
	}
	if s.Value > CriticalCap || !s.Capped || !strings.Contains(s.CapReason, "could not be determined") {
		t.Fatalf("a provisional score must be capped: %+v", s)
	}
	// all unknown
	s = Compute([]CheckResult{cr("u", 10, StatusUnknown), cr("v", 10, StatusUnknown)})
	if s.Value > 50 || !s.Provisional {
		t.Fatalf("%+v", s)
	}
}

func TestScoreCriticalCap(t *testing.T) {
	c := cr("admin.auth", 10, StatusFail)
	c.Critical, c.Title = true, "Admin interface requires a login"
	s := Compute([]CheckResult{c, cr("a", 90, StatusOK)})
	// 10 points lost -> 90, capped at 69
	if s.Value != CriticalCap || !s.Capped || s.Grade != "C" || !strings.Contains(s.CapReason, "Admin interface requires a login") {
		t.Fatalf("%+v", s)
	}
	// a critical check that passes does not cap
	c.Status = StatusOK
	if s := Compute([]CheckResult{c, cr("a", 90, StatusOK)}); s.Value != 100 || s.Capped {
		t.Fatalf("%+v", s)
	}
	// a critical warning does not cap either
	c.Status = StatusWarn
	if s := Compute([]CheckResult{c, cr("a", 90, StatusOK)}); s.Capped {
		t.Fatalf("%+v", s)
	}
}

func TestScoreGradeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		lost  int
		grade string
	}{{0, "A"}, {10, "A"}, {11, "B"}, {20, "B"}, {21, "C"}, {35, "C"}, {36, "D"}, {50, "D"}, {51, "F"}, {100, "F"}} {
		s := Compute([]CheckResult{cr("x", tc.lost, StatusFail), cr("y", 100-tc.lost, StatusOK)})
		if tc.lost == 100 {
			s = Compute([]CheckResult{cr("x", 100, StatusFail)})
		}
		if s.Grade != tc.grade {
			t.Errorf("lost %d -> %d %s, want %s", tc.lost, s.Value, s.Grade, tc.grade)
		}
	}
}

func TestScoreRealisticFreshInstance(t *testing.T) {
	f := healthy()
	f.Admin.AuthRequired = true
	f.Abuse.Enabled = false
	setRules(f, func(r *RuleFacts) {
		r.WAFMode = "off"
		r.RateLimit = false
		r.UptimeMonitor = false
		r.HSTSMaxAge = 0
		r.AuthMethod = "none"
		r.BlockExploits = false
	})
	f.WAF.PolicyEnabled = false
	rep := Default.Evaluate(f)
	if rep.Score.Value >= 80 {
		t.Fatalf("a fresh instance with nothing switched on scored %d", rep.Score.Value)
	}
	if rep.Score.Lost <= 0 || len(rep.Score.Losses) < 4 {
		t.Fatalf("%+v", rep.Score)
	}
}
