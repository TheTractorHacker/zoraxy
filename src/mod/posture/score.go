package posture

import (
	"fmt"
	"math"
	"sort"
)

/*
	Score

	  applicable = sum of the weights of the checks whose status is ok, warn, fail or unknown
	               (not-applicable checks are left out of everything)
	  cost       = ok 0, warn 0.5, unknown 0.5, fail 1  (of the check's weight)
	  lost(c)    = cost(c) * weight(c) / applicable * 100        points
	  raw        = 100 - sum(lost)

	An unknown check costs as much as a warning: "we could not prove it" is not "fine".
	Two caps keep the number honest:
	  - while a check marked Critical fails, the score is at most CriticalCap (69)
	  - when unknown checks carry more than UnknownLimit (25%) of the applicable weight the score is
	    "provisional": it is capped at CriticalCap, gets no letter grade and the label says "Incomplete".

	Grades: A >= 90 Strong, B >= 80 Good, C >= 65 Fair, D >= 50 Weak, otherwise F At risk.
*/

const (
	// CriticalCap is the highest score while a critical check fails or the result is provisional
	CriticalCap = 69
	// UnknownLimit is the share of the applicable weight that may be unknown before the score is provisional
	UnknownLimit = 0.25
)

// FormulaText is shown in the UI next to the score
const FormulaText = "Every applicable check has a weight. A failed check loses its whole share of the 100 points, a warning and an unknown check lose half of it, " +
	"a passed check loses nothing. Checks that do not apply to your setup are left out. While a critical check fails, the score cannot exceed 69. " +
	"If more than a quarter of the weight is unknown the score is marked incomplete and cannot exceed 69 either."

// Loss is one line of the "points lost" breakdown
type Loss struct {
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	Status Status  `json:"status"`
	Points float64 `json:"points"`
}

// Score is the transparent result
type Score struct {
	Value        int            `json:"value"`
	Raw          float64        `json:"raw"` // before caps
	Grade        string         `json:"grade"`
	Label        string         `json:"label"`
	Provisional  bool           `json:"provisional"`
	Capped       bool           `json:"capped"`
	CapReason    string         `json:"capReason,omitempty"`
	Applicable   int            `json:"applicableWeight"`
	UnknownShare float64        `json:"unknownShare"`
	Lost         float64        `json:"lost"`
	Losses       []Loss         `json:"losses"`
	Counts       map[Status]int `json:"counts"`
	Formula      string         `json:"formula"`
}

func cost(s Status) float64 {
	switch s {
	case StatusFail:
		return 1
	case StatusWarn, StatusUnknown:
		return 0.5
	}
	return 0
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// Compute scores a set of evaluated checks. LostPoints of each result is filled in.
func Compute(results []CheckResult) Score {
	s := Score{Formula: FormulaText, Counts: map[Status]int{}, Losses: []Loss{}}
	applicable, unknownW := 0, 0
	criticalFail := ""
	for _, r := range results {
		s.Counts[r.Status]++
		switch r.Status {
		case StatusNA:
		default:
			applicable += r.Weight
			if r.Status == StatusUnknown {
				unknownW += r.Weight
			}
			if r.Status == StatusFail && r.Critical && criticalFail == "" {
				criticalFail = r.Title
			}
		}
	}
	s.Applicable = applicable
	if applicable == 0 {
		s.Value, s.Raw, s.Grade, s.Label, s.Provisional = 0, 0, "?", "Nothing to assess", true
		return s
	}
	lost := 0.0
	for i := range results {
		r := &results[i]
		r.LostPoints = 0
		if r.Status == StatusNA {
			continue
		}
		if c := cost(r.Status); c > 0 {
			r.LostPoints = round1(c * float64(r.Weight) / float64(applicable) * 100)
			lost += c * float64(r.Weight) / float64(applicable) * 100
			s.Losses = append(s.Losses, Loss{ID: r.ID, Title: r.Title, Status: r.Status, Points: r.LostPoints})
		}
	}
	sort.SliceStable(s.Losses, func(i, j int) bool { return s.Losses[i].Points > s.Losses[j].Points })
	s.Lost = round1(lost)
	s.Raw = round1(100 - lost)
	s.UnknownShare = round1(float64(unknownW)/float64(applicable)*1000) / 10 // percent, one decimal
	v := int(math.Round(100 - lost))
	if v < 0 {
		v = 0
	}
	if criticalFail != "" && v > CriticalCap {
		v, s.Capped, s.CapReason = CriticalCap, true, fmt.Sprintf("capped at %d while \"%s\" fails", CriticalCap, criticalFail)
	}
	if float64(unknownW)/float64(applicable) > UnknownLimit {
		s.Provisional = true
		if v > CriticalCap {
			v, s.Capped = CriticalCap, true
			s.CapReason = fmt.Sprintf("capped at %d because %.0f%% of the checks could not be determined", CriticalCap, s.UnknownShare)
		}
	}
	s.Value = v
	switch {
	case s.Provisional:
		s.Grade, s.Label = "?", "Incomplete"
	case v >= 90:
		s.Grade, s.Label = "A", "Strong"
	case v >= 80:
		s.Grade, s.Label = "B", "Good"
	case v >= 65:
		s.Grade, s.Label = "C", "Fair"
	case v >= 50:
		s.Grade, s.Label = "D", "Weak"
	default:
		s.Grade, s.Label = "F", "At risk"
	}
	return s
}
