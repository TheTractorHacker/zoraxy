package waf

import "testing"

func TestScoreRulePredicates(t *testing.T) {
	for _, id := range []int{949110, 949111, 949000, 949999, 959100, 959999, 980130, 980170} {
		if !IsScoreRule(id) {
			t.Errorf("%d must be a score rule", id)
		}
	}
	for _, id := range []int{0, 942100, 941100, 948999, 950000, 979999, 981000, 920350} {
		if IsScoreRule(id) {
			t.Errorf("%d must not be a score rule", id)
		}
	}
	for spec, want := range map[string]bool{
		"949110": true, " 949110 ": true, "942100": false, "940000-950000": true, "1-999999999": true,
		"949000-949999": true, "941000-941999": false, "980500-981000": true, "950000-958999": false,
		"x": true, "": true, "5-1": true, "-5": true,
	} {
		if SpecTouchesScoreRule(spec) != want {
			t.Errorf("SpecTouchesScoreRule(%q) != %v", spec, want)
		}
	}
}
