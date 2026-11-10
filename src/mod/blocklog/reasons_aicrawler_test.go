package blocklog

import "testing"

func TestClassifyAICrawler(t *testing.T) {
	for ft, want := range map[string]string{
		"aicrawler-blocked":               "blocked",
		"aicrawler-spoofed":               "spoofed",
		"aicrawler-ratelimited":           "ratelimited",
		"aicrawler-challenge":             "challenge",
		"aicrawler-challenge-unavailable": "challenge-unavailable",
	} {
		reason, detail, ok := Classify(ft)
		if !ok || reason != ReasonAICrawler || detail != want {
			t.Errorf("%s: %q %q %v", ft, reason, detail, ok)
		}
		if !IsBlocked(ft) {
			t.Errorf("%s must count as blocked", ft)
		}
	}
	// log-only decisions went through
	for _, ft := range []string{"aicrawler-blocked-logonly", "aicrawler-spoofed-logonly"} {
		if IsBlocked(ft) {
			t.Errorf("%s must not count as blocked", ft)
		}
	}
	found := false
	for _, r := range Reasons() {
		if r.Key == ReasonAICrawler && r.Tab == "aicrawlers" {
			found = true
		}
	}
	if !found {
		t.Error("the reason list must explain the AI crawler policy and link to its page")
	}
}
