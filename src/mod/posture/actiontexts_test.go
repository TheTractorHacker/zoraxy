package posture

import (
	"strings"
	"testing"
)

// With the WAF already on in Block mode the action must not read like "turn on detection-only mode".
func TestWAFBaselineTextWhenWAFAlreadyOn(t *testing.T) {
	v := newEnv()
	v.b.state["waf.enabled"] = "on"
	v.b.state["waf.mode"] = "block"
	p := previewHash(t, v, "waf.baseline")
	if len(p.Changes) != 2 {
		t.Fatalf("only paranoia and threshold are missing: %+v", p.Changes)
	}
	if strings.Contains(strings.ToLower(p.Title), "detection-only") || !strings.Contains(p.Description, "Block") {
		t.Fatalf("title and description must say the mode stays as it is: %q / %q", p.Title, p.Description)
	}
	// a fresh instance keeps the static wording
	if q := previewHash(t, newEnv(), "waf.baseline"); !strings.Contains(q.Title, "detection-only") {
		t.Fatalf("fresh instance: %q", q.Title)
	}
}

// The apply result and the preview name the auto-ban detectors in words, never by id.
func TestAutoBanChangeLabelsAreReadable(t *testing.T) {
	v := newEnv()
	p := previewHash(t, v, "autoban.enable")
	for _, c := range p.Changes {
		if strings.Contains(c.Label, "_") {
			t.Errorf("raw id in label %q", c.Label)
		}
	}
}

func TestCertStateTextIsASentence(t *testing.T) {
	for _, s := range []string{"missing", "fallback", "mismatch", "expired", "selfsigned"} {
		if got := certStateText(s); strings.Contains(got, "is "+s) || got == s {
			t.Errorf("%s -> %q", s, got)
		}
	}
}
