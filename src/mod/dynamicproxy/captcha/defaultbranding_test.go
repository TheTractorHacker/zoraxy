package captcha

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultBrandingMerge(t *testing.T) {
	t.Cleanup(func() { SetDefaultBranding(nil) })
	if got := ApplyDefaultBranding(nil); got != nil {
		t.Fatal("no default must leave a nil config alone")
	}
	SetDefaultBranding(&Branding{Title: "Global title", AccentColor: "#112233", HideFooter: true})
	cfg := &Config{Branding: &Branding{Title: "Rule title"}}
	m := ApplyDefaultBranding(cfg)
	if m.Branding.Title != "Rule title" || m.Branding.AccentColor != "#112233" || !m.Branding.HideFooter {
		t.Fatalf("merge wrong: %+v", m.Branding)
	}
	if cfg.Branding.AccentColor != "" {
		t.Fatal("the stored config must not be modified")
	}
	if ApplyDefaultBranding(nil).Branding.Title != "Global title" {
		t.Fatal("nil config must get the default")
	}
	w := httptest.NewRecorder()
	RenderBlocked(w, httptest.NewRequest("GET", "/", nil), &Config{}, "example.com")
	if !strings.Contains(w.Body.String(), "#112233") {
		t.Fatal("rendered page does not use the default accent")
	}
}
