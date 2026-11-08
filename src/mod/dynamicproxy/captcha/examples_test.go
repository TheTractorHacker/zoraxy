package captcha

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestShippedExampleTemplatesValidate(t *testing.T) {
	files, err := filepath.Glob("../../../../example/captcha-templates/*.html")
	if err != nil || len(files) < 3 {
		t.Fatalf("expected at least 3 example templates, found %v (%v)", files, err)
	}
	for _, f := range files {
		src, _ := os.ReadFile(f)
		if err := ValidateCustomTemplate(string(src)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		cfg := &Config{Provider: ProviderCloudflare, SiteKey: "k", Branding: &Branding{CustomTemplate: string(src), Heading: "<i>x</i>"}}
		w := render(t, cfg, PageChallenge)
		if strings.Contains(w.Body.String(), "<i>x</i>") || !strings.Contains(w.Body.String(), `id="zx-widget"`) {
			t.Errorf("%s: heading not escaped or widget missing", f)
		}
	}
}

// The admin UI's "Insert starter template" button must insert something that passes validation.
func TestUIStarterTemplateValidates(t *testing.T) {
	html, err := os.ReadFile("../../../web/components/httprp.html")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)CAPTCHA_STARTER_TEMPLATE = `(.*?)`;").FindSubmatch(html)
	if m == nil {
		t.Fatal("starter template not found in httprp.html")
	}
	if err := ValidateCustomTemplate(string(m[1])); err != nil {
		t.Errorf("starter template invalid: %v", err)
	}
}
