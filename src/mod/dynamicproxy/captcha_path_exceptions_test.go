package dynamicproxy

import (
	"net/http/httptest"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
)

// Path exemptions (prefix, exact, regex) behave the same for every CAPTCHA provider (fork #222).
func TestCaptchaPathExemptionsForEveryProvider(t *testing.T) {
	providers := map[string]captcha.Provider{
		"turnstile": captcha.ProviderCloudflare, "recaptcha": captcha.ProviderGoogle,
		"altcha": captcha.ProviderAltcha, "friendly": captcha.ProviderFriendly,
	}
	rules := []*captcha.ExceptionRule{
		{RuleType: captcha.ExceptionTypePaths, PathPrefix: "/public"},
		{RuleType: captcha.ExceptionTypePaths, PathPrefix: "/healthz", MatchMode: captcha.ExceptionMatchExact},
		{RuleType: captcha.ExceptionTypePaths, PathPrefix: `/hooks/[a-z]+`, MatchMode: captcha.ExceptionMatchRegex},
	}
	exempt := []string{"/public/app.css", "/healthz", "/hooks/github"}
	challenged := []string{"/", "/admin", "/healthz/x", "/hooks/github/x", "/hooks/../admin", "/public/../admin",
		"/healthz/../admin", "/hooks/%2e%2e/admin", "/publicity"}

	for name, prov := range providers {
		t.Run(name, func(t *testing.T) {
			router := newTestCaptchaRouter(t, false)
			ep := newTestCaptchaEndpoint("")
			ep.CaptchaConfig.Provider = prov
			ep.CaptchaConfig.ExceptionRules = rules
			for _, target := range exempt {
				r := newTestRequest("203.0.113.5:44321", nil)
				r.RequestURI = target
				if handled, ch := router.handleCaptchaGating(httptest.NewRecorder(), r, ep); handled || ch {
					t.Errorf("%s was challenged although exempt", target)
				}
			}
			for _, target := range challenged {
				r := newTestRequest("203.0.113.5:44321", nil)
				r.RequestURI = target
				if _, ch := router.handleCaptchaGating(httptest.NewRecorder(), r, ep); !ch {
					t.Errorf("%s skipped the challenge", target)
				}
			}
		})
	}
}
