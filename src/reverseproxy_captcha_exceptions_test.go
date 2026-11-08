package main

import (
	"net/url"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
)

// Editing an endpoint rebuilds the CAPTCHA config from form fields, which do
// not carry the exception rules; they must survive the save (fork #200).
func TestEditKeepsCaptchaExceptionRules(t *testing.T) {
	old := &captcha.Config{
		ExceptionRules: []*captcha.ExceptionRule{
			{RuleType: captcha.ExceptionTypePaths, PathPrefix: "/api"},
			{RuleType: captcha.ExceptionTypeCIDR, CIDR: "10.0.0.0/8"},
		},
	}
	form := url.Values{"captcha": {"true"}, "captchaProvider": {"1"}, "captchaSiteKey": {"k"}, "captchaSecretKey": {"s"}}
	cfg, err := parseCaptchaConfigFromRequest(authProviderForm(form))
	if err != nil || cfg == nil {
		t.Fatalf("parse: %v", err)
	}
	preserveCaptchaExceptionRules(cfg, old)
	if len(cfg.ExceptionRules) != 2 || cfg.ExceptionRules[0].PathPrefix != "/api" || cfg.ExceptionRules[1].CIDR != "10.0.0.0/8" {
		t.Fatalf("exception rules lost: %+v", cfg.ExceptionRules)
	}
	//the preserved slice must not alias the old config
	cfg.ExceptionRules[0] = nil
	if old.ExceptionRules[0] == nil {
		t.Error("exception rules share memory with the old config")
	}
	//nil on either side must not panic
	preserveCaptchaExceptionRules(nil, old)
	preserveCaptchaExceptionRules(cfg, nil)
}

func TestCaptchaExceptionRuleAddRemove(t *testing.T) {
	cfg := &captcha.Config{}
	adds := []struct {
		typ   int
		value string
		ok    bool
	}{
		{0, "public/", true},         //normalised to /public
		{0, "/public", false},        //duplicate after normalisation
		{0, "  ", false},             //empty
		{1, "192.168.1.0/24", true},  //CIDR
		{1, "2001:db8::1", true},     //single IPv6
		{1, "10.0.0.1", true},        //single IPv4
		{1, "not-an-ip", false},      //garbage
		{1, "10.0.0.0/33", false},    //bad prefix
		{1, "192.168.1.0/24", false}, //duplicate
		{7, "x", false},              //unknown type
	}
	for _, a := range adds {
		err := addCaptchaExceptionRule(cfg, a.typ, a.value)
		if (err == nil) != a.ok {
			t.Errorf("add(%d,%q): err=%v, want ok=%v", a.typ, a.value, err, a.ok)
		}
	}
	if len(cfg.ExceptionRules) != 4 || cfg.ExceptionRules[0].PathPrefix != "/public" {
		t.Fatalf("unexpected rules: %+v", cfg.ExceptionRules)
	}
	if err := removeCaptchaExceptionRule(cfg, 0, "/public/"); err != nil {
		t.Fatalf("remove normalised path: %v", err)
	}
	if err := removeCaptchaExceptionRule(cfg, 1, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if removeCaptchaExceptionRule(cfg, 1, "10.0.0.1") == nil {
		t.Error("removing a missing rule must fail")
	}
	if len(cfg.ExceptionRules) != 2 {
		t.Fatalf("rules left: %+v", cfg.ExceptionRules)
	}
}
