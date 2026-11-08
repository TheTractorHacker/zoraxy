package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	CAPTCHA exception rules (path prefixes and IP / CIDR ranges that bypass the
	CAPTCHA challenge).

	The endpoint editor form does not carry the rules, so a normal edit must
	copy them over from the stored config (preserveCaptchaExceptionRules), and
	they are managed through the dedicated /api/proxy/captcha/exceptions/*
	endpoints below.
*/

// preserveCaptchaExceptionRules copies the stored exception rules into a config
// that was rebuilt from form fields.
func preserveCaptchaExceptionRules(newCfg *captcha.Config, oldCfg *captcha.Config) {
	if newCfg == nil || oldCfg == nil {
		return
	}
	newCfg.ExceptionRules = append([]*captcha.ExceptionRule(nil), oldCfg.ExceptionRules...)
}

func normalizeCaptchaExceptionPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// normalizeCaptchaException validates and normalises a rule value for a type
// (EXCEPTION_TYPE_PATH / EXCEPTION_TYPE_IP).
func normalizeCaptchaException(ruleType int, value string) (captcha.ExceptionType, string, error) {
	value = strings.TrimSpace(value)
	switch ruleType {
	case EXCEPTION_TYPE_PATH:
		p := normalizeCaptchaExceptionPath(value)
		if p == "" {
			return 0, "", errors.New("invalid path prefix given")
		}
		return captcha.ExceptionTypePaths, p, nil
	case EXCEPTION_TYPE_IP:
		if _, _, err := net.ParseCIDR(value); err != nil && net.ParseIP(value) == nil {
			return 0, "", errors.New("invalid IP address or CIDR given")
		}
		return captcha.ExceptionTypeCIDR, value, nil
	}
	return 0, "", errors.New("invalid exception type given")
}

func captchaRuleMatches(rule *captcha.ExceptionRule, t captcha.ExceptionType, value string) bool {
	if rule == nil || rule.RuleType != t {
		return false
	}
	if t == captcha.ExceptionTypePaths {
		return normalizeCaptchaExceptionPath(rule.PathPrefix) == value
	}
	return strings.TrimSpace(rule.CIDR) == value
}

// addCaptchaExceptionRule appends a rule, rejecting invalid values and duplicates.
func addCaptchaExceptionRule(cfg *captcha.Config, ruleType int, value string) error {
	t, v, err := normalizeCaptchaException(ruleType, value)
	if err != nil {
		return err
	}
	for _, rule := range cfg.ExceptionRules {
		if captchaRuleMatches(rule, t, v) {
			return errors.New("this rule already exists")
		}
	}
	rule := &captcha.ExceptionRule{RuleType: t}
	if t == captcha.ExceptionTypePaths {
		rule.PathPrefix = v
	} else {
		rule.CIDR = v
	}
	//Build a new slice so concurrent readers never see a half updated one
	cfg.ExceptionRules = append(append([]*captcha.ExceptionRule(nil), cfg.ExceptionRules...), rule)
	return nil
}

// removeCaptchaExceptionRule deletes a rule by type and value.
func removeCaptchaExceptionRule(cfg *captcha.Config, ruleType int, value string) error {
	t, v, err := normalizeCaptchaException(ruleType, value)
	if err != nil {
		return err
	}
	kept := []*captcha.ExceptionRule{}
	found := false
	for _, rule := range cfg.ExceptionRules {
		if captchaRuleMatches(rule, t, v) {
			found = true
			continue
		}
		kept = append(kept, rule)
	}
	if !found {
		return errors.New("target rule not found")
	}
	cfg.ExceptionRules = kept
	return nil
}

// ListProxyCaptchaExceptionRules lists the CAPTCHA exception rules of an endpoint (GET ep).
func ListProxyCaptchaExceptionRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ep, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid ep given")
		return
	}
	targetProxy, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	results := []*captcha.ExceptionRule{}
	if targetProxy.CaptchaConfig != nil && targetProxy.CaptchaConfig.ExceptionRules != nil {
		results = targetProxy.CaptchaConfig.ExceptionRules
	}
	js, _ := json.Marshal(results)
	utils.SendJSONResponse(w, string(js))
}

// modifyProxyCaptchaExceptionRule is the shared add / delete handler body.
// POST: ep, type (0 = path prefix, 1 = IP / CIDR), value.
func modifyProxyCaptchaExceptionRule(w http.ResponseWriter, r *http.Request, mutate func(*captcha.Config, int, string) error) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ep, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Invalid ep given")
		return
	}
	ruleType, err := utils.PostInt(r, "type")
	if err != nil {
		ruleType = EXCEPTION_TYPE_PATH
	}
	value, _ := utils.PostPara(r, "value")
	targetProxy, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if targetProxy.CaptchaConfig == nil {
		utils.SendErrorResponse(w, "CAPTCHA is not configured for this endpoint")
		return
	}
	if err := mutate(targetProxy.CaptchaConfig, ruleType, value); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	targetProxy.UpdateToRuntime()
	if err := SaveReverseProxyConfig(targetProxy); err != nil {
		utils.SendErrorResponse(w, "unable to save config: "+err.Error())
		return
	}
	utils.SendOK(w)
}

// AddProxyCaptchaExceptionRule adds a CAPTCHA exception rule to an endpoint.
func AddProxyCaptchaExceptionRule(w http.ResponseWriter, r *http.Request) {
	modifyProxyCaptchaExceptionRule(w, r, addCaptchaExceptionRule)
}

// RemoveProxyCaptchaExceptionRule removes a CAPTCHA exception rule from an endpoint.
func RemoveProxyCaptchaExceptionRule(w http.ResponseWriter, r *http.Request) {
	modifyProxyCaptchaExceptionRule(w, r, removeCaptchaExceptionRule)
}
