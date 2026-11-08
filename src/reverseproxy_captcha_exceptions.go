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

// captchaExceptionSpec is one rule as submitted by the editor.
type captchaExceptionSpec struct {
	Type   int    // EXCEPTION_TYPE_PATH / EXCEPTION_TYPE_IP
	Value  string // path prefix / exact path / regular expression, or IP / CIDR
	Mode   string // path rules: "", prefix, exact or regex
	NoCase bool   // path rules: case insensitive
}

// normalizeCaptchaException validates and normalises a rule value for a type.
func normalizeCaptchaException(spec captchaExceptionSpec) (captcha.ExceptionType, string, string, error) {
	value := strings.TrimSpace(spec.Value)
	switch spec.Type {
	case EXCEPTION_TYPE_PATH:
		mode := strings.ToLower(strings.TrimSpace(spec.Mode))
		if mode == captcha.ExceptionMatchPrefix {
			mode = ""
		}
		if err := captcha.ValidateExceptionPattern(mode, value); err != nil {
			return 0, "", "", err
		}
		if mode == captcha.ExceptionMatchRegex {
			if value == "" {
				return 0, "", "", errors.New("invalid path pattern given")
			}
			return captcha.ExceptionTypePaths, value, mode, nil
		}
		p := normalizeCaptchaExceptionPath(value)
		if p == "" {
			return 0, "", "", errors.New("invalid path prefix given")
		}
		return captcha.ExceptionTypePaths, p, mode, nil
	case EXCEPTION_TYPE_IP:
		if _, _, err := net.ParseCIDR(value); err != nil && net.ParseIP(value) == nil {
			return 0, "", "", errors.New("invalid IP address or CIDR given")
		}
		return captcha.ExceptionTypeCIDR, value, "", nil
	}
	return 0, "", "", errors.New("invalid exception type given")
}

func captchaRuleMatches(rule *captcha.ExceptionRule, t captcha.ExceptionType, value, mode string, noCase bool) bool {
	if rule == nil || rule.RuleType != t {
		return false
	}
	if t == captcha.ExceptionTypePaths {
		ruleMode := strings.ToLower(rule.MatchMode)
		if ruleMode == captcha.ExceptionMatchPrefix {
			ruleMode = ""
		}
		stored := normalizeCaptchaExceptionPath(rule.PathPrefix)
		if ruleMode == captcha.ExceptionMatchRegex {
			stored = strings.TrimSpace(rule.PathPrefix)
		}
		return stored == value && ruleMode == mode && rule.CaseInsensitive == noCase
	}
	return strings.TrimSpace(rule.CIDR) == value
}

// addCaptchaExceptionRule appends a rule, rejecting invalid values and duplicates.
func addCaptchaExceptionRule(cfg *captcha.Config, spec captchaExceptionSpec) error {
	t, v, mode, err := normalizeCaptchaException(spec)
	if err != nil {
		return err
	}
	noCase := spec.NoCase && t == captcha.ExceptionTypePaths
	for _, rule := range cfg.ExceptionRules {
		if captchaRuleMatches(rule, t, v, mode, noCase) {
			return errors.New("this rule already exists")
		}
	}
	rule := &captcha.ExceptionRule{RuleType: t}
	if t == captcha.ExceptionTypePaths {
		rule.PathPrefix, rule.MatchMode, rule.CaseInsensitive = v, mode, noCase
	} else {
		rule.CIDR = v
	}
	//Build a new slice so concurrent readers never see a half updated one
	cfg.ExceptionRules = append(append([]*captcha.ExceptionRule(nil), cfg.ExceptionRules...), rule)
	return nil
}

// removeCaptchaExceptionRule deletes a rule by type, value, mode and case flag.
func removeCaptchaExceptionRule(cfg *captcha.Config, spec captchaExceptionSpec) error {
	t, v, mode, err := normalizeCaptchaException(spec)
	if err != nil {
		return err
	}
	noCase := spec.NoCase && t == captcha.ExceptionTypePaths
	kept := []*captcha.ExceptionRule{}
	found := false
	for _, rule := range cfg.ExceptionRules {
		if captchaRuleMatches(rule, t, v, mode, noCase) {
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
// POST: ep, type (0 = path, 1 = IP / CIDR), value, mode (prefix|exact|regex, paths only), nocase.
func modifyProxyCaptchaExceptionRule(w http.ResponseWriter, r *http.Request, mutate func(*captcha.Config, captchaExceptionSpec) error) {
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
	mode, _ := utils.PostPara(r, "mode")
	noCase, _ := utils.PostBool(r, "nocase")
	targetProxy, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if targetProxy.CaptchaConfig == nil {
		utils.SendErrorResponse(w, "CAPTCHA is not configured for this endpoint")
		return
	}
	if err := mutate(targetProxy.CaptchaConfig, captchaExceptionSpec{Type: ruleType, Value: value, Mode: mode, NoCase: noCase}); err != nil {
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
