package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	authexceptions.go

	Admin API for the exception rules of Forward Auth and OAuth2 (upstream #652).
	Matching lives in mod/dynamicproxy/authexceptions.go.

	GET  /api/proxy/auth/sso/exceptions/list?ep=<rule>
	POST /api/proxy/auth/sso/exceptions/add      ep, type (0 path | 1 ip), pattern, mode (prefix|exact|regex), nocase, cidr
	POST /api/proxy/auth/sso/exceptions/delete   ep, type, pattern, mode, nocase | cidr
*/

func RegisterAuthExceptionAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/proxy/auth/sso/exceptions/list", ListProxyAuthExceptionRules)
	authRouter.HandleFunc("/api/proxy/auth/sso/exceptions/add", AddProxyAuthExceptionRule)
	authRouter.HandleFunc("/api/proxy/auth/sso/exceptions/delete", RemoveProxyAuthExceptionRule)
}

func authExceptionSendErr(w http.ResponseWriter, msg string) {
	js, _ := json.Marshal(map[string]string{"error": msg})
	utils.SendJSONResponse(w, string(js))
}

func loadAuthExceptionTarget(w http.ResponseWriter, ep string) *dynamicproxy.ProxyEndpoint {
	target, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		authExceptionSendErr(w, err.Error())
		return nil
	}
	if target.AuthenticationProvider == nil {
		target.AuthenticationProvider = &dynamicproxy.AuthenticationProvider{}
	}
	return target
}

func ListProxyAuthExceptionRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ep, err := utils.GetPara(r, "ep")
	if err != nil {
		authExceptionSendErr(w, "Invalid ep given")
		return
	}
	target := loadAuthExceptionTarget(w, ep)
	if target == nil {
		return
	}
	results := target.AuthenticationProvider.ExternalAuthExceptionRules
	if results == nil {
		results = []*dynamicproxy.AuthExceptionRule{}
	}
	js, _ := json.Marshal(results)
	utils.SendJSONResponse(w, string(js))
}

func authExceptionRuleFromForm(r *http.Request) (*dynamicproxy.AuthExceptionRule, string) {
	exceptionType, err := utils.PostInt(r, "type")
	if err != nil {
		exceptionType = EXCEPTION_TYPE_PATH
	}
	rule := &dynamicproxy.AuthExceptionRule{}
	switch exceptionType {
	case EXCEPTION_TYPE_PATH:
		pattern, _ := utils.PostPara(r, "pattern")
		mode, _ := utils.PostPara(r, "mode")
		nocase, _ := utils.PostBool(r, "nocase")
		rule.RuleType = dynamicproxy.AuthExceptionType_Paths
		rule.PathPattern = pattern
		rule.MatchMode = strings.TrimSpace(mode)
		rule.CaseInsensitive = nocase
	case EXCEPTION_TYPE_IP:
		cidr, _ := utils.PostPara(r, "cidr")
		rule.RuleType = dynamicproxy.AuthExceptionType_CIDR
		rule.CIDR = cidr
	default:
		return nil, "Invalid exception type given"
	}
	if err := dynamicproxy.ValidateAuthExceptionRule(rule); err != nil {
		return nil, err.Error()
	}
	return rule, ""
}

func sameAuthExceptionRule(a, b *dynamicproxy.AuthExceptionRule) bool {
	return a != nil && b != nil && a.RuleType == b.RuleType && a.MatchMode == b.MatchMode &&
		a.PathPattern == b.PathPattern && a.CaseInsensitive == b.CaseInsensitive && a.CIDR == b.CIDR
}

func AddProxyAuthExceptionRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ep, err := utils.PostPara(r, "ep")
	if err != nil {
		authExceptionSendErr(w, "Invalid ep given")
		return
	}
	rule, msg := authExceptionRuleFromForm(r)
	if rule == nil {
		authExceptionSendErr(w, msg)
		return
	}
	target := loadAuthExceptionTarget(w, ep)
	if target == nil {
		return
	}
	for _, existing := range target.AuthenticationProvider.ExternalAuthExceptionRules {
		if sameAuthExceptionRule(existing, rule) {
			authExceptionSendErr(w, "This rule already exists")
			return
		}
	}
	target.AuthenticationProvider.ExternalAuthExceptionRules = append(target.AuthenticationProvider.ExternalAuthExceptionRules, rule)
	target.UpdateToRuntime()
	SaveReverseProxyConfig(target)
	utils.SendOK(w)
}

func RemoveProxyAuthExceptionRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ep, err := utils.PostPara(r, "ep")
	if err != nil {
		authExceptionSendErr(w, "Invalid ep given")
		return
	}
	rule, msg := authExceptionRuleFromForm(r)
	if rule == nil {
		authExceptionSendErr(w, msg)
		return
	}
	target := loadAuthExceptionTarget(w, ep)
	if target == nil {
		return
	}
	kept := []*dynamicproxy.AuthExceptionRule{}
	found := false
	for _, existing := range target.AuthenticationProvider.ExternalAuthExceptionRules {
		if sameAuthExceptionRule(existing, rule) {
			found = true
			continue
		}
		kept = append(kept, existing)
	}
	if !found {
		authExceptionSendErr(w, "Target rule not found")
		return
	}
	target.AuthenticationProvider.ExternalAuthExceptionRules = kept
	target.UpdateToRuntime()
	SaveReverseProxyConfig(target)
	utils.SendOK(w)
}
