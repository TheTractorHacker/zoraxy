package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	securityapi.go

	Admin APIs of the optional security features:
	  GET  /api/botrules/get                   active bot rule config + available categories / good bots
	  POST /api/botrules/set                   config (JSON)
	  POST /api/botrules/endpoint              ep, policy ("", "on", "off")
	  GET  /api/headerrules/get?ep=<rule>      header rules of a proxy rule
	  POST /api/headerrules/set                ep, rules (JSON array of HeaderRule)
*/

var (
	botEngine     *botrules.Engine
	botEngineOnce sync.Once
)

func getBotEngine() *botrules.Engine {
	botEngineOnce.Do(func() {
		e := botrules.New(CONF_FOLDER + "/botrules.json")
		if err := e.Load(); err != nil && SystemWideLogger != nil {
			SystemWideLogger.PrintAndLog("botrules", "Unable to load bot rules, starting disabled", err)
		}
		botEngine = e
	})
	return botEngine
}

func RegisterSecurityAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/botrules/get", HandleBotRulesGet)
	authRouter.HandleFunc("/api/botrules/set", HandleBotRulesSet)
	authRouter.HandleFunc("/api/botrules/endpoint", HandleBotRulesEndpoint)
	authRouter.HandleFunc("/api/headerrules/get", HandleHeaderRulesGet)
	authRouter.HandleFunc("/api/headerrules/set", HandleHeaderRulesSet)
}

func HandleBotRulesGet(w http.ResponseWriter, r *http.Request) {
	type catInfo struct {
		ID, Title string
		Count     int
	}
	cats := []catInfo{}
	for _, c := range botrules.Categories() {
		cats = append(cats, catInfo{c.ID, c.Title, len(c.Items)})
	}
	bots := []string{}
	for _, g := range botrules.GoodBots() {
		bots = append(bots, g.Name)
	}
	cfg := getBotEngine().Config()
	if cfg.Categories == nil {
		cfg.Categories = botrules.DefaultConfig().Categories
	}
	//Per proxy rule policy
	policies := map[string]string{}
	captchaSites := 0 //sites with a working CAPTCHA: a Challenge action only challenges there, everywhere else it blocks
	if dynamicProxyRouter != nil {
		for name, ep := range dynamicProxyRouter.GetProxyEndpointsAsMap() {
			policies[name] = ep.BotPolicy
			if ep.EffectiveCaptchaConfig() != nil && ep.EffectiveCaptchaConfig().IsConfigured() {
				captchaSites++
			}
		}
	}
	js, _ := json.Marshal(map[string]interface{}{"Config": cfg, "Categories": cats, "GoodBots": bots, "Policies": policies, "CaptchaSites": captchaSites})
	utils.SendJSONResponse(w, string(js))
}

func HandleBotRulesSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config missing")
		return
	}
	cfg := botrules.DefaultConfig()
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		utils.SendErrorResponse(w, "invalid config JSON")
		return
	}
	if err := getBotEngine().SetConfig(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleBotRulesEndpoint(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	policy, _ := utils.PostPara(r, "policy")
	if policy != "" && policy != "on" && policy != "off" {
		utils.SendErrorResponse(w, "policy must be empty, on or off")
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		e.BotPolicy = policy
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleHeaderRulesGet(w http.ResponseWriter, r *http.Request) {
	ep, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	target, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	rules := target.HeaderRules
	if rules == nil {
		rules = []*dynamicproxy.HeaderRule{}
	}
	//Values of "equals" rules are secrets: the admin UI shows their count, never the stored text
	masked := make([]*dynamicproxy.HeaderRule, 0, len(rules))
	for _, hr := range rules {
		c := *hr
		if c.Match == "" || c.Match == dynamicproxy.HeaderMatchEquals {
			c.Values = make([]string, len(hr.Values))
			for i := range c.Values {
				c.Values[i] = ""
			}
		}
		masked = append(masked, &c)
	}
	js, _ := json.Marshal(masked)
	utils.SendJSONResponse(w, string(js))
}

// HandleHeaderRulesSet replaces the header rules. For "equals" rules an empty value in an
// existing slot keeps the stored secret (the GET API never returns secrets), so the UI can
// edit other fields without re-entering them.
func HandleHeaderRulesSet(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	raw, err := utils.PostPara(r, "rules")
	if err != nil {
		utils.SendErrorResponse(w, "rules missing")
		return
	}
	var rules []*dynamicproxy.HeaderRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		utils.SendErrorResponse(w, "rules must be a JSON array")
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		for i, nr := range rules {
			if nr == nil || (nr.Match != "" && nr.Match != dynamicproxy.HeaderMatchEquals) {
				continue
			}
			if i < len(e.HeaderRules) && e.HeaderRules[i] != nil {
				old := e.HeaderRules[i]
				if len(nr.Values) == len(old.Values) {
					for j := range nr.Values {
						if nr.Values[j] == "" {
							nr.Values[j] = old.Values[j]
						}
					}
				}
			}
		}
		if err := dynamicproxy.ValidateHeaderRules(rules); err != nil {
			return err
		}
		e.HeaderRules = rules
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
