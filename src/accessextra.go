package main

import (
	"encoding/json"
	"net/http"

	"github.com/microcosm-cc/bluemonday"
	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	accessextra.go

	Optional access rule features: sorting / duplicating rules (upstream #762),
	dropping blocked connections (#908) and challenge countries (#281).
*/

// RegisterAccessRuleExtraAPIs adds the optional access rule APIs
func RegisterAccessRuleExtraAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/access/listSorted", handleListAccessRulesSorted)
	authRouter.HandleFunc("/api/access/duplicate", handleDuplicateAccessRule)
	authRouter.HandleFunc("/api/access/reorder", handleReorderAccessRules)
	authRouter.HandleFunc("/api/access/dropOnBlock", handleAccessDropOnBlock)
	authRouter.HandleFunc("/api/access/challenge/list", handleChallengeList)
	authRouter.HandleFunc("/api/access/challenge/add", handleChallengeAdd)
	authRouter.HandleFunc("/api/access/challenge/remove", handleChallengeRemove)
}

// GET ?sort=manual|name|id
func handleListAccessRulesSorted(w http.ResponseWriter, r *http.Request) {
	mode, _ := utils.GetPara(r, "sort")
	rules := access.SortRules(accessController.ListAllAccessRules(), mode)
	js, _ := json.Marshal(rules)
	utils.SendJSONResponse(w, string(js))
}

// POST id, optional name
func handleDuplicateAccessRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := utils.PostPara(r, "id")
	if err != nil {
		utils.SendErrorResponse(w, "invalid rule id")
		return
	}
	name, _ := utils.PostPara(r, "name")
	name = bluemonday.StrictPolicy().Sanitize(name)
	cp, err := accessController.DuplicateAccessRule(id, name)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	js, _ := json.Marshal(map[string]string{"id": cp.ID, "name": cp.Name})
	utils.SendJSONResponse(w, string(js))
}

// POST ids = JSON array of rule IDs in the wanted order
func handleReorderAccessRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := utils.PostPara(r, "ids")
	if err != nil {
		utils.SendErrorResponse(w, "ids missing")
		return
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		utils.SendErrorResponse(w, "ids must be a JSON array")
		return
	}
	if err := accessController.SetRuleOrder(ids); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// GET id -> {DropOnBlock}; POST id, enable
func handleAccessDropOnBlock(w http.ResponseWriter, r *http.Request) {
	id, _ := utils.GetPara(r, "id")
	if r.Method == http.MethodPost {
		id, _ = utils.PostPara(r, "id")
	}
	rule, err := accessController.GetAccessRuleByID(id)
	if err != nil {
		utils.SendErrorResponse(w, "access rule not found")
		return
	}
	if r.Method != http.MethodPost {
		js, _ := json.Marshal(rule.DropOnBlock)
		utils.SendJSONResponse(w, string(js))
		return
	}
	enable, err := utils.PostBool(r, "enable")
	if err != nil {
		utils.SendErrorResponse(w, "enable missing")
		return
	}
	if err := rule.SetDropOnBlock(enable); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func handleChallengeList(w http.ResponseWriter, r *http.Request) {
	id, _ := utils.GetPara(r, "id")
	rule, err := accessController.GetAccessRuleByID(id)
	if err != nil {
		utils.SendErrorResponse(w, "access rule not found")
		return
	}
	//The UI warns when a challenge country exists but no proxy rule using this access rule has a CAPTCHA
	hostsWithoutCaptcha := []string{}
	if dynamicProxyRouter != nil {
		for _, ep := range dynamicProxyRouter.GetProxyEndpointsAsMap() {
			ruleOfHost := ep.AccessFilterUUID
			if ruleOfHost == "" {
				ruleOfHost = "default"
			}
			want := id
			if want == "" {
				want = "default"
			}
			if ruleOfHost == want && !ep.CaptchaConfig.IsConfigured() {
				hostsWithoutCaptcha = append(hostsWithoutCaptcha, ep.RootOrMatchingDomain)
			}
		}
	}
	js, _ := json.Marshal(map[string]interface{}{
		"Countries":           rule.ListChallengeCountries(),
		"HostsWithoutCaptcha": hostsWithoutCaptcha,
	})
	utils.SendJSONResponse(w, string(js))
}

func handleChallengeAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, _ := utils.PostPara(r, "id")
	cc, _ := utils.PostPara(r, "cc")
	comment, _ := utils.PostPara(r, "comment")
	rule, err := accessController.GetAccessRuleByID(id)
	if err != nil {
		utils.SendErrorResponse(w, "access rule not found")
		return
	}
	if err := rule.AddChallengeCountry(cc, bluemonday.StrictPolicy().Sanitize(comment)); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func handleChallengeRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, _ := utils.PostPara(r, "id")
	cc, _ := utils.PostPara(r, "cc")
	rule, err := accessController.GetAccessRuleByID(id)
	if err != nil {
		utils.SendErrorResponse(w, "access rule not found")
		return
	}
	if err := rule.RemoveChallengeCountry(cc); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}
