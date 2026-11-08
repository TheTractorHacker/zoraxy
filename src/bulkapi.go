package main

/*
	bulkapi.go

	Bulk edit (upstream #924) and reusable rule templates (upstream #826 #877).

	POST /api/proxy/bulk            rules (JSON array of rule names), action, params (JSON BulkParams), dryrun (bool)
	                                -> {"results":[{Rule,OK,Error,Changes}]}; actions: see mod/dynamicproxy/bulk.go
	                                   params.TemplateName resolves a template for apply_template
	GET  /api/proxy/templates/list  -> built in + custom templates
	POST /api/proxy/templates/save  template (JSON RuleTemplate)     custom templates only
	POST /api/proxy/templates/delete name

	New rules: POST /api/proxy/add accepts an optional "template" (name) which is applied before the rule goes live.
*/

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

const ruleTemplateTable = "ruletemplates"

func RegisterBulkAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/proxy/bulk", HandleProxyBulk)
	authRouter.HandleFunc("/api/proxy/templates/list", HandleRuleTemplateList)
	authRouter.HandleFunc("/api/proxy/templates/save", HandleRuleTemplateSave)
	authRouter.HandleFunc("/api/proxy/templates/delete", HandleRuleTemplateDelete)
}

func listRuleTemplates() []*dynamicproxy.RuleTemplate {
	out := dynamicproxy.BuiltinRuleTemplates()
	if sysdb == nil {
		return out
	}
	sysdb.NewTable(ruleTemplateTable)
	entries, err := sysdb.ListTable(ruleTemplateTable)
	if err != nil {
		return out
	}
	custom := []*dynamicproxy.RuleTemplate{}
	for _, e := range entries {
		t := &dynamicproxy.RuleTemplate{}
		if json.Unmarshal(e[1], t) == nil && t.Validate() == nil {
			t.Builtin = false
			custom = append(custom, t)
		}
	}
	sort.Slice(custom, func(i, j int) bool { return custom[i].Name < custom[j].Name })
	return append(out, custom...)
}

func findRuleTemplate(name string) (*dynamicproxy.RuleTemplate, error) {
	for _, t := range listRuleTemplates() {
		if strings.EqualFold(t.Name, name) {
			return t, nil
		}
	}
	return nil, errors.New("template not found: " + name)
}

func HandleRuleTemplateList(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(listRuleTemplates())
	utils.SendJSONResponse(w, string(js))
}

func HandleRuleTemplateSave(w http.ResponseWriter, r *http.Request) {
	raw, err := utils.PostPara(r, "template")
	if err != nil {
		utils.SendErrorResponse(w, "template not given")
		return
	}
	t := &dynamicproxy.RuleTemplate{}
	if err := json.Unmarshal([]byte(raw), t); err != nil {
		utils.SendErrorResponse(w, "invalid template: "+err.Error())
		return
	}
	t.Builtin = false
	if err := t.Validate(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	for _, b := range dynamicproxy.BuiltinRuleTemplates() {
		if strings.EqualFold(b.Name, t.Name) {
			utils.SendErrorResponse(w, "a built in template has that name")
			return
		}
	}
	sysdb.NewTable(ruleTemplateTable)
	if err := sysdb.Write(ruleTemplateTable, t.Name, t); err != nil {
		utils.SendErrorResponse(w, "unable to save the template")
		return
	}
	utils.SendOK(w)
}

func HandleRuleTemplateDelete(w http.ResponseWriter, r *http.Request) {
	name, err := utils.PostPara(r, "name")
	if err != nil {
		utils.SendErrorResponse(w, "name not given")
		return
	}
	for _, b := range dynamicproxy.BuiltinRuleTemplates() {
		if strings.EqualFold(b.Name, name) {
			utils.SendErrorResponse(w, "built in templates cannot be deleted")
			return
		}
	}
	sysdb.NewTable(ruleTemplateTable)
	sysdb.Delete(ruleTemplateTable, name)
	utils.SendOK(w)
}

// applyRuleTemplateByName applies a stored template to a rule that is not live yet
func applyRuleTemplateByName(ep *dynamicproxy.ProxyEndpoint, name string) error {
	t, err := findRuleTemplate(name)
	if err != nil {
		return err
	}
	_, err = dynamicproxy.ApplyRuleTemplate(ep, t)
	return err
}

func HandleProxyBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	rulesRaw, err := utils.PostPara(r, "rules")
	if err != nil {
		utils.SendErrorResponse(w, "rules not given")
		return
	}
	req := &dynamicproxy.BulkRequest{}
	if err := json.Unmarshal([]byte(rulesRaw), &req.Rules); err != nil {
		utils.SendErrorResponse(w, "rules must be a JSON array of names")
		return
	}
	req.Action, _ = utils.PostPara(r, "action")
	if paramsRaw, _ := utils.PostPara(r, "params"); paramsRaw != "" {
		if err := json.Unmarshal([]byte(paramsRaw), &req.Params); err != nil {
			utils.SendErrorResponse(w, "invalid params: "+err.Error())
			return
		}
	}
	req.DryRun, _ = utils.PostBool(r, "dryrun")
	if req.Action == dynamicproxy.BulkApplyTemplate {
		tplName, _ := utils.PostPara(r, "template")
		if tplName == "" {
			utils.SendErrorResponse(w, "template not given")
			return
		}
		t, err := findRuleTemplate(tplName)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		req.Params.Template = t
	}
	results, err := dynamicProxyRouter.BulkEdit(req, dynamicproxy.BulkHooks{
		Persist: SaveReverseProxyConfig,
		Remove:  RemoveReverseProxyConfig,
	})
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if !req.DryRun {
		UpdateUptimeMonitorTargets()
		SystemWideLogger.PrintAndLog("proxy-config", "Bulk edit ("+req.Action+") applied to "+strconv.Itoa(len(results))+" rule(s)", nil)
	}
	js, _ := json.Marshal(map[string]interface{}{"results": results})
	utils.SendJSONResponse(w, string(js))
}
