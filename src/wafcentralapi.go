package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	wafcentralapi.go

	Admin APIs of the central WAF page: global policy, profiles, coverage,
	summary and rule reference. Endpoint level helpers live in wafapi.go.
*/

func RegisterWAFCentralAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/waf/policy", HandleWAFPolicy)
	authRouter.HandleFunc("/api/waf/profiles", HandleWAFProfiles)
	authRouter.HandleFunc("/api/waf/profile/save", HandleWAFProfileSave)
	authRouter.HandleFunc("/api/waf/profile/clone", HandleWAFProfileClone)
	authRouter.HandleFunc("/api/waf/profile/delete", HandleWAFProfileDelete)
	authRouter.HandleFunc("/api/waf/coverage", HandleWAFCoverage)
	authRouter.HandleFunc("/api/waf/endpoint/set", HandleWAFEndpointSet)
	authRouter.HandleFunc("/api/waf/summary", HandleWAFSummary)
	authRouter.HandleFunc("/api/waf/rules", HandleWAFRules)
}

func sendWAFJSON(w http.ResponseWriter, v interface{}) {
	js, err := json.Marshal(v)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendJSONResponse(w, string(js))
}

// HandleWAFPolicy: GET returns the global policy; POST policy=<JSON> replaces it.
func HandleWAFPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		sendWAFJSON(w, dynamicProxyRouter.WAFState().Policy)
		return
	}
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	raw, err := utils.PostPara(r, "policy")
	if err != nil {
		utils.SendErrorResponse(w, "policy not defined")
		return
	}
	var pol waf.Policy
	if err := json.Unmarshal([]byte(raw), &pol); err != nil {
		utils.SendErrorResponse(w, "Invalid policy: "+err.Error())
		return
	}
	err = mutateWAFCentral(func(p *waf.Policy, _ *[]waf.Profile) error {
		*p = pol
		return nil
	})
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

type wafProfileView struct {
	waf.Profile
	UsedBy []string
}

// HandleWAFProfiles lists built-in and custom profiles with the endpoints using them
func HandleWAFProfiles(w http.ResponseWriter, r *http.Request) {
	use := profileUsage()
	out := []wafProfileView{}
	for _, p := range dynamicProxyRouter.WAFState().Profiles() {
		out = append(out, wafProfileView{Profile: p, UsedBy: use[strings.ToLower(p.Name)]})
	}
	sendWAFJSON(w, out)
}

// HandleWAFProfileSave creates or updates a custom profile. POST profile=<JSON>, create=true|false.
// Updating applies to every endpoint using the profile, without a restart.
func HandleWAFProfileSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	raw, err := utils.PostPara(r, "profile")
	if err != nil {
		utils.SendErrorResponse(w, "profile not defined")
		return
	}
	create, _ := utils.PostBool(r, "create")
	var pr waf.Profile
	if err := json.Unmarshal([]byte(raw), &pr); err != nil {
		utils.SendErrorResponse(w, "Invalid profile: "+err.Error())
		return
	}
	pr.BuiltIn = false
	err = mutateWAFCentral(func(p *waf.Policy, profiles *[]waf.Profile) error {
		if cur, ok := dynamicProxyRouter.WAFState().Profile(pr.Name); ok && cur.BuiltIn {
			return errBuiltinProfile
		}
		idx := -1
		for i, x := range *profiles {
			if strings.EqualFold(x.Name, strings.TrimSpace(pr.Name)) {
				idx = i
			}
		}
		pr.Name = strings.TrimSpace(pr.Name)
		switch {
		case create && idx >= 0:
			return errProfileExists
		case !create && idx < 0:
			return errProfileMissing
		case idx >= 0:
			pr.Name = (*profiles)[idx].Name // name is the identity, keep its case
			(*profiles)[idx] = pr
		default:
			*profiles = append(*profiles, pr)
		}
		return nil
	})
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleWAFProfileClone copies any profile (including built-in) into a new editable one. POST from, name.
func HandleWAFProfileClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	from, err := utils.PostPara(r, "from")
	if err != nil {
		utils.SendErrorResponse(w, "source profile not defined")
		return
	}
	name, err := utils.PostPara(r, "name")
	if err != nil {
		utils.SendErrorResponse(w, "name not defined")
		return
	}
	name = strings.TrimSpace(name)
	err = mutateWAFCentral(func(p *waf.Policy, profiles *[]waf.Profile) error {
		src, ok := dynamicProxyRouter.WAFState().Profile(from)
		if !ok {
			return errProfileMissing
		}
		if _, exists := dynamicProxyRouter.WAFState().Profile(name); exists {
			return errProfileExists
		}
		src.Name = name
		src.BuiltIn = false
		src.ExcludedRuleIDs = append([]string(nil), src.ExcludedRuleIDs...)
		src.PathExclusions = append([]waf.PathExclusion(nil), src.PathExclusions...)
		*profiles = append(*profiles, src)
		return nil
	})
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleWAFProfileDelete removes a custom profile that no endpoint uses. POST name.
func HandleWAFProfileDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	name, err := utils.PostPara(r, "name")
	if err != nil {
		utils.SendErrorResponse(w, "name not defined")
		return
	}
	if err := deleteWAFProfile(name); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleWAFCoverage lists every endpoint with its effective WAF mode and source
func HandleWAFCoverage(w http.ResponseWriter, r *http.Request) {
	sendWAFJSON(w, dynamicProxyRouter.WAFCoverage())
}

// HandleWAFEndpointSet changes where an endpoint takes its WAF from.
// POST rootname ("/" = default site), source, profile (for source=profile),
// extra (optional JSON, additive overrides; empty string clears them)
func HandleWAFEndpointSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	ep, err := utils.PostPara(r, "rootname")
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	source, err := utils.PostPara(r, "source")
	if err != nil {
		utils.SendErrorResponse(w, "source not defined")
		return
	}
	profile, _ := utils.PostPara(r, "profile")
	var extra *waf.Overrides
	rawExtra, extraErr := utils.PostPara(r, "extra")
	setExtra := extraErr == nil
	if setExtra && strings.TrimSpace(rawExtra) != "" {
		extra = &waf.Overrides{}
		if err := json.Unmarshal([]byte(rawExtra), extra); err != nil {
			utils.SendErrorResponse(w, "Invalid extra: "+err.Error())
			return
		}
	}
	if err := setWAFEndpointSource(ep, source, profile, extra, setExtra); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleWAFSummary aggregates recent events. GET hours (default 24, max 168)
func HandleWAFSummary(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	sendWAFJSON(w, map[string]interface{}{
		"summary": waf.Default.Summary(time.Now().Add(-time.Duration(hours)*time.Hour), 10),
		"stats":   waf.Default.Stats(),
		"policy":  dynamicProxyRouter.WAFState().Policy.Enabled,
	})
}

// HandleWAFRules returns the CRS rule reference (ID, description, category, paranoia level)
func HandleWAFRules(w http.ResponseWriter, r *http.Request) {
	sendWAFJSON(w, waf.RuleReference())
}
