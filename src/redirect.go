package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	Redirect.go

	This script handle all the http handlers
	related to redirection function in the reverse proxy
*/

var redirectSchemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)

// stripRedirectScheme removes http:// or https:// and a trailing slash so a source and a target can be compared
func stripRedirectScheme(s string) string {
	l := strings.ToLower(s)
	l = strings.TrimPrefix(strings.TrimPrefix(l, "http://"), "https://")
	return strings.TrimSuffix(l, "/")
}

// checkRedirectInput validates the source and the destination of a redirection rule
func checkRedirectInput(source, dest string) error {
	if source == "" {
		return errors.New("redirect url cannot be empty")
	}
	if dest == "" {
		return errors.New("destination url cannot be empty")
	}
	if len(source) > 200 {
		return errors.New("redirect url is too long (200 characters at most)")
	}
	if len(dest) > 2000 {
		return errors.New("destination url is too long (2000 characters at most)")
	}
	if strings.ContainsAny(source, " \t\r\n\x00") {
		return errors.New("redirect url cannot contain spaces")
	}
	if strings.ContainsAny(dest, " \t\r\n\x00") {
		return errors.New("destination url cannot contain spaces")
	}
	if m := redirectSchemeRe.FindString(dest); m != "" {
		rest := dest[len(m):]
		isHostPort := rest != "" && rest[0] >= '0' && rest[0] <= '9' //host:8080/path has no scheme
		if !isHostPort && !strings.HasPrefix(strings.ToLower(dest), "http://") && !strings.HasPrefix(strings.ToLower(dest), "https://") {
			return errors.New("destination url must be a host name or start with http:// or https://")
		}
	}
	if stripRedirectScheme(source) == stripRedirectScheme(dest) {
		return errors.New("the destination is the same as the source, that would redirect in a loop")
	}
	return nil
}

// Handle request for listing all stored redirection rules
func handleListRedirectionRules(w http.ResponseWriter, r *http.Request) {
	rules := redirectTable.GetAllRedirectRules()
	js, _ := json.Marshal(rules)
	utils.SendJSONResponse(w, string(js))
}

// Handle request for adding new redirection rule
func handleAddRedirectionRule(w http.ResponseWriter, r *http.Request) {
	redirectUrl, err := utils.PostPara(r, "redirectUrl")
	if err != nil {
		utils.SendErrorResponse(w, "redirect url cannot be empty")
		return
	}
	destUrl, err := utils.PostPara(r, "destUrl")
	if err != nil {
		utils.SendErrorResponse(w, "destination url cannot be empty")
		return
	}

	forwardChildpath, err := utils.PostBool(r, "forwardChildpath")
	if err != nil {
		//Assume true
		forwardChildpath = true
	}

	requireExactMatch, err := utils.PostBool(r, "requireExactMatch")
	if err != nil {
		//Assume false
		requireExactMatch = false
	}

	redirectTypeString, err := utils.PostPara(r, "redirectType")
	if err != nil {
		redirectTypeString = "307"
	}

	deviceType, err := utils.PostPara(r, "deviceType")
	if err != nil {
		//Assume all devices
		deviceType = "all"
	}

	redirectionStatusCode, err := strconv.Atoi(redirectTypeString)
	if err != nil {
		utils.SendErrorResponse(w, "invalid status code number")
		return
	}

	redirectUrl = strings.TrimSpace(redirectUrl)
	destUrl = strings.TrimSpace(destUrl)
	if err := checkRedirectInput(redirectUrl, destUrl); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	for _, existing := range redirectTable.GetAllRedirectRules() {
		if existing.RedirectURL == redirectUrl {
			utils.SendErrorResponse(w, "a redirection rule for "+redirectUrl+" already exists, edit it instead")
			return
		}
	}

	err = redirectTable.AddRedirectRule(redirectUrl, destUrl, forwardChildpath, redirectionStatusCode, requireExactMatch, deviceType)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	utils.SendOK(w)
}

// Handle remove of a given redirection rule
func handleDeleteRedirectionRule(w http.ResponseWriter, r *http.Request) {
	redirectUrl, err := utils.PostPara(r, "redirectUrl")
	if err != nil {
		utils.SendErrorResponse(w, "redirect url cannot be empty")
		return
	}

	err = redirectTable.DeleteRedirectRule(redirectUrl)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	utils.SendOK(w)
}

func handleEditRedirectionRule(w http.ResponseWriter, r *http.Request) {
	originalRedirectUrl, err := utils.PostPara(r, "originalRedirectUrl")
	if err != nil {
		utils.SendErrorResponse(w, "original redirect url cannot be empty")
		return
	}

	newRedirectUrl, err := utils.PostPara(r, "newRedirectUrl")
	if err != nil {
		utils.SendErrorResponse(w, "redirect url cannot be empty")
		return
	}
	destUrl, err := utils.PostPara(r, "destUrl")
	if err != nil {
		utils.SendErrorResponse(w, "destination url cannot be empty")
		return
	}

	forwardChildpath, err := utils.PostBool(r, "forwardChildpath")
	if err != nil {
		//Assume true
		forwardChildpath = true
	}

	requireExactMatch, err := utils.PostBool(r, "requireExactMatch")
	if err != nil {
		//Assume false
		requireExactMatch = false
	}

	redirectTypeString, err := utils.PostPara(r, "redirectType")
	if err != nil {
		redirectTypeString = "307"
	}

	deviceType, err := utils.PostPara(r, "deviceType")
	if err != nil {
		//Assume all devices
		deviceType = "all"
	}

	redirectionStatusCode, err := strconv.Atoi(redirectTypeString)
	if err != nil {
		utils.SendErrorResponse(w, "invalid status code number")
		return
	}

	newRedirectUrl = strings.TrimSpace(newRedirectUrl)
	destUrl = strings.TrimSpace(destUrl)
	if err := checkRedirectInput(newRedirectUrl, destUrl); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if newRedirectUrl != originalRedirectUrl {
		for _, existing := range redirectTable.GetAllRedirectRules() {
			if existing.RedirectURL == newRedirectUrl {
				utils.SendErrorResponse(w, "a redirection rule for "+newRedirectUrl+" already exists")
				return
			}
		}
	}

	err = redirectTable.EditRedirectRule(originalRedirectUrl, newRedirectUrl, destUrl, forwardChildpath, redirectionStatusCode, requireExactMatch, deviceType)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	utils.SendOK(w)
}

// Toggle redirection regex support. Note that this cost another O(n) time complexity to each page load
func handleToggleRedirectRegexpSupport(w http.ResponseWriter, r *http.Request) {
	//Update the current regex support rule enable state
	enableRegexSupport, err := utils.PostBool(r, "enable")
	if err != nil {
		//Return the current state of the regex support
		js, _ := json.Marshal(redirectTable.AllowRegex)
		utils.SendJSONResponse(w, string(js))
		return
	}
	redirectTable.AllowRegex = enableRegexSupport
	err = sysdb.Write("redirect", "regex", enableRegexSupport)

	if enableRegexSupport {
		SystemWideLogger.PrintAndLog("redirect", "Regex redirect rule enabled", nil)
	} else {
		SystemWideLogger.PrintAndLog("redirect", "Regex redirect rule disabled", nil)
	}
	if err != nil {
		utils.SendErrorResponse(w, "unable to save settings")
		return
	}
	utils.SendOK(w)
}

// Handle toggling the enabled state of a redirection rule
func handleToggleRedirectionRuleEnable(w http.ResponseWriter, r *http.Request) {
	redirectUrl, err := utils.PostPara(r, "redirectUrl")
	if err != nil {
		utils.SendErrorResponse(w, "redirect url cannot be empty")
		return
	}

	enabled, err := utils.PostBool(r, "enabled")
	if err != nil {
		utils.SendErrorResponse(w, "enabled state cannot be empty")
		return
	}

	err = redirectTable.ToggleEnableRedirectRule(redirectUrl, enabled)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	utils.SendOK(w)
}

// Toggle redirection case sensitivity. Note that this affects all redirection rules
func handleToggleRedirectCaseSensitivity(w http.ResponseWriter, r *http.Request) {
	//Update the current case sensitivity rule enable state
	enableCaseSensitivity, err := utils.PostBool(r, "enable")
	if err != nil {
		//Return the current state of the case sensitivity
		js, _ := json.Marshal(redirectTable.CaseSensitive)
		utils.SendJSONResponse(w, string(js))
		return
	}
	redirectTable.CaseSensitive = enableCaseSensitivity
	err = sysdb.Write("redirect", "case_sensitive", enableCaseSensitivity)

	if enableCaseSensitivity {
		SystemWideLogger.PrintAndLog("redirect", "Case sensitive redirect rule enabled", nil)
	} else {
		SystemWideLogger.PrintAndLog("redirect", "Case sensitive redirect rule disabled", nil)
	}
	if err != nil {
		utils.SendErrorResponse(w, "unable to save settings")
		return
	}
	utils.SendOK(w)
}
