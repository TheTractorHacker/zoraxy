package main

import (
	"encoding/json"
	"net/http"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Node wide default CAPTCHA branding.

	GET  /api/proxy/captcha/default   returns the stored Branding (null when unset)
	POST /api/proxy/captcha/default   same page fields as the endpoint editor (captchaTitle, ...);
	                                  no field at all clears the default
*/

const captchaDefaultBrandingKey = "captchaDefaultBranding"

// loadCaptchaDefaultBranding restores the saved default at start up.
func loadCaptchaDefaultBranding() {
	var b captcha.Branding
	if sysdb.KeyExists("settings", captchaDefaultBrandingKey) {
		if err := sysdb.Read("settings", captchaDefaultBrandingKey, &b); err == nil && b.Validate() == nil {
			captcha.SetDefaultBranding(&b)
		}
	}
}

// HandleCaptchaDefaultBranding reads or replaces the node wide default branding.
func HandleCaptchaDefaultBranding(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		js, _ := json.Marshal(captcha.DefaultBranding())
		utils.SendJSONResponse(w, string(js))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := &captcha.Config{}
	parseCaptchaPageSettings(r, cfg)
	if err := cfg.ValidatePageSettings(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	var b captcha.Branding
	if cfg.Branding != nil {
		b = *cfg.Branding
	}
	if err := sysdb.Write("settings", captchaDefaultBrandingKey, b); err != nil {
		utils.SendErrorResponse(w, "unable to save: "+err.Error())
		return
	}
	captcha.SetDefaultBranding(&b)
	utils.SendOK(w)
}
