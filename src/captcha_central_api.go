package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Node wide central CAPTCHA provider (see mod/dynamicproxy/captcha/central.go).

	GET  /api/proxy/captcha/central   the stored config WITHOUT the secret key
	                                  (SecretSet tells whether one is stored); null when unset
	POST /api/proxy/captcha/central   same form fields as the endpoint editor (captchaProvider,
	                                  captchaSiteKey, captchaSecretKey, captchaSessionDuration,
	                                  captchaRecaptchaVersion / Score / Invisible / Action,
	                                  captchaFriendlyEndpoint, captchaAltchaMaxNumber,
	                                  captchaVerifyHostname, turnstile*). An empty captchaSecretKey
	                                  keeps the stored secret (only for the same provider).
	                                  clear=true removes the central config.

	A rule uses it only when it opted in (CaptchaConfig.UseCentral).
*/

const captchaCentralKey = "captchaCentral"

// loadCaptchaCentral restores the saved central config at start up.
func loadCaptchaCentral() {
	var c captcha.Central
	if sysdb.KeyExists("settings", captchaCentralKey) {
		if err := sysdb.Read("settings", captchaCentralKey, &c); err == nil {
			c.Normalize()
			if c.Validate() == nil {
				captcha.SetCentral(&c)
			}
		}
	}
}

// buildCaptchaCentralFromRequest parses and validates a posted central config.
// stored is the current config, used to keep the secret when none is posted.
func buildCaptchaCentralFromRequest(r *http.Request, stored *captcha.Central) (*captcha.Central, error) {
	provider := 0
	if s := postText(r, "captchaProvider"); s != "" {
		p, err := strconv.Atoi(s)
		if err != nil {
			return nil, errors.New("invalid CAPTCHA provider")
		}
		provider = p
	}
	c := &captcha.Central{
		Provider:         captcha.Provider(provider),
		SiteKey:          postText(r, "captchaSiteKey"),
		RecaptchaVersion: postText(r, "captchaRecaptchaVersion"),
	}
	secret, _ := utils.PostPara(r, "captchaSecretKey")
	c.SecretKey = strings.TrimSpace(secret)
	if c.SecretKey == "" {
		if stored != nil && stored.Provider == c.Provider {
			c.SecretKey = stored.SecretKey
		} else {
			return nil, errors.New("enter the secret key of the selected provider")
		}
	}
	if s := postText(r, "captchaSessionDuration"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, errors.New("invalid CAPTCHA session duration: must be a number of seconds")
		}
		c.SessionDuration = n
	}
	if s := postText(r, "captchaRecaptchaScore"); s != "" {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, errors.New("invalid reCAPTCHA score")
		}
		c.RecaptchaScore = f
	}
	if s := postText(r, "captchaAltchaMaxNumber"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return nil, errors.New("invalid Altcha work factor")
		}
		c.AltchaMaxNumber = n
	}
	// page level provider options share the parser of the endpoint form
	pc := &captcha.Config{Provider: c.Provider}
	parseCaptchaPageSettings(r, pc)
	c.Turnstile = pc.Turnstile
	c.RecaptchaInvisible = pc.RecaptchaInvisible
	c.RecaptchaAction = pc.RecaptchaAction
	c.VerifyHostname = pc.VerifyHostname
	c.FriendlyEndpoint = pc.FriendlyEndpoint
	c.Normalize()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// HandleCaptchaCentral reads or replaces the node wide central CAPTCHA provider.
func HandleCaptchaCentral(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		js, _ := json.Marshal(captcha.GetCentral().View()) // the view never carries the secret
		utils.SendJSONResponse(w, string(js))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if clr, _ := utils.PostBool(r, "clear"); clr {
		if sysdb.KeyExists("settings", captchaCentralKey) {
			if err := sysdb.Delete("settings", captchaCentralKey); err != nil {
				utils.SendErrorResponse(w, "unable to save: "+err.Error())
				return
			}
		}
		captcha.SetCentral(nil)
		utils.SendOK(w)
		return
	}
	c, err := buildCaptchaCentralFromRequest(r, captcha.GetCentral())
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if err := sysdb.Write("settings", captchaCentralKey, c); err != nil {
		utils.SendErrorResponse(w, "unable to save: "+err.Error())
		return
	}
	captcha.SetCentral(c)
	utils.SendOK(w)
}

// applyCaptchaCentralOptIn finishes a per-rule config rebuilt from form fields.
// A form that does not carry captchaUseCentral (older UI, scripts) keeps the
// stored choice. A rule that uses the central provider keeps its own stored
// provider fields exactly as they were, so switching back restores them.
func applyCaptchaCentralOptIn(r *http.Request, newCfg, oldCfg *captcha.Config) {
	if newCfg == nil || oldCfg == nil {
		return
	}
	if !formHas(r, "captchaUseCentral") {
		newCfg.UseCentral = oldCfg.UseCentral
	}
	if newCfg.UseCentral {
		newCfg.Provider = oldCfg.Provider
		newCfg.SiteKey = oldCfg.SiteKey
		newCfg.SecretKey = oldCfg.SecretKey
		newCfg.SessionDuration = oldCfg.SessionDuration
		newCfg.RecaptchaVersion = oldCfg.RecaptchaVersion
		newCfg.RecaptchaScore = oldCfg.RecaptchaScore
		newCfg.RecaptchaInvisible = oldCfg.RecaptchaInvisible
		newCfg.RecaptchaAction = oldCfg.RecaptchaAction
		newCfg.AltchaMaxNumber = oldCfg.AltchaMaxNumber
		newCfg.FriendlyEndpoint = oldCfg.FriendlyEndpoint
		newCfg.VerifyHostname = oldCfg.VerifyHostname
		newCfg.Turnstile = oldCfg.Turnstile
	}
}
