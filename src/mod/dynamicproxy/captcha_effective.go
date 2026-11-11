package dynamicproxy

import "imuslab.com/zoraxy/mod/dynamicproxy/captcha"

// EffectiveCaptchaConfig is the CAPTCHA configuration requests of this endpoint
// are handled with. It is the one accessor every trigger (plain gate, exploit,
// country / bot, WAF challenge, rules-engine challenge, Altcha challenge, verify
// handler, IsConfigured checks) must use instead of reading CaptchaConfig, so a
// rule that opted in to the central provider (CaptchaConfig.UseCentral) sees the
// central provider fields, resolved at request time. See captcha.ResolveCentral.
func (ep *ProxyEndpoint) EffectiveCaptchaConfig() *CaptchaConfig {
	if ep == nil {
		return nil
	}
	return captcha.ResolveCentral(ep.CaptchaConfig)
}
