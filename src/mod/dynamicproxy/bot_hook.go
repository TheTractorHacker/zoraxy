package dynamicproxy

import (
	"net/http"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/metrics"
)

/*
	Bot (User-Agent) rules glue, see mod/botrules (upstream #615).

	ProxyEndpoint.BotPolicy: "" follows the global switch, "on" applies the global
	rule set even when the global switch is off, "off" skips the endpoint.
	Actions: block (403), challenge (the endpoint CAPTCHA, 403 when none is configured),
	log (log only) and drop (close the connection).
*/

func (h *ProxyHandler) handleBotRules(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	eng := h.Parent.Option.Bots
	if eng == nil {
		return false
	}
	switch sep.BotPolicy {
	case "off":
		return false
	case "on":
	default:
		if !eng.Enabled() {
			return false
		}
	}
	//Every User-Agent header value is judged: a duplicate header must not hide a bot from the rules
	//while the upstream reads the other one
	var d botrules.Decision
	uas := r.Header.Values("User-Agent")
	if len(uas) == 0 {
		uas = []string{""}
	} else if len(uas) > 4 {
		uas = uas[:4]
	}
	ipFn := func() string { return h.Parent.GetClientIPForEndpoint(r, sep) }
	for _, ua := range uas {
		if d = eng.Evaluate(ua, ipFn); d.Action != "" {
			break
		}
	}
	if d.Action == "" {
		return false
	}
	reason := "bot-" + d.Reason
	switch d.Action {
	case botrules.ActionLog:
		h.Parent.logRequest(r, true, 200, reason+"-logonly", r.Host, "", sep)
		return false
	case botrules.ActionChallenge:
		return h.Parent.captchaChallengeFor(w, r, sep, "bot", d.Reason, "bot:"+d.Reason)
	case botrules.ActionDrop:
		h.Parent.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "bot")
		h.Parent.logRequestRule(r, false, 444, reason+"-dropped", r.Host, "", sep, "", "bot:"+d.Reason)
		abuseNoteKind(r, abuse.KindBot)
		dropConnection(w)
		return true
	}
	h.Parent.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "bot")
	h.Parent.logRequestRule(r, false, 403, reason, r.Host, "", sep, "", "bot:"+d.Reason)
	abuseNoteKind(r, abuse.KindBot)
	serveProxyRequestError(w, r, http.StatusForbidden, h.Parent, ErrorTemplateForbidden)
	return true
}
