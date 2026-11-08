package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

type ruleInfoKey struct{}

// RuleID derives the stable identifier of a proxy rule from its key (rules have no stored UUID)
func RuleID(ruleKey string) string {
	sum := sha256.Sum256([]byte("zoraxy-rule:" + ruleKey))
	return hex.EncodeToString(sum[:8])
}

// WithRuleInfo attaches the matched proxy rule to the request context, so that the
// dynamic capture sniff can tell the plugin which rule matched.
func WithRuleInfo(r *http.Request, ruleKey string, tags []string) *http.Request {
	info := &zoraxy_plugin.SniffRuleInfo{Name: ruleKey, UUID: RuleID(ruleKey), Tags: append([]string{}, tags...)}
	return r.WithContext(context.WithValue(r.Context(), ruleInfoKey{}, info))
}

// RuleInfoFromRequest returns the rule attached by WithRuleInfo (nil when unknown)
func RuleInfoFromRequest(r *http.Request) *zoraxy_plugin.SniffRuleInfo {
	v, _ := r.Context().Value(ruleInfoKey{}).(*zoraxy_plugin.SniffRuleInfo)
	return v
}
