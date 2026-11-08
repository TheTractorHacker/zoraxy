package main

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"imuslab.com/zoraxy/mod/auth/sso/oauth2"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	oauth2providers.go

	Glue between the OAuth2 provider registry (mod/auth/sso/oauth2/providers.go) and the proxy rules:
	which rules use a provider, and the per rule provider / allow-list form fields of the rule editor.

	Form fields of /api/proxy/edit (all optional, only the ones sent change the rule):
	  oauth2provider  provider id ("" = default)
	  oauth2groups, oauth2claims, oauth2emails, oauth2emaildomains   extra allow-lists for this rule
*/

// oauth2ProviderUsers lists the proxy rules whose OAuth2 authentication uses the provider.
func oauth2ProviderUsers(providerID string) []string {
	if dynamicProxyRouter == nil {
		return nil
	}
	var users []string
	for name, ep := range dynamicProxyRouter.GetProxyEndpointsAsMap() {
		ap := ep.AuthenticationProvider
		if ap == nil || ap.AuthMethod != dynamicproxy.AuthMethodOauth2 {
			continue
		}
		used := ap.OAuth2ProviderID
		if used == "" {
			used = oauth2.DefaultProviderID
		}
		if used == providerID {
			users = append(users, name)
		}
	}
	sort.Strings(users)
	return users
}

// applyOAuth2RuleForm reads the OAuth2 provider selection and per rule allow-lists from the request.
func applyOAuth2RuleForm(r *http.Request, ap *dynamicproxy.AuthenticationProvider) error {
	field := func(key string, dst *string) {
		if formHas(r, key) {
			v, _ := utils.PostPara(r, key)
			*dst = strings.TrimSpace(v)
		}
	}
	prevProvider := ap.OAuth2ProviderID
	field("oauth2provider", &ap.OAuth2ProviderID)
	field("oauth2groups", &ap.OAuth2AllowedGroups)
	field("oauth2claims", &ap.OAuth2AllowedClaims)
	field("oauth2emails", &ap.OAuth2AllowedEmails)
	field("oauth2emaildomains", &ap.OAuth2AllowedEmailDomains)
	if ap.OAuth2ProviderID == oauth2.DefaultProviderID {
		ap.OAuth2ProviderID = "" //"default" and unset are the same provider; keep the stored form canonical
	}
	if ap.OAuth2ProviderID != "" {
		if !oauth2.ValidProviderID(ap.OAuth2ProviderID) {
			return errors.New("invalid OAuth2 provider id")
		}
		if ap.AuthMethod == dynamicproxy.AuthMethodOauth2 && ap.OAuth2ProviderID != prevProvider && !oauth2Router.ProviderExists(ap.OAuth2ProviderID) {
			return errors.New("OAuth2 provider \"" + ap.OAuth2ProviderID + "\" does not exist")
		}
	}
	if err := oauth2.ValidateRuleOptions(oauth2.RuleOptions{AllowedClaims: ap.OAuth2AllowedClaims}); err != nil {
		return errors.New("OAuth2 allowed claims: " + err.Error())
	}
	return nil
}
