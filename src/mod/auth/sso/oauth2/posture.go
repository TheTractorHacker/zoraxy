package oauth2

// ProviderURL is one URL a provider talks to (no secret is ever part of it)
type ProviderURL struct {
	Provider string // provider name (or id)
	Kind     string // issuer, well-known URL, authorization URL, token URL, user info URL
	URL      string
}

// ProviderURLs lists the endpoint URLs of every configured provider, for the security overview.
// Client ids and secrets are not returned.
func (ar *OAuth2Router) ProviderURLs() []ProviderURL {
	var out []ProviderURL
	for _, id := range ar.ProviderIDs() {
		ps := ar.prov(id)
		if ps == nil {
			continue
		}
		c := ps.config()
		name := c.ProviderName
		if name == "" {
			name = id
		}
		for _, u := range []struct{ kind, val string }{
			{"issuer", c.OAuth2Issuer}, {"well-known URL", c.OAuth2WellKnownUrl}, {"authorization URL", c.OAuth2ServerURL},
			{"token URL", c.OAuth2TokenURL}, {"user info URL", c.OAuth2UserInfoUrl},
		} {
			if u.val != "" {
				out = append(out, ProviderURL{Provider: name, Kind: u.kind, URL: u.val})
			}
		}
	}
	return out
}
