package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	providers.go

	Provider registry (upstream #884 / #1162): any number of named OIDC / OAuth2 providers, each
	proxy rule picks one by id. The provider "default" is the legacy single configuration: the
	first start after the upgrade migrates the old oauth2 settings into it and rules without a
	provider id keep using it, so existing setups behave exactly as before. Edits of "default" are
	mirrored to the legacy keys so a downgrade still finds its settings.
*/

const (
	// DefaultProviderID is the provider used by rules that do not name one (and the legacy API).
	DefaultProviderID = "default"

	providerTable  = "oauth2_providers"
	migratedKey    = "providersMigrated"
	maxProviders   = 32
	maxNameLen     = 64
	secretMask     = "********"
	callbackSubdir = callbackPrefix + "/p/"
)

var providerIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidProviderID reports whether id is an acceptable provider identifier.
func ValidProviderID(id string) bool { return providerIDRe.MatchString(id) }

// callbackPathFor is the redirect URI path of a provider. The default provider keeps the historical
// path (already registered at the identity provider); others live below /internal/oauth2/p/<id>.
func callbackPathFor(id string) string {
	if id == "" || id == DefaultProviderID {
		return callbackPrefix
	}
	return callbackSubdir + id
}

func logoutPathFor(id string) string {
	if id == "" || id == DefaultProviderID {
		return logoutPath
	}
	return callbackSubdir + id + "/logout"
}

// providerRecord is what is persisted for a provider.
type providerRecord struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Preset              string `json:"preset,omitempty"`
	WellKnownUrl        string `json:"wellKnownUrl,omitempty"`
	Issuer              string `json:"issuer,omitempty"`
	ServerUrl           string `json:"serverUrl,omitempty"`
	TokenUrl            string `json:"tokenUrl,omitempty"`
	UserInfoUrl         string `json:"userInfoUrl,omitempty"`
	ClientId            string `json:"clientId"`
	ClientSecret        string `json:"clientSecret"`
	Scopes              string `json:"scopes,omitempty"`
	CodeChallengeMethod string `json:"codeChallengeMethod,omitempty"`
	CacheTimeSec        int    `json:"cacheTimeSec,omitempty"`
	GroupsClaim         string `json:"groupsClaim,omitempty"`
	AllowedGroups       string `json:"allowedGroups,omitempty"`
	AllowedClaims       string `json:"allowedClaims,omitempty"`
	AllowedEmails       string `json:"allowedEmails,omitempty"`
	AllowedEmailDomains string `json:"allowedEmailDomains,omitempty"`
	HeaderMappings      string `json:"headerMappings,omitempty"`
	EndSessionUrl       string `json:"endSessionUrl,omitempty"`
	PostLogoutRedirect  string `json:"postLogoutRedirectUrl,omitempty"`
}

func (rec *providerRecord) options() *OAuth2RouterOptions {
	ct := DefaultOAuth2ConfigCacheTime
	if rec.CacheTimeSec > 0 {
		ct = time.Duration(rec.CacheTimeSec) * time.Second
	}
	return &OAuth2RouterOptions{
		ProviderID: rec.ID, ProviderName: rec.Name, ProviderPreset: rec.Preset,
		OAuth2WellKnownUrl: rec.WellKnownUrl, OAuth2Issuer: rec.Issuer, OAuth2ServerURL: rec.ServerUrl,
		OAuth2TokenURL: rec.TokenUrl, OAuth2UserInfoUrl: rec.UserInfoUrl, OAuth2ClientId: rec.ClientId,
		OAuth2ClientSecret: rec.ClientSecret, OAuth2Scopes: rec.Scopes, OAuth2CodeChallengeMethod: rec.CodeChallengeMethod,
		OAuth2ConfigurationCacheTime: &ct, OAuth2GroupsClaim: rec.GroupsClaim, OAuth2AllowedGroups: rec.AllowedGroups,
		OAuth2AllowedClaims: rec.AllowedClaims, OAuth2AllowedEmails: rec.AllowedEmails,
		OAuth2AllowedEmailDomains: rec.AllowedEmailDomains, OAuth2HeaderMappings: rec.HeaderMappings,
		OAuth2EndSessionUrl: rec.EndSessionUrl, OAuth2PostLogoutRedirectUrl: rec.PostLogoutRedirect,
	}
}

func recordFromOptions(id, name string, o *OAuth2RouterOptions) *providerRecord {
	rec := &providerRecord{
		ID: id, Name: name, Preset: o.ProviderPreset,
		WellKnownUrl: o.OAuth2WellKnownUrl, Issuer: o.OAuth2Issuer, ServerUrl: o.OAuth2ServerURL, TokenUrl: o.OAuth2TokenURL,
		UserInfoUrl: o.OAuth2UserInfoUrl, ClientId: o.OAuth2ClientId, ClientSecret: o.OAuth2ClientSecret,
		Scopes: o.OAuth2Scopes, CodeChallengeMethod: o.OAuth2CodeChallengeMethod, GroupsClaim: o.OAuth2GroupsClaim,
		AllowedGroups: o.OAuth2AllowedGroups, AllowedClaims: o.OAuth2AllowedClaims, AllowedEmails: o.OAuth2AllowedEmails,
		AllowedEmailDomains: o.OAuth2AllowedEmailDomains, HeaderMappings: o.OAuth2HeaderMappings,
		EndSessionUrl: o.OAuth2EndSessionUrl, PostLogoutRedirect: o.OAuth2PostLogoutRedirectUrl,
	}
	if o.OAuth2ConfigurationCacheTime != nil && *o.OAuth2ConfigurationCacheTime > 0 &&
		*o.OAuth2ConfigurationCacheTime != DefaultOAuth2ConfigCacheTime {
		rec.CacheTimeSec = int(o.OAuth2ConfigurationCacheTime.Seconds())
	}
	return rec
}

// providerState is the runtime of one provider: its settings, discovery cache and JWKS cache.
type providerState struct {
	ar  *OAuth2Router
	mu  sync.RWMutex
	cfg *OAuth2RouterOptions //replaced as a whole on edit, never mutated

	metaMu  sync.Mutex
	meta    *providerMeta
	metaKey string
	metaErr time.Time
	lastErr error
	errKey  string
	jwks    *jwksCache
}

func newProviderState(ar *OAuth2Router, cfg *OAuth2RouterOptions) *providerState {
	return &providerState{ar: ar, cfg: cfg, jwks: &jwksCache{}}
}

func (ps *providerState) config() *OAuth2RouterOptions {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.cfg
}

/* Registry on the router */

// loadProviders reads the registry, migrating the legacy single configuration on first use.
func (ar *OAuth2Router) loadProviders(legacy *OAuth2RouterOptions) {
	db := ar.options.Database
	db.NewTable(providerTable)
	if !db.KeyExists(dbTable, migratedKey) {
		// First start with the registry: the legacy configuration (settings read from the
		// oauth2 table, or handed in by the caller) becomes the provider "default".
		if legacy.OAuth2ClientId != "" || legacy.OAuth2Issuer != "" || legacy.OAuth2WellKnownUrl != "" ||
			legacy.OAuth2ServerURL != "" || legacy.OAuth2TokenURL != "" {
			if !db.KeyExists(providerTable, DefaultProviderID) {
				db.Write(providerTable, DefaultProviderID, recordFromOptions(DefaultProviderID, "Default", legacy))
			}
		}
		db.Write(dbTable, migratedKey, true)
	}
	rows, _ := db.ListTable(providerTable)
	for _, kv := range rows {
		if len(kv) < 2 {
			continue
		}
		var rec providerRecord
		if json.Unmarshal(kv[1], &rec) != nil || !ValidProviderID(rec.ID) || rec.ID != string(kv[0]) {
			continue
		}
		ar.provs[rec.ID] = newProviderState(ar, rec.options())
	}
}

// prov returns the runtime of a provider ("" = default) or nil.
func (ar *OAuth2Router) prov(id string) *providerState {
	if id == "" {
		id = DefaultProviderID
	}
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	return ar.provs[id]
}

// ProviderExists reports whether a provider with this id is configured.
func (ar *OAuth2Router) ProviderExists(id string) bool { return ar.prov(id) != nil }

// ProviderIDs lists the configured provider ids, sorted.
func (ar *OAuth2Router) ProviderIDs() []string {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	ids := make([]string, 0, len(ar.provs))
	for id := range ar.provs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// legacyKeys maps the legacy oauth2 table keys to record accessors; used to mirror "default".
func (ar *OAuth2Router) mirrorDefault(o *OAuth2RouterOptions) {
	wr := func(key string, v any) { ar.options.Database.Write(dbTable, key, v) }
	wr("oauth2WellKnownUrl", o.OAuth2WellKnownUrl)
	wr("oauth2ServerUrl", o.OAuth2ServerURL)
	wr("oauth2TokenUrl", o.OAuth2TokenURL)
	wr("oauth2UserInfoUrl", o.OAuth2UserInfoUrl)
	wr("oauth2ClientId", o.OAuth2ClientId)
	wr("oauth2ClientSecret", o.OAuth2ClientSecret)
	wr("oauth2Scopes", o.OAuth2Scopes)
	wr("oauth2CodeChallengeMethod", o.OAuth2CodeChallengeMethod)
	wr("oauth2ConfigurationCacheTime", o.OAuth2ConfigurationCacheTime)
	wr("oauth2Issuer", o.OAuth2Issuer)
	wr("oauth2GroupsClaim", o.OAuth2GroupsClaim)
	wr("oauth2AllowedGroups", o.OAuth2AllowedGroups)
	wr("oauth2AllowedClaims", o.OAuth2AllowedClaims)
	wr("oauth2AllowedEmails", o.OAuth2AllowedEmails)
	wr("oauth2AllowedEmailDomains", o.OAuth2AllowedEmailDomains)
	wr("oauth2HeaderMappings", o.OAuth2HeaderMappings)
	wr("oauth2EndSessionUrl", o.OAuth2EndSessionUrl)
	wr("oauth2PostLogoutRedirectUrl", o.OAuth2PostLogoutRedirectUrl)
}

var legacyKeyList = []string{"oauth2WellKnownUrl", "oauth2ServerUrl", "oauth2TokenUrl", "oauth2UserInfoUrl",
	"oauth2ClientId", "oauth2ClientSecret", "oauth2Scopes", "oauth2CodeChallengeMethod", "oauth2ConfigurationCacheTime",
	"oauth2Issuer", "oauth2GroupsClaim", "oauth2AllowedGroups", "oauth2HeaderMappings", "oauth2EndSessionUrl",
	"oauth2PostLogoutRedirectUrl", "oauth2AllowedClaims", "oauth2AllowedEmails", "oauth2AllowedEmailDomains"}

// saveProvider validates nothing (callers did) and stores + activates a provider. Sessions of the
// provider are dropped: changed secrets / allow-lists must apply immediately.
func (ar *OAuth2Router) saveProvider(rec *providerRecord) error {
	if err := ar.options.Database.Write(providerTable, rec.ID, rec); err != nil {
		return err
	}
	o := rec.options()
	ar.mu.Lock()
	ps := ar.provs[rec.ID]
	if ps == nil {
		ps = newProviderState(ar, o)
		ar.provs[rec.ID] = ps
	} else {
		ps.mu.Lock()
		ps.cfg = o
		ps.mu.Unlock()
	}
	ar.mu.Unlock()
	ps.flush()
	ar.store.purgeProvider(rec.ID)
	if rec.ID == DefaultProviderID {
		ar.mirrorDefault(o)
	}
	return nil
}

var errInUse = errors.New("provider is in use")

func (ar *OAuth2Router) deleteProvider(id string) error {
	if ar.prov(id) == nil {
		return errors.New("no such provider")
	}
	if ar.options.InUse != nil {
		if users := ar.options.InUse(id); len(users) > 0 {
			if len(users) > 5 {
				users = append(users[:5], "...")
			}
			return fmt.Errorf("%w by: %s", errInUse, strings.Join(users, ", "))
		}
	}
	ar.options.Database.Delete(providerTable, id)
	ar.mu.Lock()
	delete(ar.provs, id)
	ar.mu.Unlock()
	ar.store.purgeProvider(id)
	if id == DefaultProviderID {
		for _, k := range legacyKeyList {
			ar.options.Database.Delete(dbTable, k)
		}
	}
	return nil
}

func (ps *providerState) flush() {
	ps.metaMu.Lock()
	ps.meta = nil
	ps.metaKey = ""
	ps.lastErr = nil
	ps.metaMu.Unlock()
}

/* Settings parsing shared by the legacy and the provider API */

// parseRecord builds a record from form values. prev (may be nil) supplies the secret when the form
// leaves it blank.
func parseRecord(r *http.Request, id string, prev *providerRecord, secretRequired bool) (*providerRecord, error) {
	opt := func(key string) string {
		v, _ := utils.PostPara(r, key)
		return strings.TrimSpace(v)
	}
	rec := &providerRecord{ID: id}
	rec.Name = opt("name")
	if rec.Name == "" {
		rec.Name = id
	}
	if len(rec.Name) > maxNameLen {
		return nil, errors.New("name is too long")
	}
	rec.Preset = opt("preset")
	if len(rec.Preset) > 32 {
		rec.Preset = ""
	}
	rec.ClientId = opt("oauth2ClientId")
	if rec.ClientId == "" {
		return nil, errors.New("oauth2ClientId not found")
	}
	sec, _ := utils.PostPara(r, "oauth2ClientSecret")
	if sec == secretMask {
		sec = ""
	}
	switch {
	case sec != "":
		rec.ClientSecret = sec
	case prev != nil && prev.ClientSecret != "" && !secretRequired:
		rec.ClientSecret = prev.ClientSecret
	default:
		return nil, errors.New("oauth2ClientSecret not found")
	}
	rec.CodeChallengeMethod = opt("oauth2CodeChallengeMethod")
	switch rec.CodeChallengeMethod {
	case "", "plain", "PKCE", "PKCE_S256": // "plain" (UI label "None") means no PKCE
	default:
		return nil, errors.New("oauth2CodeChallengeMethod must be empty, plain, PKCE or PKCE_S256")
	}
	if d, err := utils.PostDuration(r, "oauth2ConfigurationCacheTime"); err == nil && d != nil && *d > 0 && *d != DefaultOAuth2ConfigCacheTime {
		rec.CacheTimeSec = int(d.Seconds())
	}
	rec.WellKnownUrl = opt("oauth2WellKnownUrl")
	rec.Issuer = opt("oauth2Issuer")
	rec.ServerUrl = opt("oauth2ServerUrl")
	rec.TokenUrl = opt("oauth2TokenUrl")
	rec.UserInfoUrl = opt("oauth2UserInfoUrl")
	rec.Scopes = opt("oauth2Scopes")
	rec.EndSessionUrl = opt("oauth2EndSessionUrl")
	rec.PostLogoutRedirect = opt("oauth2PostLogoutRedirectUrl")
	if rec.WellKnownUrl == "" && rec.Issuer == "" {
		// Manual endpoint configuration needs the authorization and token endpoints (legacy behavior)
		if rec.ServerUrl == "" || rec.TokenUrl == "" {
			return nil, errors.New("set an issuer / well-known URL, or both the authorization and token endpoints")
		}
	}
	for name, v := range map[string]string{
		"oauth2WellKnownUrl": rec.WellKnownUrl, "oauth2Issuer": rec.Issuer, "oauth2ServerUrl": rec.ServerUrl,
		"oauth2TokenUrl": rec.TokenUrl, "oauth2UserInfoUrl": rec.UserInfoUrl,
		"oauth2EndSessionUrl": rec.EndSessionUrl, "oauth2PostLogoutRedirectUrl": rec.PostLogoutRedirect,
	} {
		if v != "" {
			if err := validateHTTPURL(v); err != nil {
				return nil, errors.New("invalid " + name)
			}
		}
	}
	rec.HeaderMappings = opt("oauth2HeaderMappings")
	if _, err := ParseHeaderMappings(rec.HeaderMappings); err != nil {
		return nil, errors.New("oauth2HeaderMappings: " + err.Error())
	}
	rec.AllowedClaims = opt("oauth2AllowedClaims")
	if _, err := ParseClaimRules(rec.AllowedClaims); err != nil {
		return nil, errors.New("oauth2AllowedClaims: " + err.Error())
	}
	rec.GroupsClaim = opt("oauth2GroupsClaim")
	rec.AllowedGroups = opt("oauth2AllowedGroups")
	rec.AllowedEmails = opt("oauth2AllowedEmails")
	rec.AllowedEmailDomains = opt("oauth2AllowedEmailDomains")
	return rec, nil
}

// publicView is the representation returned to the UI: the secret is never sent.
func (rec *providerRecord) publicView() map[string]any {
	ct := DefaultOAuth2ConfigCacheTime
	if rec.CacheTimeSec > 0 {
		ct = time.Duration(rec.CacheTimeSec) * time.Second
	}
	return map[string]any{
		"id": rec.ID, "name": rec.Name, "preset": rec.Preset,
		"oauth2WellKnownUrl": rec.WellKnownUrl, "oauth2Issuer": rec.Issuer, "oauth2ServerUrl": rec.ServerUrl,
		"oauth2TokenUrl": rec.TokenUrl, "oauth2UserInfoUrl": rec.UserInfoUrl, "oauth2ClientId": rec.ClientId,
		"oauth2ClientSecret": secretMask, "oauth2Scopes": rec.Scopes, "oauth2CodeChallengeMethod": rec.CodeChallengeMethod,
		"oauth2ConfigurationCacheTime": ct.String(), "oauth2GroupsClaim": rec.GroupsClaim, "oauth2AllowedGroups": rec.AllowedGroups,
		"oauth2AllowedClaims": rec.AllowedClaims, "oauth2AllowedEmails": rec.AllowedEmails,
		"oauth2AllowedEmailDomains": rec.AllowedEmailDomains, "oauth2HeaderMappings": rec.HeaderMappings,
		"oauth2EndSessionUrl": rec.EndSessionUrl, "oauth2PostLogoutRedirectUrl": rec.PostLogoutRedirect,
		"redirectPath": callbackPathFor(rec.ID),
	}
}

func (ar *OAuth2Router) recordOf(id string) *providerRecord {
	ps := ar.prov(id)
	if ps == nil {
		return nil
	}
	c := ps.config()
	return recordFromOptions(id, c.ProviderName, c)
}

// HandleProviders is the provider manager API:
//
//	GET    ?id=x      one provider (secret masked); without id: the list
//	POST   id=x ...   create or update (blank secret on update keeps the stored one)
//	DELETE id=x       delete; refused while a proxy rule uses it
func (ar *OAuth2Router) HandleProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if id := r.URL.Query().Get("id"); id != "" {
			rec := ar.recordOf(id)
			if rec == nil {
				jsonError(w, "no such provider")
				return
			}
			js, _ := json.Marshal(rec.publicView())
			utils.SendJSONResponse(w, string(js))
			return
		}
		list := []map[string]any{}
		for _, id := range ar.ProviderIDs() {
			v := ar.recordOf(id).publicView()
			if ar.options.InUse != nil {
				v["usedBy"] = ar.options.InUse(id)
			}
			list = append(list, v)
		}
		js, _ := json.Marshal(list)
		utils.SendJSONResponse(w, string(js))
	case http.MethodPost:
		id, _ := utils.PostPara(r, "id")
		id = strings.TrimSpace(id)
		if !ValidProviderID(id) {
			jsonError(w, "id must be 1-32 characters of a-z, 0-9, '-' or '_' and start with a letter or digit")
			return
		}
		prev := ar.recordOf(id)
		if prev == nil && len(ar.ProviderIDs()) >= maxProviders {
			jsonError(w, "too many providers")
			return
		}
		rec, err := parseRecord(r, id, prev, false)
		if err != nil {
			jsonError(w, err.Error())
			return
		}
		if err := ar.saveProvider(rec); err != nil {
			jsonError(w, "could not save: "+err.Error())
			return
		}
		utils.SendOK(w)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if v, err := utils.PostPara(r, "id"); err == nil && v != "" {
			id = v
		}
		if err := ar.deleteProvider(strings.TrimSpace(id)); err != nil {
			jsonError(w, err.Error())
			return
		}
		utils.SendOK(w)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
