package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/utils"
)

const (
	// DefaultOAuth2ConfigCacheTime defines the default cache duration for the provider metadata
	DefaultOAuth2ConfigCacheTime = 60 * time.Second

	// DefaultScopes are requested when no scopes are configured.
	DefaultScopes = "openid profile email"

	logTitle = "OAuth2Router"
)

type OAuth2RouterOptions struct {
	OAuth2ServerURL              string //The URL of the OAuth 2.0 server server
	OAuth2TokenURL               string //The URL of the OAuth 2.0 token server
	OAuth2ClientId               string //The client id for OAuth 2.0 Application
	OAuth2ClientSecret           string //The client secret for OAuth 2.0 Application
	OAuth2WellKnownUrl           string //The well-known url for OAuth 2.0 server
	OAuth2UserInfoUrl            string //The URL of the OAuth 2.0 user info endpoint
	OAuth2Scopes                 string //The scopes for OAuth 2.0 Application
	OAuth2CodeChallengeMethod    string //The authorization code challenge method: "", "PKCE" (plain) or "PKCE_S256"
	OAuth2ConfigurationCacheTime *time.Duration

	OAuth2Issuer                string //OIDC issuer URL; discovery is fetched from <issuer>/.well-known/openid-configuration
	OAuth2GroupsClaim           string //Claim holding the user's groups (default "groups")
	OAuth2AllowedGroups         string //Comma separated groups; empty allows every authenticated user
	OAuth2AllowedClaims         string //Generalised allow-list "claim=v1,v2; claim2=v3" (see access.go); empty = not checked
	OAuth2AllowedEmails         string //Comma separated e-mail addresses; empty = not checked
	OAuth2AllowedEmailDomains   string //Comma separated e-mail domains; empty = not checked
	OAuth2HeaderMappings        string //Comma separated "Header=claim" pairs forwarded to the upstream
	OAuth2EndSessionUrl         string //Optional override of the provider's end_session_endpoint
	OAuth2PostLogoutRedirectUrl string //Optional post_logout_redirect_uri sent on RP-initiated logout

	// Provider identity (registry entries only; the router level options leave these empty)
	ProviderID     string
	ProviderName   string
	ProviderPreset string

	SystemUUID string //Node UUID (or the key material derived from the cluster secret): session cookie signing key and at-rest encryption key
	SharedKey  bool   //SystemUUID is derived from a cluster secret shared by several nodes (enables portable tickets)

	// InUse returns the proxy rules (host names) that use a provider; a provider in use cannot be deleted.
	InUse func(providerID string) []string

	Logger   *logger.Logger
	Database *database.Database

	// HTTPClient is used for every outbound call to the identity provider (tests may override it).
	HTTPClient *http.Client
}

type OAuth2Router struct {
	mu      sync.RWMutex
	options *OAuth2RouterOptions //router level options (database, logger, keys); the legacy provider values are only used for the first migration
	provs   map[string]*providerState

	client *http.Client
	store  *sessionStore

	now func() time.Time
}

const dbTable = "oauth2"

// NewOAuth2Router creates a new OAuth2Router object
func NewOAuth2Router(options *OAuth2RouterOptions) *OAuth2Router {
	options.Database.NewTable(dbTable)

	//Read settings from database, if exists
	rd := func(key string, dst any) { options.Database.Read(dbTable, key, dst) }
	rd("oauth2WellKnownUrl", &options.OAuth2WellKnownUrl)
	rd("oauth2ServerUrl", &options.OAuth2ServerURL)
	rd("oauth2TokenUrl", &options.OAuth2TokenURL)
	rd("oauth2ClientId", &options.OAuth2ClientId)
	rd("oauth2ClientSecret", &options.OAuth2ClientSecret)
	rd("oauth2UserInfoUrl", &options.OAuth2UserInfoUrl)
	rd("oauth2CodeChallengeMethod", &options.OAuth2CodeChallengeMethod)
	rd("oauth2Scopes", &options.OAuth2Scopes)
	rd("oauth2ConfigurationCacheTime", &options.OAuth2ConfigurationCacheTime)
	rd("oauth2Issuer", &options.OAuth2Issuer)
	rd("oauth2GroupsClaim", &options.OAuth2GroupsClaim)
	rd("oauth2AllowedGroups", &options.OAuth2AllowedGroups)
	rd("oauth2AllowedClaims", &options.OAuth2AllowedClaims)
	rd("oauth2AllowedEmails", &options.OAuth2AllowedEmails)
	rd("oauth2AllowedEmailDomains", &options.OAuth2AllowedEmailDomains)
	rd("oauth2HeaderMappings", &options.OAuth2HeaderMappings)
	rd("oauth2EndSessionUrl", &options.OAuth2EndSessionUrl)
	rd("oauth2PostLogoutRedirectUrl", &options.OAuth2PostLogoutRedirectUrl)

	if options.OAuth2ConfigurationCacheTime == nil ||
		options.OAuth2ConfigurationCacheTime.Seconds() == 0 {
		cacheTime := DefaultOAuth2ConfigCacheTime
		options.OAuth2ConfigurationCacheTime = &cacheTime
	}

	client := options.HTTPClient
	if client == nil {
		client = newHTTPClient()
	}

	ar := &OAuth2Router{
		options: options,
		provs:   map[string]*providerState{},
		client:  client,
		store: newSessionStoreOpt(storeOptions{
			nodeSecret: options.SystemUUID, shared: options.SharedKey, db: options.Database,
		}),
		now: time.Now,
	}
	legacy := *options
	ar.loadProviders(&legacy)
	return ar
}

// Close stops the background session janitors.
func (ar *OAuth2Router) Close() { ar.store.close() }

// snapshot returns a copy of the default provider's settings (zero value when it is not configured).
func (ar *OAuth2Router) snapshot() *OAuth2RouterOptions {
	if ps := ar.prov(DefaultProviderID); ps != nil {
		cp := *ps.config()
		return &cp
	}
	return &OAuth2RouterOptions{}
}

func (ar *OAuth2Router) log(msg string, err error) {
	if ar.options.Logger != nil {
		ar.options.Logger.PrintAndLog(logTitle, msg, err)
	}
}

/* Settings API */

// HandleSetOAuth2Settings is the internal handler for setting the OAuth URL and HTTPS
func (ar *OAuth2Router) HandleSetOAuth2Settings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ar.handleSetOAuthSettingsGET(w, r)
	case http.MethodPost:
		ar.handleSetOAuthSettingsPOST(w, r)
	case http.MethodDelete:
		ar.handleSetOAuthSettingsDELETE(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ar *OAuth2Router) handleSetOAuthSettingsGET(w http.ResponseWriter, r *http.Request) {
	o := ar.snapshot()
	ct := DefaultOAuth2ConfigCacheTime
	if o.OAuth2ConfigurationCacheTime != nil {
		ct = *o.OAuth2ConfigurationCacheTime
	}
	//Return the current settings of the default provider
	js, _ := json.Marshal(map[string]interface{}{
		"oauth2WellKnownUrl":           o.OAuth2WellKnownUrl,
		"oauth2ServerUrl":              o.OAuth2ServerURL,
		"oauth2TokenUrl":               o.OAuth2TokenURL,
		"oauth2UserInfoUrl":            o.OAuth2UserInfoUrl,
		"oauth2Scopes":                 o.OAuth2Scopes,
		"oauth2ClientSecret":           o.OAuth2ClientSecret,
		"oauth2ClientId":               o.OAuth2ClientId,
		"oauth2CodeChallengeMethod":    o.OAuth2CodeChallengeMethod,
		"oauth2ConfigurationCacheTime": ct.String(),
		"oauth2Issuer":                 o.OAuth2Issuer,
		"oauth2GroupsClaim":            o.OAuth2GroupsClaim,
		"oauth2AllowedGroups":          o.OAuth2AllowedGroups,
		"oauth2AllowedClaims":          o.OAuth2AllowedClaims,
		"oauth2AllowedEmails":          o.OAuth2AllowedEmails,
		"oauth2AllowedEmailDomains":    o.OAuth2AllowedEmailDomains,
		"oauth2HeaderMappings":         o.OAuth2HeaderMappings,
		"oauth2EndSessionUrl":          o.OAuth2EndSessionUrl,
		"oauth2PostLogoutRedirectUrl":  o.OAuth2PostLogoutRedirectUrl,
	})

	utils.SendJSONResponse(w, string(js))
}

func jsonError(w http.ResponseWriter, msg string) {
	b, _ := json.Marshal(map[string]string{"error": msg})
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// The legacy single-provider endpoints operate on the provider "default".
func (ar *OAuth2Router) handleSetOAuthSettingsPOST(w http.ResponseWriter, r *http.Request) {
	prev := ar.recordOf(DefaultProviderID)
	rec, err := parseRecord(r, DefaultProviderID, prev, true)
	if err != nil {
		jsonError(w, err.Error())
		return
	}
	if prev != nil {
		rec.Name, rec.Preset = prev.Name, prev.Preset
	} else {
		rec.Name = "Default"
	}
	if err := ar.saveProvider(rec); err != nil {
		jsonError(w, "could not save: "+err.Error())
		return
	}
	utils.SendOK(w)
}

func (ar *OAuth2Router) handleSetOAuthSettingsDELETE(w http.ResponseWriter, r *http.Request) {
	if ar.prov(DefaultProviderID) == nil {
		utils.SendOK(w)
		return
	}
	if err := ar.deleteProvider(DefaultProviderID); err != nil {
		jsonError(w, err.Error())
		return
	}
	utils.SendOK(w)
}

/* Discovery test API */

// HandleDiscoveryTest fetches the discovery document server side and reports what Zoraxy found.
// Parameters (all optional, falling back to the saved settings): oauth2Issuer, oauth2WellKnownUrl.
func (ar *OAuth2Router) HandleDiscoveryTest(w http.ResponseWriter, r *http.Request) {
	o := ar.snapshot()
	issuer, _ := utils.PostPara(r, "oauth2Issuer")
	wk, _ := utils.PostPara(r, "oauth2WellKnownUrl")
	if r.Method == http.MethodGet {
		issuer = r.URL.Query().Get("oauth2Issuer")
		wk = r.URL.Query().Get("oauth2WellKnownUrl")
	}
	issuer, wk = strings.TrimSpace(issuer), strings.TrimSpace(wk)
	if issuer == "" && wk == "" {
		issuer, wk = o.OAuth2Issuer, o.OAuth2WellKnownUrl
	}
	if wk == "" && issuer != "" {
		wk = wellKnownFor(issuer)
	}
	if wk == "" {
		jsonError(w, "provide an issuer URL or a well-known URL")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*httpTimeout)
	defer cancel()
	doc, err := fetchDiscovery(ctx, ar.client, wk, issuer)
	if err != nil {
		jsonError(w, err.Error())
		return
	}

	var warnings []string
	res := map[string]any{
		"wellKnownUrl":          wk,
		"issuer":                doc.Issuer,
		"authorizationEndpoint": doc.AuthorizationEndpoint,
		"tokenEndpoint":         doc.TokenEndpoint,
		"userinfoEndpoint":      doc.UserinfoEndpoint,
		"endSessionEndpoint":    doc.EndSessionEndpoint,
		"jwksUri":               doc.JwksURI,
		"codeChallengeMethods":  doc.CodeChallengeMethodsSupported,
		"pkceS256Supported":     containsStr(doc.CodeChallengeMethodsSupported, "S256"),
		"idTokenSigningAlgs":    doc.IDTokenSigningAlgValuesSupported,
		"scopesSupported":       doc.ScopesSupported,
		"refreshSupported":      containsStr(doc.GrantTypesSupported, "refresh_token"),
		"offlineAccessScope":    containsStr(doc.ScopesSupported, "offline_access"),
	}
	jwksReachable, keyCount := false, 0
	if doc.JwksURI == "" {
		warnings = append(warnings, "Provider publishes no jwks_uri: ID tokens cannot be verified")
	} else {
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := getJSON(ctx, ar.client, doc.JwksURI, &set); err != nil {
			warnings = append(warnings, "JWKS is not reachable: "+err.Error())
		} else {
			jwksReachable, keyCount = true, len(set.Keys)
			if keyCount == 0 {
				warnings = append(warnings, "JWKS is reachable but contains no keys. In Authentik select a Signing Key on the provider.")
			}
		}
	}
	res["jwksReachable"] = jwksReachable
	res["jwksKeyCount"] = keyCount
	if !containsStr(doc.CodeChallengeMethodsSupported, "S256") {
		warnings = append(warnings, "Provider does not advertise PKCE S256 support")
	}
	if doc.EndSessionEndpoint == "" {
		warnings = append(warnings, "No end_session_endpoint: logout will only clear the Zoraxy session")
	}
	if strings.HasPrefix(doc.Issuer, "http://") {
		warnings = append(warnings, "The issuer is plain http: tokens travel unencrypted")
	}
	if len(doc.IDTokenSigningAlgValuesSupported) > 0 && !containsAnyAsym(doc.IDTokenSigningAlgValuesSupported) {
		warnings = append(warnings, "Only HMAC ID token signatures advertised: verified with the client secret")
	}
	res["warnings"] = warnings

	js, _ := json.Marshal(res)
	utils.SendJSONResponse(w, string(js))
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsAnyAsym(algs []string) bool {
	for _, a := range algs {
		if !strings.HasPrefix(a, "HS") && a != "none" {
			return true
		}
	}
	return false
}

/* Provider resolution */

func (ar *OAuth2Router) httpCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, ar.client)
}

// resolve resolves the provider endpoints. Manually configured endpoints take precedence over
// discovery, like they always did. Metadata is cached for OAuth2ConfigurationCacheTime and a stale
// copy is used if the provider is temporarily unreachable.
func (ps *providerState) resolve(ctx context.Context, o *OAuth2RouterOptions) (*providerMeta, error) {
	key := strings.Join([]string{o.OAuth2WellKnownUrl, o.OAuth2Issuer, o.OAuth2ServerURL, o.OAuth2TokenURL,
		o.OAuth2UserInfoUrl, o.OAuth2EndSessionUrl}, "|")
	ttl := DefaultOAuth2ConfigCacheTime
	if o.OAuth2ConfigurationCacheTime != nil && *o.OAuth2ConfigurationCacheTime > 0 {
		ttl = *o.OAuth2ConfigurationCacheTime
	}

	ps.metaMu.Lock()
	defer ps.metaMu.Unlock()
	if ps.meta != nil && ps.metaKey == key && time.Since(ps.meta.fetched) < ttl {
		return ps.meta, nil
	}

	meta := &providerMeta{fetched: time.Now()}
	wk := o.OAuth2WellKnownUrl
	if wk == "" && o.OAuth2Issuer != "" {
		wk = wellKnownFor(o.OAuth2Issuer)
	}
	manualComplete := o.OAuth2ServerURL != "" && o.OAuth2TokenURL != ""
	if wk != "" {
		// Do not hammer an unreachable provider: back off 5s after a failure (all callers share the result).
		if ps.lastErr != nil && ps.errKey == key && time.Since(ps.metaErr) < 5*time.Second {
			if ps.meta != nil && ps.metaKey == key {
				return ps.meta, nil
			}
			return nil, ps.lastErr
		}
		doc, err := fetchDiscovery(ctx, ps.ar.client, wk, o.OAuth2Issuer)
		if err != nil {
			ps.metaErr, ps.lastErr, ps.errKey = time.Now(), err, key
			if ps.meta != nil && ps.metaKey == key && time.Since(ps.meta.fetched) < 24*time.Hour {
				ps.ar.log("Discovery refresh failed, using cached provider metadata", err)
				return ps.meta, nil
			}
			if !manualComplete {
				return nil, err
			}
			ps.ar.log("Discovery failed, using manually configured endpoints", err)
		} else {
			meta = doc.toMeta()
			ps.lastErr = nil
		}
	}
	if o.OAuth2ServerURL != "" {
		meta.AuthURL = o.OAuth2ServerURL
	}
	if o.OAuth2TokenURL != "" {
		meta.TokenURL = o.OAuth2TokenURL
	}
	if o.OAuth2UserInfoUrl != "" {
		meta.UserinfoURL = o.OAuth2UserInfoUrl
	}
	if o.OAuth2EndSessionUrl != "" {
		meta.EndSessionURL = o.OAuth2EndSessionUrl
	}
	if meta.Issuer == "" {
		meta.Issuer = o.OAuth2Issuer
	}
	if meta.AuthURL == "" || meta.TokenURL == "" {
		return nil, errors.New("authorization or token endpoint missing")
	}
	ps.jwks.reset(meta.JWKSURI)
	ps.meta, ps.metaKey = meta, key
	return meta, nil
}

func scopesFor(o *OAuth2RouterOptions, meta *providerMeta) []string {
	scopes := strings.FieldsFunc(o.OAuth2Scopes, func(r rune) bool { return r == ',' || r == ' ' })
	if len(scopes) == 0 {
		scopes = strings.Fields(DefaultScopes)
		if containsStr(meta.ScopesSupported, "offline_access") {
			// Needed by providers such as Authentik to issue a refresh token
			scopes = append(scopes, "offline_access")
		}
	}
	return scopes
}

func (ar *OAuth2Router) oauthConfig(r *http.Request, o *OAuth2RouterOptions, meta *providerMeta) *oauth2.Config {
	cb := callbackPathFor(o.ProviderID)
	sch := "http"
	if r.TLS != nil {
		sch = "https"
	}
	return &oauth2.Config{
		ClientID:     o.OAuth2ClientId,
		ClientSecret: o.OAuth2ClientSecret,
		RedirectURL:  sch + "://" + r.Host + cb,
		Endpoint:     oauth2.Endpoint{AuthURL: meta.AuthURL, TokenURL: meta.TokenURL},
		Scopes:       scopesFor(o, meta),
	}
}

func (ar *OAuth2Router) verifier(ps *providerState, o *OAuth2RouterOptions, meta *providerMeta) *idTokenVerifier {
	return &idTokenVerifier{
		issuer: meta.Issuer, clientID: o.OAuth2ClientId, clientSecret: o.OAuth2ClientSecret,
		meta: meta, jwks: ps.jwks, client: ar.client, now: ar.now,
	}
}

/* Request handling */

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func deny(w http.ResponseWriter, code int, msg string) error {
	noStore(w)
	http.Error(w, msg, code)
	return errors.New("unauthorized")
}

func validRequestHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	return !strings.ContainsAny(h, " /\\?#@\r\n\t")
}

// RuleOptions are the per proxy rule settings of an OAuth2 protected endpoint.
type RuleOptions struct {
	ProviderID          string //provider to use, "" = default
	AllowedGroups       string //additional group allow-list (AND with the provider's)
	AllowedClaims       string //additional "claim=v1,v2; ..." allow-list
	AllowedEmails       string //additional e-mail allow-list
	AllowedEmailDomains string //additional e-mail domain allow-list
}

// ValidateRuleOptions checks the syntax of the per rule allow-lists.
func ValidateRuleOptions(ro RuleOptions) error {
	if _, err := ParseClaimRules(ro.AllowedClaims); err != nil {
		return err
	}
	return nil
}

// ruleAllowed applies the per rule allow-lists on top of the provider's.
func ruleAllowed(ro RuleOptions, groupsClaim string, claims map[string]any) bool {
	if !groupsAllowed(claims, groupsClaim, splitList(ro.AllowedGroups)) {
		return false
	}
	rules, err := ParseClaimRules(ro.AllowedClaims)
	if err != nil || !claimRulesAllowed(claims, rules) {
		return false
	}
	return emailAllowed(claims, splitList(ro.AllowedEmails), splitList(ro.AllowedEmailDomains))
}

// HandleOAuth2Auth authenticates a request with the default provider (legacy entry point).
func (ar *OAuth2Router) HandleOAuth2Auth(w http.ResponseWriter, r *http.Request) error {
	return ar.HandleOAuth2AuthFor(w, r, RuleOptions{})
}

// HandleOAuth2AuthFor is the internal handler for OAuth authentication of one proxy rule.
// It returns nil when the request is authenticated (and may continue to the upstream) and a
// non-nil error when a response (redirect / error) has already been written.
func (ar *OAuth2Router) HandleOAuth2AuthFor(w http.ResponseWriter, r *http.Request, ro RuleOptions) error {
	if !validRequestHost(r.Host) {
		return deny(w, http.StatusBadRequest, "Bad request")
	}
	ps := ar.prov(ro.ProviderID)
	if ps == nil {
		ar.log("OAuth2 provider \""+normProvider(ro.ProviderID)+"\" is not configured", nil)
		return deny(w, http.StatusInternalServerError, "OAuth2 is not configured")
	}
	o := ps.config()
	if o.OAuth2ClientId == "" {
		ar.log("OAuth2 is not configured", nil)
		return deny(w, http.StatusInternalServerError, "OAuth2 is not configured")
	}

	ctx := ar.httpCtx(r.Context())
	meta, err := ps.resolve(ctx, o)
	if err != nil {
		ar.log("Failed to resolve OIDC provider configuration", err)
		return deny(w, http.StatusInternalServerError, "Authentication provider unavailable")
	}
	openid := containsStr(scopesFor(o, meta), "openid")
	if openid && meta.Issuer == "" {
		ar.log("An issuer URL is required when the openid scope is requested", nil)
		return deny(w, http.StatusInternalServerError, "Invalid OAuth2 configuration")
	}
	if !openid && meta.UserinfoURL == "" {
		ar.log("Invalid OAuth2 configuration: no userinfo endpoint and no openid scope", nil)
		return deny(w, http.StatusInternalServerError, "Invalid OAuth2 configuration")
	}
	cfg := ar.oauthConfig(r, o, meta)

	switch r.URL.Path {
	case callbackPathFor(o.ProviderID):
		return ar.handleCallback(ctx, w, r, ps, o, meta, cfg, ro)
	case logoutPathFor(o.ProviderID):
		return ar.handleLogout(w, r, o, meta)
	}

	id, sess := ar.store.lookup(r, o.ProviderID)
	if sess != nil {
		ok, claims := ar.ensureFresh(ctx, ps, o, meta, cfg, sess)
		if !ok {
			ar.store.destroy(id)
			expireCookie(w, r, cookieNameFor(sessionCookie, o.ProviderID))
			expireCookie(w, r, cookieNameFor(ticketCookie, o.ProviderID))
			return ar.startLogin(w, r, o, meta, cfg)
		}
		if !accessAllowed(o, claims) || !ruleAllowed(ro, o.OAuth2GroupsClaim, claims) {
			return ar.forbidden(w, o.ProviderID)
		}
		ar.store.refreshTicket(w, r, sess)
		ar.scrubAll(r)
		mappings, _ := ParseHeaderMappings(o.OAuth2HeaderMappings)
		applyHeaderMappings(r, mappings, claims)
		return nil
	}

	// Anonymous: send the browser to the identity provider.
	return ar.startLogin(w, r, o, meta, cfg)
}

func (ar *OAuth2Router) forbidden(w http.ResponseWriter, provider string) error {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "<!doctype html><title>Access denied</title><h1>Access denied</h1>"+
		"<p>Your account is not allowed to access this application.</p><p><a href=\"%s\">Sign out</a></p>",
		html.EscapeString(logoutPathFor(provider)))
	return errors.New("forbidden")
}

func (ar *OAuth2Router) startLogin(w http.ResponseWriter, r *http.Request, o *OAuth2RouterOptions, meta *providerMeta, cfg *oauth2.Config) error {
	p := &pendingLogin{
		provider:   normProvider(o.ProviderID),
		host:       r.Host,
		nonce:      randomToken(24),
		returnPath: safeReturnPath(r.URL.RequestURI()),
		bind:       randomToken(24),
	}
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	switch o.OAuth2CodeChallengeMethod {
	case "PKCE_S256":
		p.verifier = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(p.verifier))
	case "PKCE":
		p.verifier = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", p.verifier),
			oauth2.SetAuthURLParam("code_challenge_method", "plain"))
	}
	if containsStr(cfg.Scopes, "openid") {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", p.nonce))
	}
	state := ar.store.newPending(p)

	http.SetCookie(w, newCookie(r, pendingCookieName(state), ar.store.sign("bind", p.bind), ar.now().Add(pendingTTL)))
	noStore(w)
	http.Redirect(w, r, cfg.AuthCodeURL(state, opts...), http.StatusFound)
	return errors.New("unauthorized")
}

func (ar *OAuth2Router) handleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, ps *providerState, o *OAuth2RouterOptions, meta *providerMeta, cfg *oauth2.Config, ro RuleOptions) error {
	if r.Method != http.MethodGet {
		return deny(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
	q := r.URL.Query()
	state, code := q.Get("state"), q.Get("code")
	if state == "" {
		return deny(w, http.StatusBadRequest, "Missing state")
	}
	// The state is single use: consume it before anything else can fail.
	item, ok := ar.store.pending.GetAndDelete(state)
	cookieName := pendingCookieName(state)
	bindCookie, cerr := r.Cookie(cookieName)
	expireCookie(w, r, cookieName)
	if !ok || item == nil {
		return deny(w, http.StatusBadRequest, "Login attempt expired or invalid, please try again")
	}
	p := item.Value()
	// CSRF / login-fixation protection: the browser that finished the flow must be the one that started it.
	bind, bok := "", false
	if cerr == nil {
		bind, bok = ar.store.unsign("bind", bindCookie.Value)
	}
	if !bok || bind != p.bind || p.host != r.Host || p.provider != normProvider(o.ProviderID) {
		ar.log("OAuth2 callback rejected: state is not bound to this browser, host or provider", nil)
		return deny(w, http.StatusBadRequest, "Login attempt expired or invalid, please try again")
	}
	if e := q.Get("error"); e != "" {
		ar.log("Identity provider returned error "+e, nil)
		return deny(w, http.StatusForbidden, "Login was not completed")
	}
	if code == "" {
		return deny(w, http.StatusBadRequest, "Missing code")
	}

	var exchOpts []oauth2.AuthCodeOption
	if p.verifier != "" {
		exchOpts = append(exchOpts, oauth2.VerifierOption(p.verifier))
	}
	token, err := cfg.Exchange(ctx, code, exchOpts...)
	if err != nil {
		ar.log("Token exchange failed", err)
		return deny(w, http.StatusUnauthorized, "Unauthorized")
	}
	if !token.Valid() {
		ar.log("Invalid token", nil)
		return deny(w, http.StatusUnauthorized, "Unauthorized")
	}

	idClaims, rawID, err := ar.verifyIDToken(ctx, ps, o, meta, cfg, token, p.nonce, true)
	if err != nil {
		ar.log("ID token validation failed", err)
		return deny(w, http.StatusUnauthorized, "Unauthorized")
	}
	ui, err := ar.fetchUserinfo(ctx, meta, token)
	if err != nil && idClaims == nil {
		ar.log("Failed to get user info", err)
		return deny(w, http.StatusUnauthorized, "Unauthorized")
	}
	if err != nil {
		ar.log("Userinfo unavailable, relying on ID token claims", err)
	}
	claims, err := mergeClaims(idClaims, ui)
	if err != nil {
		ar.log("Claims rejected", err)
		return deny(w, http.StatusUnauthorized, "Unauthorized")
	}

	if !accessAllowed(o, claims) || !ruleAllowed(ro, o.OAuth2GroupsClaim, claims) {
		ar.log(fmt.Sprintf("User %v denied by the group / claim / e-mail allow-list", claims["sub"]), nil)
		return ar.forbidden(w, o.ProviderID)
	}

	now := ar.now()
	sess := &session{provider: normProvider(o.ProviderID), host: r.Host, claims: claims, idToken: rawID, refreshToken: token.RefreshToken}
	sess.accessExpiry = token.Expiry
	if sess.accessExpiry.IsZero() {
		sess.accessExpiry = now.Add(noExpiryLife)
	}
	if token.RefreshToken != "" {
		sess.hardExpiry = now.Add(maxSessionLife)
	} else {
		sess.hardExpiry = sess.accessExpiry
	}
	cookieVal := ar.store.create(sess)
	http.SetCookie(w, newCookie(r, cookieNameFor(sessionCookie, o.ProviderID), cookieVal, sess.hardExpiry))
	ar.store.refreshTicket(w, r, sess)
	// Retire cookies of the previous implementation
	expireCookie(w, r, legacyToken)
	expireCookie(w, r, legacyVerifier)

	noStore(w)
	http.Redirect(w, r, safeReturnPath(p.returnPath), http.StatusFound)
	return errors.New("authorized")
}

// verifyIDToken validates the ID token carried by tok (if any). It returns nil claims when the
// provider issued none and the openid scope was not requested (plain OAuth2 provider).
func (ar *OAuth2Router) verifyIDToken(ctx context.Context, ps *providerState, o *OAuth2RouterOptions, meta *providerMeta, cfg *oauth2.Config, tok *oauth2.Token, nonce string, required bool) (map[string]any, string, error) {
	if !containsStr(cfg.Scopes, "openid") {
		// Plain OAuth2: identity comes from the userinfo endpoint, any id_token is ignored.
		return nil, "", nil
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		if required {
			return nil, "", errors.New("provider returned no id_token although openid was requested")
		}
		return nil, "", nil
	}
	if meta.Issuer == "" {
		return nil, "", errors.New("cannot verify id_token without an issuer")
	}
	claims, err := ar.verifier(ps, o, meta).verify(ctx, raw, nonce)
	return claims, raw, err
}

func (ar *OAuth2Router) fetchUserinfo(ctx context.Context, meta *providerMeta, tok *oauth2.Token) (map[string]any, error) {
	if meta.UserinfoURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.UserinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := ar.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		return nil, fmt.Errorf("userinfo returned HTTP %d", resp.StatusCode)
	}
	out := map[string]any{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// mergeClaims combines verified ID token claims with userinfo claims. ID token claims win; the
// userinfo subject must match the ID token subject (OIDC Core 5.3.2).
func mergeClaims(id, ui map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range id {
		out[k] = v
	}
	if id != nil && ui != nil {
		if a, b := fmt.Sprint(id["sub"]), fmt.Sprint(ui["sub"]); ui["sub"] != nil && a != b {
			return nil, errors.New("userinfo subject does not match id_token subject")
		}
	}
	for k, v := range ui {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no identity claims available")
	}
	return out, nil
}

// ensureFresh refreshes the session's tokens when the access token is about to expire. It
// returns false when the session is no longer valid.
func (ar *OAuth2Router) ensureFresh(ctx context.Context, ps *providerState, o *OAuth2RouterOptions, meta *providerMeta, cfg *oauth2.Config, s *session) (bool, map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := ar.now()
	if now.After(s.hardExpiry) {
		return false, nil
	}
	if now.Before(s.accessExpiry.Add(-refreshSkew)) {
		return true, s.claims
	}
	if s.refreshToken == "" {
		return false, nil
	}
	tok, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: s.refreshToken, Expiry: time.Unix(1, 0)}).Token()
	if err != nil {
		ar.log("Token refresh failed", err)
		return false, nil
	}
	idClaims, rawID, err := ar.verifyIDToken(ctx, ps, o, meta, cfg, tok, "", false)
	if err != nil {
		ar.log("ID token validation after refresh failed", err)
		return false, nil
	}
	ui, _ := ar.fetchUserinfo(ctx, meta, tok) // best effort: the previous claims remain on failure
	var claims map[string]any
	if idClaims != nil {
		if fmt.Sprint(idClaims["sub"]) != fmt.Sprint(s.claims["sub"]) {
			ar.log("Refreshed ID token subject changed, dropping session", nil)
			return false, nil
		}
		claims, err = mergeClaims(idClaims, ui)
	} else {
		// No new ID token: keep the old claims, refresh them from userinfo when available
		claims = map[string]any{}
		for k, v := range s.claims {
			claims[k] = v
		}
		if ui != nil && (ui["sub"] == nil || fmt.Sprint(ui["sub"]) == fmt.Sprint(s.claims["sub"])) {
			for k, v := range ui {
				claims[k] = v
			}
		}
	}
	if err != nil {
		ar.log("Claims rejected after refresh", err)
		return false, nil
	}
	s.claims = claims
	if rawID != "" {
		s.idToken = rawID
	}
	if tok.RefreshToken != "" {
		s.refreshToken = tok.RefreshToken
	}
	s.accessExpiry = tok.Expiry
	if s.accessExpiry.IsZero() {
		s.accessExpiry = now.Add(noExpiryLife)
	}
	claimsOut := s.claims
	if ar.store.persist != nil {
		ar.store.persist.saveHeld(s) //persist the rotated tokens
	}
	return true, claimsOut
}

func (ar *OAuth2Router) handleLogout(w http.ResponseWriter, r *http.Request, o *OAuth2RouterOptions, meta *providerMeta) error {
	id, sess := ar.store.lookup(r, o.ProviderID)
	idToken := ""
	if sess != nil {
		sess.mu.Lock()
		idToken = sess.idToken
		sess.mu.Unlock()
	}
	ar.store.destroy(id)
	expireCookie(w, r, cookieNameFor(sessionCookie, o.ProviderID))
	expireCookie(w, r, cookieNameFor(ticketCookie, o.ProviderID))
	expireCookie(w, r, legacyToken)
	noStore(w)

	target := "/"
	if meta.EndSessionURL != "" {
		u, err := url.Parse(meta.EndSessionURL)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			q := u.Query()
			if idToken != "" {
				q.Set("id_token_hint", idToken)
			}
			q.Set("client_id", o.OAuth2ClientId)
			// Only an admin configured value is ever sent; a caller supplied target is never used.
			if o.OAuth2PostLogoutRedirectUrl != "" {
				q.Set("post_logout_redirect_uri", o.OAuth2PostLogoutRedirectUrl)
			}
			u.RawQuery = q.Encode()
			target = u.String()
		}
	}
	http.Redirect(w, r, target, http.StatusFound)
	return errors.New("logged out")
}

// ScrubIdentityHeaders removes every header that is mapped from OAuth2 claims by any provider, so
// requests that skip authentication through an exception rule cannot carry a forged identity to the upstream.
func (ar *OAuth2Router) ScrubIdentityHeaders(r *http.Request) {
	if ar == nil || r == nil {
		return
	}
	ar.scrubAll(r)
}

func (ar *OAuth2Router) scrubAll(r *http.Request) {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	for _, ps := range ar.provs {
		mappings, _ := ParseHeaderMappings(ps.config().OAuth2HeaderMappings)
		applyHeaderMappings(r, mappings, nil)
	}
}
