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
	OAuth2HeaderMappings        string //Comma separated "Header=claim" pairs forwarded to the upstream
	OAuth2EndSessionUrl         string //Optional override of the provider's end_session_endpoint
	OAuth2PostLogoutRedirectUrl string //Optional post_logout_redirect_uri sent on RP-initiated logout

	SystemUUID string //Node UUID, the session cookie signing key is derived from it

	Logger   *logger.Logger
	Database *database.Database

	// HTTPClient is used for every outbound call to the identity provider (tests may override it).
	HTTPClient *http.Client
}

type OAuth2Router struct {
	mu      sync.RWMutex
	options *OAuth2RouterOptions

	client *http.Client
	store  *sessionStore
	jwks   *jwksCache

	metaMu  sync.Mutex
	meta    *providerMeta
	metaKey string
	metaErr time.Time

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

	return &OAuth2Router{
		options: options,
		client:  client,
		store:   newSessionStore(options.SystemUUID),
		jwks:    &jwksCache{},
		now:     time.Now,
	}
}

// Close stops the background session janitors.
func (ar *OAuth2Router) Close() { ar.store.close() }

func (ar *OAuth2Router) snapshot() *OAuth2RouterOptions {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	cp := *ar.options
	return &cp
}

func (ar *OAuth2Router) log(msg string, err error) {
	if ar.options.Logger != nil {
		ar.options.Logger.PrintAndLog(logTitle, msg, err)
	}
}

func (ar *OAuth2Router) flushCaches() {
	ar.metaMu.Lock()
	ar.meta = nil
	ar.metaKey = ""
	ar.metaMu.Unlock()
	ar.store.sessions.DeleteAll()
	ar.store.pending.DeleteAll()
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
	//Return the current settings
	js, _ := json.Marshal(map[string]interface{}{
		"oauth2WellKnownUrl":           o.OAuth2WellKnownUrl,
		"oauth2ServerUrl":              o.OAuth2ServerURL,
		"oauth2TokenUrl":               o.OAuth2TokenURL,
		"oauth2UserInfoUrl":            o.OAuth2UserInfoUrl,
		"oauth2Scopes":                 o.OAuth2Scopes,
		"oauth2ClientSecret":           o.OAuth2ClientSecret,
		"oauth2ClientId":               o.OAuth2ClientId,
		"oauth2CodeChallengeMethod":    o.OAuth2CodeChallengeMethod,
		"oauth2ConfigurationCacheTime": o.OAuth2ConfigurationCacheTime.String(),
		"oauth2Issuer":                 o.OAuth2Issuer,
		"oauth2GroupsClaim":            o.OAuth2GroupsClaim,
		"oauth2AllowedGroups":          o.OAuth2AllowedGroups,
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

func (ar *OAuth2Router) handleSetOAuthSettingsPOST(w http.ResponseWriter, r *http.Request) {
	opt := func(key string) string {
		v, _ := utils.PostPara(r, key)
		return strings.TrimSpace(v)
	}

	oauth2ClientId, err := utils.PostPara(r, "oauth2ClientId")
	if err != nil {
		utils.SendErrorResponse(w, "oauth2ClientId not found")
		return
	}

	oauth2ClientSecret, err := utils.PostPara(r, "oauth2ClientSecret")
	if err != nil {
		utils.SendErrorResponse(w, "oauth2ClientSecret not found")
		return
	}

	oauth2CodeChallengeMethod := opt("oauth2CodeChallengeMethod")
	switch oauth2CodeChallengeMethod {
	case "", "plain", "PKCE", "PKCE_S256": // "plain" (UI label "None") means no PKCE
	default:
		utils.SendErrorResponse(w, "oauth2CodeChallengeMethod must be empty, plain, PKCE or PKCE_S256")
		return
	}

	cacheTime := DefaultOAuth2ConfigCacheTime
	oauth2ConfigurationCacheTime := &cacheTime
	if d, err := utils.PostDuration(r, "oauth2ConfigurationCacheTime"); err == nil && d != nil && *d > 0 {
		oauth2ConfigurationCacheTime = d
	}

	oauth2WellKnownUrl := opt("oauth2WellKnownUrl")
	oauth2Issuer := strings.TrimSpace(opt("oauth2Issuer"))
	oauth2ServerUrl := opt("oauth2ServerUrl")
	oauth2TokenURL := opt("oauth2TokenUrl")
	oauth2UserInfoUrl := opt("oauth2UserInfoUrl")
	oauth2Scopes := opt("oauth2Scopes")

	if oauth2WellKnownUrl == "" && oauth2Issuer == "" {
		// Manual endpoint configuration needs the three endpoints (legacy behavior)
		if oauth2ServerUrl == "" || oauth2TokenURL == "" {
			utils.SendErrorResponse(w, "set an issuer / well-known URL, or both the authorization and token endpoints")
			return
		}
	}
	for name, v := range map[string]string{
		"oauth2WellKnownUrl": oauth2WellKnownUrl, "oauth2Issuer": oauth2Issuer, "oauth2ServerUrl": oauth2ServerUrl,
		"oauth2TokenUrl": oauth2TokenURL, "oauth2UserInfoUrl": oauth2UserInfoUrl,
		"oauth2EndSessionUrl": opt("oauth2EndSessionUrl"), "oauth2PostLogoutRedirectUrl": opt("oauth2PostLogoutRedirectUrl"),
	} {
		if v != "" {
			if err := validateHTTPURL(v); err != nil {
				utils.SendErrorResponse(w, "invalid "+name)
				return
			}
		}
	}
	headerMappings := opt("oauth2HeaderMappings")
	if _, err := ParseHeaderMappings(headerMappings); err != nil {
		jsonError(w, "oauth2HeaderMappings: "+err.Error())
		return
	}

	ar.mu.Lock()
	o := ar.options
	o.OAuth2WellKnownUrl = oauth2WellKnownUrl
	o.OAuth2ServerURL = oauth2ServerUrl
	o.OAuth2TokenURL = oauth2TokenURL
	o.OAuth2UserInfoUrl = oauth2UserInfoUrl
	o.OAuth2ClientId = oauth2ClientId
	o.OAuth2ClientSecret = oauth2ClientSecret
	o.OAuth2Scopes = oauth2Scopes
	o.OAuth2CodeChallengeMethod = oauth2CodeChallengeMethod
	o.OAuth2ConfigurationCacheTime = oauth2ConfigurationCacheTime
	o.OAuth2Issuer = oauth2Issuer
	o.OAuth2GroupsClaim = opt("oauth2GroupsClaim")
	o.OAuth2AllowedGroups = opt("oauth2AllowedGroups")
	o.OAuth2HeaderMappings = headerMappings
	o.OAuth2EndSessionUrl = opt("oauth2EndSessionUrl")
	o.OAuth2PostLogoutRedirectUrl = opt("oauth2PostLogoutRedirectUrl")
	ar.mu.Unlock()

	//Write changes to database
	wr := func(key string, v any) { ar.options.Database.Write(dbTable, key, v) }
	wr("oauth2WellKnownUrl", oauth2WellKnownUrl)
	wr("oauth2ServerUrl", oauth2ServerUrl)
	wr("oauth2TokenUrl", oauth2TokenURL)
	wr("oauth2UserInfoUrl", oauth2UserInfoUrl)
	wr("oauth2ClientId", oauth2ClientId)
	wr("oauth2ClientSecret", oauth2ClientSecret)
	wr("oauth2Scopes", oauth2Scopes)
	wr("oauth2CodeChallengeMethod", oauth2CodeChallengeMethod)
	wr("oauth2ConfigurationCacheTime", oauth2ConfigurationCacheTime)
	wr("oauth2Issuer", oauth2Issuer)
	wr("oauth2GroupsClaim", o.OAuth2GroupsClaim)
	wr("oauth2AllowedGroups", o.OAuth2AllowedGroups)
	wr("oauth2HeaderMappings", headerMappings)
	wr("oauth2EndSessionUrl", o.OAuth2EndSessionUrl)
	wr("oauth2PostLogoutRedirectUrl", o.OAuth2PostLogoutRedirectUrl)

	// Flush caches and sessions: changed group rules / secrets must apply immediately
	ar.flushCaches()

	utils.SendOK(w)
}

func (ar *OAuth2Router) handleSetOAuthSettingsDELETE(w http.ResponseWriter, r *http.Request) {
	ar.mu.Lock()
	o := ar.options
	o.OAuth2WellKnownUrl, o.OAuth2ServerURL, o.OAuth2TokenURL, o.OAuth2UserInfoUrl = "", "", "", ""
	o.OAuth2ClientId, o.OAuth2ClientSecret, o.OAuth2Scopes, o.OAuth2CodeChallengeMethod = "", "", "", ""
	o.OAuth2Issuer, o.OAuth2GroupsClaim, o.OAuth2AllowedGroups, o.OAuth2HeaderMappings = "", "", "", ""
	o.OAuth2EndSessionUrl, o.OAuth2PostLogoutRedirectUrl = "", ""
	ar.mu.Unlock()

	for _, k := range []string{"oauth2WellKnownUrl", "oauth2ServerUrl", "oauth2TokenUrl", "oauth2UserInfoUrl",
		"oauth2ClientId", "oauth2ClientSecret", "oauth2Scopes", "oauth2CodeChallengeMethod", "oauth2ConfigurationCacheTime",
		"oauth2Issuer", "oauth2GroupsClaim", "oauth2AllowedGroups", "oauth2HeaderMappings", "oauth2EndSessionUrl",
		"oauth2PostLogoutRedirectUrl"} {
		ar.options.Database.Delete(dbTable, k)
	}
	ar.flushCaches()

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

// provider resolves the provider endpoints. Manually configured endpoints take precedence over
// discovery, like they always did. Metadata is cached for OAuth2ConfigurationCacheTime and a stale
// copy is used if the provider is temporarily unreachable.
func (ar *OAuth2Router) provider(ctx context.Context, o *OAuth2RouterOptions) (*providerMeta, error) {
	key := strings.Join([]string{o.OAuth2WellKnownUrl, o.OAuth2Issuer, o.OAuth2ServerURL, o.OAuth2TokenURL,
		o.OAuth2UserInfoUrl, o.OAuth2EndSessionUrl}, "|")
	ttl := DefaultOAuth2ConfigCacheTime
	if o.OAuth2ConfigurationCacheTime != nil && *o.OAuth2ConfigurationCacheTime > 0 {
		ttl = *o.OAuth2ConfigurationCacheTime
	}

	ar.metaMu.Lock()
	defer ar.metaMu.Unlock()
	if ar.meta != nil && ar.metaKey == key && time.Since(ar.meta.fetched) < ttl {
		return ar.meta, nil
	}

	meta := &providerMeta{fetched: time.Now()}
	wk := o.OAuth2WellKnownUrl
	if wk == "" && o.OAuth2Issuer != "" {
		wk = wellKnownFor(o.OAuth2Issuer)
	}
	manualComplete := o.OAuth2ServerURL != "" && o.OAuth2TokenURL != ""
	if wk != "" {
		// Do not hammer an unreachable provider: back off 5s after a failure.
		if ar.meta != nil && ar.metaKey == key && time.Since(ar.metaErr) < 5*time.Second {
			return ar.meta, nil
		}
		doc, err := fetchDiscovery(ctx, ar.client, wk, o.OAuth2Issuer)
		if err != nil {
			ar.metaErr = time.Now()
			if ar.meta != nil && ar.metaKey == key && time.Since(ar.meta.fetched) < 24*time.Hour {
				ar.log("Discovery refresh failed, using cached provider metadata", err)
				return ar.meta, nil
			}
			if !manualComplete {
				return nil, err
			}
			ar.log("Discovery failed, using manually configured endpoints", err)
		} else {
			meta = doc.toMeta()
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
	ar.jwks.reset(meta.JWKSURI)
	ar.meta, ar.metaKey = meta, key
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
	sch := "http"
	if r.TLS != nil {
		sch = "https"
	}
	return &oauth2.Config{
		ClientID:     o.OAuth2ClientId,
		ClientSecret: o.OAuth2ClientSecret,
		RedirectURL:  sch + "://" + r.Host + callbackPrefix,
		Endpoint:     oauth2.Endpoint{AuthURL: meta.AuthURL, TokenURL: meta.TokenURL},
		Scopes:       scopesFor(o, meta),
	}
}

func (ar *OAuth2Router) verifier(o *OAuth2RouterOptions, meta *providerMeta) *idTokenVerifier {
	return &idTokenVerifier{
		issuer: meta.Issuer, clientID: o.OAuth2ClientId, clientSecret: o.OAuth2ClientSecret,
		meta: meta, jwks: ar.jwks, client: ar.client, now: ar.now,
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

// HandleOAuth2Auth is the internal handler for OAuth authentication.
// It returns nil when the request is authenticated (and may continue to the upstream) and a
// non-nil error when a response (redirect / error) has already been written.
func (ar *OAuth2Router) HandleOAuth2Auth(w http.ResponseWriter, r *http.Request) error {
	o := ar.snapshot()
	if !validRequestHost(r.Host) {
		return deny(w, http.StatusBadRequest, "Bad request")
	}
	if o.OAuth2ClientId == "" {
		ar.log("OAuth2 is not configured", nil)
		return deny(w, http.StatusInternalServerError, "OAuth2 is not configured")
	}

	ctx := ar.httpCtx(r.Context())
	meta, err := ar.provider(ctx, o)
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
	case callbackPrefix:
		return ar.handleCallback(ctx, w, r, o, meta, cfg)
	case logoutPath:
		return ar.handleLogout(w, r, o, meta)
	}

	id, sess := ar.store.lookup(r)
	if sess != nil {
		ok, claims := ar.ensureFresh(ctx, o, meta, cfg, sess)
		if !ok {
			ar.store.destroy(id)
			expireCookie(w, r, sessionCookie)
			return ar.startLogin(w, r, o, meta, cfg)
		}
		if !groupsAllowed(claims, o.OAuth2GroupsClaim, splitList(o.OAuth2AllowedGroups)) {
			return ar.forbidden(w)
		}
		mappings, _ := ParseHeaderMappings(o.OAuth2HeaderMappings)
		applyHeaderMappings(r, mappings, claims)
		return nil
	}

	// Anonymous: send the browser to the identity provider.
	return ar.startLogin(w, r, o, meta, cfg)
}

func (ar *OAuth2Router) forbidden(w http.ResponseWriter) error {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "<!doctype html><title>Access denied</title><h1>Access denied</h1>"+
		"<p>Your account is not allowed to access this application.</p><p><a href=\"%s\">Sign out</a></p>",
		html.EscapeString(logoutPath))
	return errors.New("forbidden")
}

func (ar *OAuth2Router) startLogin(w http.ResponseWriter, r *http.Request, o *OAuth2RouterOptions, meta *providerMeta, cfg *oauth2.Config) error {
	p := &pendingLogin{
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

func (ar *OAuth2Router) handleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, o *OAuth2RouterOptions, meta *providerMeta, cfg *oauth2.Config) error {
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
	if !bok || bind != p.bind || p.host != r.Host {
		ar.log("OAuth2 callback rejected: state is not bound to this browser or host", nil)
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

	idClaims, rawID, err := ar.verifyIDToken(ctx, o, meta, cfg, token, p.nonce, true)
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

	if !groupsAllowed(claims, o.OAuth2GroupsClaim, splitList(o.OAuth2AllowedGroups)) {
		ar.log(fmt.Sprintf("User %v denied by group allow-list", claims["sub"]), nil)
		return ar.forbidden(w)
	}

	now := ar.now()
	sess := &session{host: r.Host, claims: claims, idToken: rawID, refreshToken: token.RefreshToken}
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
	http.SetCookie(w, newCookie(r, sessionCookie, cookieVal, sess.hardExpiry))
	// Retire cookies of the previous implementation
	expireCookie(w, r, legacyToken)
	expireCookie(w, r, legacyVerifier)

	noStore(w)
	http.Redirect(w, r, safeReturnPath(p.returnPath), http.StatusFound)
	return errors.New("authorized")
}

// verifyIDToken validates the ID token carried by tok (if any). It returns nil claims when the
// provider issued none and the openid scope was not requested (plain OAuth2 provider).
func (ar *OAuth2Router) verifyIDToken(ctx context.Context, o *OAuth2RouterOptions, meta *providerMeta, cfg *oauth2.Config, tok *oauth2.Token, nonce string, required bool) (map[string]any, string, error) {
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
	claims, err := ar.verifier(o, meta).verify(ctx, raw, nonce)
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
func (ar *OAuth2Router) ensureFresh(ctx context.Context, o *OAuth2RouterOptions, meta *providerMeta, cfg *oauth2.Config, s *session) (bool, map[string]any) {
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
	idClaims, rawID, err := ar.verifyIDToken(ctx, o, meta, cfg, tok, "", false)
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
	return true, s.claims
}

func (ar *OAuth2Router) handleLogout(w http.ResponseWriter, r *http.Request, o *OAuth2RouterOptions, meta *providerMeta) error {
	id, sess := ar.store.lookup(r)
	idToken := ""
	if sess != nil {
		sess.mu.Lock()
		idToken = sess.idToken
		sess.mu.Unlock()
	}
	ar.store.destroy(id)
	expireCookie(w, r, sessionCookie)
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
