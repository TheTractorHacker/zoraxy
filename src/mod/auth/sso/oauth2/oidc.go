package oauth2

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

/*
	oidc.go

	OpenID Connect discovery, JWKS handling and ID token validation.
*/

const (
	// httpTimeout bounds every outbound call to the identity provider.
	httpTimeout = 10 * time.Second
	// maxBodyBytes caps the size of any document we read from the identity provider.
	maxBodyBytes = 1 << 20
	// idTokenLeeway is the tolerated clock skew for exp / nbf / iat.
	idTokenLeeway = 60 * time.Second
	// jwksMaxAge is how long a fetched JWKS is trusted before it is refreshed.
	jwksMaxAge = time.Hour
	// defaultJWKSMinRefresh rate limits JWKS refetches triggered by unknown key ids.
	defaultJWKSMinRefresh = 10 * time.Second

	wellKnownSuffix = "/.well-known/openid-configuration"
)

// Asymmetric algorithms accepted for ID tokens. "none" is never accepted.
var asymmetricAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// HMAC algorithms are only accepted when the provider explicitly advertises them in discovery;
// they are verified with the client secret (never with a key from the JWKS).
var hmacAlgs = []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512}

// providerMeta is the resolved set of endpoints for the identity provider.
type providerMeta struct {
	Issuer            string
	AuthURL           string
	TokenURL          string
	UserinfoURL       string
	JWKSURI           string
	EndSessionURL     string
	CodeChallengeMeth []string
	IDTokenAlgs       []string
	ScopesSupported   []string
	GrantTypes        []string
	fetched           time.Time
}

func (m *providerMeta) supportsAlg(alg string) bool {
	for _, a := range m.IDTokenAlgs {
		if a == alg {
			return true
		}
	}
	return false
}

func (m *providerMeta) supportsPKCE(method string) bool {
	for _, a := range m.CodeChallengeMeth {
		if a == method {
			return true
		}
	}
	return false
}

// OIDCDiscoveryDocument is the subset of the provider metadata that we read.
// (Kept as an exported name for backwards compatibility.)
type OIDCDiscoveryDocument struct {
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	Issuer                            string   `json:"issuer"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
}

// validateHTTPURL checks that s is an absolute http(s) URL.
func validateHTTPURL(s string) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("missing host")
	}
	return nil
}

// wellKnownFor returns the discovery URL for an issuer URL.
func wellKnownFor(issuer string) string {
	return strings.TrimRight(strings.TrimSpace(issuer), "/") + wellKnownSuffix
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func getJSON(ctx context.Context, client *http.Client, target string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		return fmt.Errorf("%s returned HTTP %d", target, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(dst)
}

// fetchDiscovery downloads and sanity checks a discovery document. If expectedIssuer is not empty
// the document's issuer must match it (a trailing slash difference is tolerated).
func fetchDiscovery(ctx context.Context, client *http.Client, wellKnown, expectedIssuer string) (*OIDCDiscoveryDocument, error) {
	if err := validateHTTPURL(wellKnown); err != nil {
		return nil, fmt.Errorf("invalid discovery URL: %w", err)
	}
	doc := &OIDCDiscoveryDocument{}
	if err := getJSON(ctx, client, wellKnown, doc); err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}
	if doc.Issuer == "" {
		return nil, errors.New("discovery document has no issuer")
	}
	if expectedIssuer != "" &&
		strings.TrimRight(doc.Issuer, "/") != strings.TrimRight(strings.TrimSpace(expectedIssuer), "/") {
		return nil, fmt.Errorf("issuer mismatch: configured %q, provider reports %q", expectedIssuer, doc.Issuer)
	}
	// An https issuer must not point us at plaintext endpoints.
	if strings.HasPrefix(doc.Issuer, "https://") {
		for name, v := range map[string]string{
			"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint,
			"userinfo_endpoint": doc.UserinfoEndpoint, "jwks_uri": doc.JwksURI, "end_session_endpoint": doc.EndSessionEndpoint,
		} {
			if v != "" && !strings.HasPrefix(v, "https://") {
				return nil, fmt.Errorf("%s is not https although the issuer is", name)
			}
		}
	}
	for name, v := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint,
		"userinfo_endpoint": doc.UserinfoEndpoint, "jwks_uri": doc.JwksURI, "end_session_endpoint": doc.EndSessionEndpoint,
	} {
		if v != "" {
			if err := validateHTTPURL(v); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return doc, nil
}

func (d *OIDCDiscoveryDocument) toMeta() *providerMeta {
	return &providerMeta{
		Issuer:            d.Issuer,
		AuthURL:           d.AuthorizationEndpoint,
		TokenURL:          d.TokenEndpoint,
		UserinfoURL:       d.UserinfoEndpoint,
		JWKSURI:           d.JwksURI,
		EndSessionURL:     d.EndSessionEndpoint,
		CodeChallengeMeth: d.CodeChallengeMethodsSupported,
		IDTokenAlgs:       d.IDTokenSigningAlgValuesSupported,
		ScopesSupported:   d.ScopesSupported,
		GrantTypes:        d.GrantTypesSupported,
		fetched:           time.Now(),
	}
}

/* JWKS cache */

type jwksCache struct {
	mu         sync.Mutex
	uri        string
	keys       []jose.JSONWebKey
	fetched    time.Time
	lastTry    time.Time
	minRefresh time.Duration
}

func (c *jwksCache) reset(uri string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uri != uri {
		c.uri = uri
		c.keys = nil
		c.fetched = time.Time{}
		c.lastTry = time.Time{}
	}
}

func (c *jwksCache) refreshLocked(ctx context.Context, client *http.Client) error {
	c.lastTry = time.Now()
	var set jose.JSONWebKeySet
	if err := getJSON(ctx, client, c.uri, &set); err != nil {
		return fmt.Errorf("jwks fetch failed: %w", err)
	}
	c.keys = set.Keys
	c.fetched = time.Now()
	return nil
}

func (c *jwksCache) matchLocked(kid, alg string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for _, k := range c.keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Algorithm != "" && alg != "" && k.Algorithm != alg {
			continue
		}
		if kid != "" && k.KeyID != kid {
			continue
		}
		out = append(out, k)
	}
	return out
}

// keysFor returns candidate verification keys. The JWKS is refreshed when it is stale or when the
// requested kid is unknown (rate limited so a forged kid cannot make us hammer the provider).
func (c *jwksCache) keysFor(ctx context.Context, client *http.Client, kid, alg string) ([]jose.JSONWebKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uri == "" {
		return nil, errors.New("provider has no jwks_uri")
	}
	min := c.minRefresh
	if min == 0 {
		min = defaultJWKSMinRefresh
	}
	stale := c.fetched.IsZero() || time.Since(c.fetched) > jwksMaxAge
	if stale {
		if err := c.refreshLocked(ctx, client); err != nil {
			return nil, err
		}
	}
	if m := c.matchLocked(kid, alg); len(m) > 0 {
		return m, nil
	}
	if time.Since(c.lastTry) >= min {
		if err := c.refreshLocked(ctx, client); err != nil {
			return nil, err
		}
		if m := c.matchLocked(kid, alg); len(m) > 0 {
			return m, nil
		}
	}
	return nil, fmt.Errorf("no verification key for kid %q", kid)
}

/* ID token verification */

type idTokenVerifier struct {
	issuer       string
	clientID     string
	clientSecret string
	meta         *providerMeta
	jwks         *jwksCache
	client       *http.Client
	now          func() time.Time
}

// verify validates the compact JWT and returns its claims. When nonce is not empty the token's
// nonce claim must equal it.
func (v *idTokenVerifier) verify(ctx context.Context, raw, nonce string) (map[string]any, error) {
	allowed := append([]jose.SignatureAlgorithm{}, asymmetricAlgs...)
	for _, h := range hmacAlgs {
		if v.meta.supportsAlg(string(h)) && v.clientSecret != "" {
			allowed = append(allowed, h)
		}
	}
	tok, err := jwt.ParseSigned(raw, allowed)
	if err != nil {
		return nil, fmt.Errorf("malformed id_token: %w", err)
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("id_token must have exactly one signature")
	}
	hdr := tok.Headers[0]

	var std jwt.Claims
	all := map[string]any{}
	switch jose.SignatureAlgorithm(hdr.Algorithm) {
	case jose.HS256, jose.HS384, jose.HS512:
		if err := tok.Claims([]byte(v.clientSecret), &std, &all); err != nil {
			return nil, fmt.Errorf("id_token signature invalid: %w", err)
		}
	default:
		keys, err := v.jwks.keysFor(ctx, v.client, hdr.KeyID, hdr.Algorithm)
		if err != nil {
			return nil, err
		}
		var verr error
		ok := false
		for _, k := range keys {
			std = jwt.Claims{}
			all = map[string]any{}
			if verr = tok.Claims(k, &std, &all); verr == nil {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("id_token signature invalid: %w", verr)
		}
	}

	if std.Expiry == nil {
		return nil, errors.New("id_token has no exp")
	}
	if std.Subject == "" {
		return nil, errors.New("id_token has no sub")
	}
	if len(std.Audience) == 0 {
		return nil, errors.New("id_token has no aud")
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		Issuer:      v.issuer,
		AnyAudience: jwt.Audience{v.clientID},
		Time:        v.now(),
	}, idTokenLeeway); err != nil {
		return nil, fmt.Errorf("id_token rejected: %w", err)
	}
	if len(std.Audience) > 1 {
		if azp, _ := all["azp"].(string); azp != v.clientID {
			return nil, errors.New("id_token has multiple audiences and azp does not match client id")
		}
	}
	if nonce != "" {
		got, _ := all["nonce"].(string)
		if subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
			return nil, errors.New("id_token nonce mismatch")
		}
	}
	return all, nil
}
