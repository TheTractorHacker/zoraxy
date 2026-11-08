package captcha

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/pathmatch"
)

/*
	captcha.go

	CAPTCHA verification and session management for gating access to endpoints.
	Supports Cloudflare Turnstile and Google reCAPTCHA (v2 and v3).
*/

//go:embed cloudflare_turnstile.html
var cloudflareTurnstileTemplate string

//go:embed google_recaptcha_v2.html
var googleRecaptchaV2Template string

//go:embed google_recaptcha_v3.html
var googleRecaptchaV3Template string

const (
	CookieName             = "zoraxy_captcha_session"
	VerifyPath             = "/.zoraxy/captcha/verify"
	DefaultSessionDuration = 3600 // 1 hour in seconds
	CloudflareTurnstileAPI = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	GoogleRecaptchaAPIv2v3 = "https://www.google.com/recaptcha/api/siteverify"
)

// Provider represents the CAPTCHA provider type
type Provider int

const (
	ProviderCloudflare Provider = 0
	ProviderGoogle     Provider = 1
)

// ExceptionType defines the type of CAPTCHA exception rule
type ExceptionType int

const (
	ExceptionTypePaths ExceptionType = 0x00
	ExceptionTypeCIDR  ExceptionType = 0x01
)

// Config holds the configuration for CAPTCHA
type Config struct {
	Provider              Provider         `json:"Provider"`
	SiteKey               string           `json:"SiteKey"`
	SecretKey             string           `json:"SecretKey"`
	SessionDuration       int              `json:"SessionDuration"`
	RecaptchaVersion      string           `json:"RecaptchaVersion"`      // v2 or v3
	RecaptchaScore        float64          `json:"RecaptchaScore"`        // v3 only, 0.0-1.0
	ProtectedPathPrefixes []string         `json:"ProtectedPathPrefixes"` // Empty means protect all paths on this endpoint
	ExceptionRules        []*ExceptionRule `json:"ExceptionRules"`
}

// ExceptionRule defines rules for bypassing CAPTCHA
type ExceptionRule struct {
	RuleType   ExceptionType `json:"RuleType"`
	PathPrefix string        `json:"PathPrefix"` // For path-based exceptions
	CIDR       string        `json:"CIDR"`       // For IP-based exceptions
}

// SessionStore issues and validates CAPTCHA sessions.
//
// Sessions are stateless: the cookie value is a signed token carrying the
// expiry time and the host it was issued for, so nothing is kept in memory.
// A session therefore survives a Zoraxy restart, and every node that shares
// the same secret accepts it (needed for high availability). The trade-off is
// that a single session cannot be revoked early; rotate the secret to
// invalidate all of them.
type SessionStore struct {
	key []byte
}

// Reasons returned by CheckSessionReason, useful when debugging re-challenges.
const (
	ReasonOK      = "ok"
	ReasonMissing = "no-cookie"
	ReasonInvalid = "invalid"
	ReasonExpired = "expired"
	ReasonHost    = "wrong-host"
)

const (
	// MinSessionDuration and MaxSessionDuration bound the configurable
	// session length (seconds). Values outside the range are clamped.
	MinSessionDuration = 60
	MaxSessionDuration = 30 * 24 * 3600
	tokenVersion       = "v1"
)

// NewSessionStore creates a session store with a random secret. Sessions
// issued by it are lost on restart; use NewSessionStoreWithSecret for
// restart-proof sessions.
func NewSessionStore() *SessionStore {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("captcha: cannot read system randomness: " + err.Error())
	}
	return &SessionStore{key: key}
}

// NewSessionStoreWithSecret creates a session store whose signing key is
// derived from secret (for example the node UUID). Stores built from the same
// secret accept each other's sessions.
func NewSessionStoreWithSecret(secret string) *SessionStore {
	sum := sha256.Sum256([]byte("zoraxy-captcha-session-v1|" + secret))
	return &SessionStore{key: sum[:]}
}

// ClampSessionDuration forces a duration (seconds) into the allowed range.
// Zero or negative means "use the default".
func ClampSessionDuration(seconds int) int {
	if seconds <= 0 {
		return DefaultSessionDuration
	}
	if seconds < MinSessionDuration {
		return MinSessionDuration
	}
	if seconds > MaxSessionDuration {
		return MaxSessionDuration
	}
	return seconds
}

func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (s *SessionStore) sign(payload string) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// Issue creates a signed session token for host that expires after
// durationSeconds (clamped to the allowed range).
func (s *SessionStore) Issue(host string, durationSeconds int) (token string, expires time.Time) {
	expires = time.Now().Add(time.Duration(ClampSessionDuration(durationSeconds)) * time.Second)
	payload := tokenVersion + "|" + strconv.FormatInt(expires.Unix(), 10) + "|" + normalizeHost(host)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(s.sign(payload)), expires
}

// Validate checks a token against host and returns the reason it was accepted
// or rejected (one of the Reason constants).
func (s *SessionStore) Validate(host, token string) (bool, string) {
	encPayload, encMac, found := strings.Cut(token, ".")
	if !found {
		return false, ReasonInvalid
	}
	payloadBytes, err1 := base64.RawURLEncoding.DecodeString(encPayload)
	gotMac, err2 := base64.RawURLEncoding.DecodeString(encMac)
	if err1 != nil || err2 != nil {
		return false, ReasonInvalid
	}
	payload := string(payloadBytes)
	if !hmac.Equal(gotMac, s.sign(payload)) {
		return false, ReasonInvalid
	}
	parts := strings.SplitN(payload, "|", 3)
	if len(parts) != 3 || parts[0] != tokenVersion {
		return false, ReasonInvalid
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false, ReasonInvalid
	}
	if time.Now().Unix() >= exp {
		return false, ReasonExpired
	}
	if parts[2] != normalizeHost(host) {
		return false, ReasonHost
	}
	return true, ReasonOK
}

// Close is kept for API compatibility; the store holds no resources.
func (s *SessionStore) Close() {}

// CloudflareTurnstileResponse represents the response from Cloudflare Turnstile API
type CloudflareTurnstileResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

// GoogleRecaptchaResponse represents the response from Google reCAPTCHA API
type GoogleRecaptchaResponse struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`        // v3 only
	Action      string   `json:"action"`       // v3 only
	ChallengeTS string   `json:"challenge_ts"` // ISO timestamp
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// VerifyCloudflareToken verifies a Cloudflare Turnstile token
func VerifyCloudflareToken(token, secretKey, remoteIP string) (bool, error) {
	if token == "" || secretKey == "" {
		return false, errors.New("token and secret key are required")
	}

	formData := url.Values{
		"secret":   {secretKey},
		"response": {token},
	}
	if net.ParseIP(remoteIP) != nil {
		formData.Add("remoteip", remoteIP)
	}

	resp, err := http.PostForm(CloudflareTurnstileAPI, formData)
	if err != nil {
		return false, fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response: %w", err)
	}

	var result CloudflareTurnstileResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	if !result.Success {
		return false, fmt.Errorf("verification failed: %v", result.ErrorCodes)
	}

	return true, nil
}

// VerifyGoogleRecaptchaToken verifies a Google reCAPTCHA token
func VerifyGoogleRecaptchaToken(token, secretKey, remoteIP string, version string, minScore float64) (bool, error) {
	if token == "" || secretKey == "" {
		return false, errors.New("token and secret key are required")
	}

	formData := url.Values{
		"secret":   {secretKey},
		"response": {token},
	}
	if net.ParseIP(remoteIP) != nil {
		formData.Add("remoteip", remoteIP)
	}

	resp, err := http.PostForm(GoogleRecaptchaAPIv2v3, formData)
	if err != nil {
		return false, fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response: %w", err)
	}

	var result GoogleRecaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	if !result.Success {
		return false, fmt.Errorf("verification failed: %v", result.ErrorCodes)
	}

	// For v3, check the score
	if version == "v3" {
		if result.Score < minScore {
			return false, fmt.Errorf("score too low: %f < %f", result.Score, minScore)
		}
	}

	return true, nil
}

// CheckException checks if the request matches any exception rules.
// clientIP must be resolved by the caller with the endpoint's trusted proxy
// policy (see Router.GetClientIPForEndpoint). This package does not read
// forwarding headers itself, so a direct client cannot claim an exempted
// address by sending X-Real-Ip, X-Forwarded-For, etc.
func CheckException(r *http.Request, rules []*ExceptionRule, clientIP string) bool {
	if len(rules) == 0 {
		return false
	}

	requesterIP := net.ParseIP(clientIP)
	requestTarget := pathmatch.RequestTarget(r)

	for _, rule := range rules {
		if rule == nil {
			continue
		}
		switch rule.RuleType {
		case ExceptionTypePaths:
			if pathmatch.RequestPathWithinPrefix(requestTarget, rule.PathPrefix) {
				return true
			}
		case ExceptionTypeCIDR:
			if requesterIP != nil && ipMatchesRule(requesterIP, rule.CIDR) {
				return true
			}
		}
	}

	return false
}

// ipMatchesRule reports whether ip is the single address or falls in the CIDR
// range given by rule. Addresses are compared after parsing so that equivalent
// notations (e.g. "::1" and "0:0:0:0:0:0:0:1") match the same rule.
func ipMatchesRule(ip net.IP, rule string) bool {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return false
	}

	if strings.Contains(rule, "/") {
		_, ipNet, err := net.ParseCIDR(rule)
		return err == nil && ipNet.Contains(ip)
	}

	ruleIP := net.ParseIP(rule)
	return ruleIP != nil && ruleIP.Equal(ip)
}

func normalizeProtectedPathPrefix(pathPrefix string) string {
	pathPrefix = strings.TrimSpace(pathPrefix)
	if pathPrefix == "" {
		return ""
	}

	if !strings.HasPrefix(pathPrefix, "/") {
		pathPrefix = "/" + pathPrefix
	}

	if pathPrefix != "/" {
		pathPrefix = strings.TrimSuffix(pathPrefix, "/")
	}

	return pathPrefix
}

func pathPrefixMatch(requestPath string, pathPrefix string) bool {
	normalizedPrefix := normalizeProtectedPathPrefix(pathPrefix)
	if normalizedPrefix == "" {
		return false
	}
	if normalizedPrefix == "/" {
		//All endpoints are protected if the prefix is "/"
		return true
	}

	return pathmatch.RequestPathWithinPrefix(requestPath, normalizedPrefix)
}

// ShouldEnforcePath returns true when CAPTCHA should apply to the request path.
// If no protected path prefixes are configured, CAPTCHA applies to all paths.
func ShouldEnforcePath(requestPath string, config *Config) bool {
	if config == nil || len(config.ProtectedPathPrefixes) == 0 {
		return true
	}

	for _, pathPrefix := range config.ProtectedPathPrefixes {
		if pathPrefixMatch(requestPath, pathPrefix) {
			return true
		}
	}

	return false
}

// TemplateData holds the data for rendering CAPTCHA templates
type TemplateData struct {
	Domain     string
	SiteKey    string
	VerifyPath string
}

// loadExternalTemplate tries to load an external template from the filesystem
func loadExternalTemplate(webDir string, templateName string) (string, error) {
	// Try both .html and .tmpl extensions
	possiblePaths := []string{
		filepath.Join(webDir, "templates", templateName+".html"),
		filepath.Join(webDir, "templates", templateName+".tmpl"),
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			// File exists, read it
			content, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("failed to read external template: %w", err)
			}
			return string(content), nil
		}
	}

	return "", os.ErrNotExist
}

// RenderChallenge renders the CAPTCHA challenge page
func RenderChallenge(w http.ResponseWriter, r *http.Request, config *Config, domain string, webDir string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	// Prepare template data
	data := TemplateData{
		Domain:     domain,
		SiteKey:    config.SiteKey,
		VerifyPath: VerifyPath,
	}

	var templateContent string
	var templateName string

	// Determine which template to use based on provider
	if config.Provider == ProviderCloudflare {
		templateName = "captcha_cloudflare"
		// Try to load external template first
		if webDir != "" {
			external, err := loadExternalTemplate(webDir, templateName)
			if err == nil {
				templateContent = external
			}
		}
		// Fall back to embedded template
		if templateContent == "" {
			templateContent = cloudflareTurnstileTemplate
		}
	} else {
		version := config.RecaptchaVersion
		if version == "" {
			version = "v2"
		}

		if version == "v2" {
			templateName = "captcha_recaptcha_v2"
			// Try to load external template first
			if webDir != "" {
				external, err := loadExternalTemplate(webDir, templateName)
				if err == nil {
					templateContent = external
				}
			}
			// Fall back to embedded template
			if templateContent == "" {
				templateContent = googleRecaptchaV2Template
			}
		} else {
			templateName = "captcha_recaptcha_v3"
			// Try to load external template first
			if webDir != "" {
				external, err := loadExternalTemplate(webDir, templateName)
				if err == nil {
					templateContent = external
				}
			}
			// Fall back to embedded template
			if templateContent == "" {
				templateContent = googleRecaptchaV3Template
			}
		}
	}

	// Parse and execute template
	tmpl, err := template.New(templateName).Parse(templateContent)
	if err != nil {
		http.Error(w, "Failed to parse template", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		return
	}

	w.Write(buf.Bytes())
}

// HandleVerification processes CAPTCHA verification requests. clientIP is
// forwarded to the provider as remoteip and must be resolved by the caller
// with the endpoint's trusted proxy policy, same as CheckException.
func HandleVerification(w http.ResponseWriter, r *http.Request, config *Config, sessionStore *SessionStore, clientIP string) error {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return errors.New("invalid method")
	}

	// Parse form data - handle both regular forms and multipart forms
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(1 << 20); err != nil { // 1 MB max
			http.Error(w, "Bad request", http.StatusBadRequest)
			return err
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return err
		}
	}

	// Try to get token from POST form first, then from regular form
	token := r.PostFormValue("cf-turnstile-response")
	token = strings.TrimSpace(token)
	if token == "" {
		token = r.PostFormValue("g-recaptcha-response")
		token = strings.TrimSpace(token)
	}
	if token == "" {
		token = r.FormValue("cf-turnstile-response")
		token = strings.TrimSpace(token)
	}
	if token == "" {
		token = r.FormValue("g-recaptcha-response")
		token = strings.TrimSpace(token)
	}

	if token == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "CAPTCHA token missing",
		})
		return errors.New("token missing")
	}

	var verified bool
	var verifyErr error

	// Verify based on provider
	switch config.Provider {
	case ProviderCloudflare:
		verified, verifyErr = VerifyCloudflareToken(token, config.SecretKey, clientIP)
	case ProviderGoogle:
		version := config.RecaptchaVersion
		if version == "" {
			version = "v2"
		}
		minScore := config.RecaptchaScore
		if minScore == 0 {
			minScore = 0.5
		}
		verified, verifyErr = VerifyGoogleRecaptchaToken(token, config.SecretKey, clientIP, version, minScore)
	default:
		http.Error(w, "Invalid CAPTCHA provider", http.StatusInternalServerError)
		return errors.New("invalid provider")
	}

	if verifyErr != nil || !verified {
		// Verification failed
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		errorMsg := "CAPTCHA verification failed"
		if verifyErr != nil {
			errorMsg = verifyErr.Error()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   errorMsg,
		})
		return fmt.Errorf("verification failed: %v", errorMsg)
	}

	// Create a signed session bound to this host
	duration := ClampSessionDuration(config.SessionDuration)
	sessionToken, expires := sessionStore.Issue(r.Host, duration)

	// Set cookie. Expires is set as well as MaxAge so clients that ignore
	// MaxAge still expire the session at the same moment.
	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   duration,
		Expires:  expires,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})

	// Return error to stop request chain (response already written)
	return errors.New("response already written - captcha verified")
}

// CheckSession checks if a request has a valid CAPTCHA session
func CheckSession(r *http.Request, sessionStore *SessionStore) bool {
	ok, _ := CheckSessionReason(r, sessionStore)
	return ok
}

// CheckSessionReason is CheckSession plus the reason for the decision.
func CheckSessionReason(r *http.Request, sessionStore *SessionStore) (bool, string) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return false, ReasonMissing
	}
	return sessionStore.Validate(r.Host, cookie.Value)
}

// IsConfigured checks if the CAPTCHA config is properly set up
func (config *Config) IsConfigured() bool {
	if config == nil {
		return false
	}
	if config.SiteKey == "" || config.SecretKey == "" {
		return false
	}
	return true
}
