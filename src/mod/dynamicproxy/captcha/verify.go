package captcha

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

/*
	verify.go

	Server side token verification (siteverify) for Turnstile and reCAPTCHA.
*/

// VerifyExpect lists what the siteverify response must match. Empty fields are
// not checked.
type VerifyExpect struct {
	Action   string  // Turnstile action / reCAPTCHA v3 action
	CData    string  // Turnstile cData
	Hostname string  // host the challenge was served for (port is ignored)
	Version  string  // reCAPTCHA: "v2" or "v3"
	MinScore float64 // reCAPTCHA v3 minimum score
}

const maxSiteverifyBody = 1 << 20

// siteverify POSTs the token to a provider and decodes the JSON answer into out.
func siteverify(endpoint, token, secretKey, remoteIP string, out interface{}) error {
	if token == "" || secretKey == "" {
		return errors.New("token and secret key are required")
	}
	form := url.Values{"secret": {secretKey}, "response": {token}}
	if net.ParseIP(remoteIP) != nil {
		form.Add("remoteip", remoteIP)
	}

	// Copy of the default client: keeps any test transport, adds a timeout.
	client := *http.DefaultClient
	client.Timeout = 10 * time.Second
	resp, err := client.PostForm(endpoint, form)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSiteverifyBody))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	return nil
}

func sameHost(a, b string) bool {
	norm := func(h string) string {
		h = strings.TrimSpace(strings.ToLower(h))
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		return strings.Trim(strings.TrimSuffix(h, "."), "[]")
	}
	return norm(a) == norm(b)
}

// VerifyTurnstile verifies a Cloudflare Turnstile token and checks the action,
// cData and hostname of the answer against exp.
func VerifyTurnstile(token, secretKey, remoteIP string, exp VerifyExpect) error {
	var result CloudflareTurnstileResponse
	if err := siteverify(TurnstileVerifyURL, token, secretKey, remoteIP, &result); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("verification failed: %v", result.ErrorCodes)
	}
	if exp.Action != "" && result.Action != exp.Action {
		return fmt.Errorf("verification failed: action mismatch (expected %q, got %q)", exp.Action, result.Action)
	}
	if exp.CData != "" && result.CData != exp.CData {
		return errors.New("verification failed: cdata mismatch")
	}
	if exp.Hostname != "" && !sameHost(result.Hostname, exp.Hostname) {
		return fmt.Errorf("verification failed: hostname mismatch (expected %q, got %q)", exp.Hostname, result.Hostname)
	}
	return nil
}

// VerifyRecaptcha verifies a Google reCAPTCHA token. For v3 the score and the
// action name are checked; the hostname is checked when exp.Hostname is set.
func VerifyRecaptcha(token, secretKey, remoteIP string, exp VerifyExpect) error {
	var result GoogleRecaptchaResponse
	if err := siteverify(RecaptchaVerifyURL, token, secretKey, remoteIP, &result); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("verification failed: %v", result.ErrorCodes)
	}
	if exp.Version == "v3" {
		if result.Score < exp.MinScore {
			return fmt.Errorf("score too low: %f < %f", result.Score, exp.MinScore)
		}
		if exp.Action != "" && result.Action != exp.Action {
			return fmt.Errorf("verification failed: action mismatch (expected %q, got %q)", exp.Action, result.Action)
		}
	}
	if exp.Hostname != "" && !sameHost(result.Hostname, exp.Hostname) {
		return fmt.Errorf("verification failed: hostname mismatch (expected %q, got %q)", exp.Hostname, result.Hostname)
	}
	return nil
}

// VerifyCloudflareToken verifies a Cloudflare Turnstile token without any
// action / hostname binding. Kept for API compatibility.
func VerifyCloudflareToken(token, secretKey, remoteIP string) (bool, error) {
	if err := VerifyTurnstile(token, secretKey, remoteIP, VerifyExpect{}); err != nil {
		return false, err
	}
	return true, nil
}

// VerifyGoogleRecaptchaToken verifies a Google reCAPTCHA token (score only for
// v3). Kept for API compatibility.
func VerifyGoogleRecaptchaToken(token, secretKey, remoteIP string, version string, minScore float64) (bool, error) {
	if err := VerifyRecaptcha(token, secretKey, remoteIP, VerifyExpect{Version: version, MinScore: minScore}); err != nil {
		return false, err
	}
	return true, nil
}

// expectationsFor builds the siteverify expectations for a request.
func (c *Config) expectationsFor(r *http.Request) VerifyExpect {
	exp := VerifyExpect{}
	if c.VerifyHostname {
		exp.Hostname = r.Host
	}
	switch c.Provider {
	case ProviderCloudflare:
		if c.Turnstile != nil {
			exp.Action = c.Turnstile.Action
			exp.CData = c.Turnstile.CData
		}
	case ProviderGoogle:
		exp.Version = c.RecaptchaVersion
		if exp.Version == "" {
			exp.Version = "v2"
		}
		exp.MinScore = c.RecaptchaScore
		if exp.MinScore == 0 {
			exp.MinScore = 0.5
		}
		if exp.Version == "v3" {
			exp.Action = c.recaptchaAction()
		}
	}
	return exp
}

func (c *Config) recaptchaAction() string {
	if c.RecaptchaAction != "" {
		return c.RecaptchaAction
	}
	return "access"
}
