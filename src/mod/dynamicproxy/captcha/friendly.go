package captcha

import (
	"bytes"
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
	friendly.go

	Friendly Captcha (v2 API, fork #228 / upstream #1198).

	  - Site key  = the application's sitekey (public, FC_...), used by the widget.
	  - Secret key = an API key (created on the Friendly Captcha dashboard), sent as X-API-Key.
	  - The widget posts its solution in the form field "frc-captcha-response".
	  - Siteverify: POST <endpoint>/api/v2/captcha/siteverify with a JSON body {response, sitekey}
	    and the X-API-Key header. The answer is {success, data:{challenge:{timestamp, origin}}} or
	    {success:false, error:{error_code, detail}}. Only "success" counts; any HTTP status other than
	    200 fails closed (the vendor suggests accepting the visitor then, we do not).
	  - FriendlyEndpoint "eu" selects the dedicated EU endpoints for both the widget and the verification.
*/

const (
	// FriendlyField is the form field the widget stores its solution in.
	FriendlyField = "frc-captcha-response"

	FriendlyEndpointGlobal = "global"
	FriendlyEndpointEU     = "eu"

	friendlyGlobalBase = "https://global.frcapi.com"
	friendlyEUBase     = "https://eu.frcapi.com"
	friendlyVerifyPath = "/api/v2/captcha/siteverify"

	// FriendlySDKVersion is the pinned widget SDK release served from jsDelivr.
	FriendlySDKVersion = "1.1.3"
)

// Siteverify URLs. Variables so tests can point them at an httptest server.
var (
	FriendlyVerifyURLGlobal = friendlyGlobalBase + friendlyVerifyPath
	FriendlyVerifyURLEU     = friendlyEUBase + friendlyVerifyPath
)

// FriendlyResponse is the siteverify answer.
type FriendlyResponse struct {
	Success bool `json:"success"`
	Data    struct {
		EventID   string `json:"event_id"`
		Challenge struct {
			Timestamp string `json:"timestamp"`
			Origin    string `json:"origin"`
		} `json:"challenge"`
	} `json:"data"`
	Error struct {
		Code   string `json:"error_code"`
		Detail string `json:"detail"`
	} `json:"error"`
}

// NormalizeFriendlyEndpoint maps a configured value to "global" or "eu".
func NormalizeFriendlyEndpoint(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), FriendlyEndpointEU) {
		return FriendlyEndpointEU
	}
	return FriendlyEndpointGlobal
}

func friendlyVerifyURL(endpoint string) string {
	if NormalizeFriendlyEndpoint(endpoint) == FriendlyEndpointEU {
		return FriendlyVerifyURLEU
	}
	return FriendlyVerifyURLGlobal
}

// VerifyFriendly verifies a Friendly Captcha solution. When exp.Hostname is set the origin the
// challenge was solved on must be that host.
func VerifyFriendly(token, apiKey, siteKey, endpoint string, exp VerifyExpect) error {
	return verifyFriendlyAt(friendlyVerifyURL(endpoint), token, apiKey, siteKey, exp)
}

func verifyFriendlyAt(verifyURL, token, apiKey, siteKey string, exp VerifyExpect) error {
	if token == "" || apiKey == "" {
		return errors.New("token and API key are required")
	}
	if len(token) > 16*1024 {
		return errors.New("verification failed: response too large")
	}
	payload := map[string]string{"response": token}
	if siteKey != "" {
		payload["sitekey"] = siteKey
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, verifyURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	client := *http.DefaultClient
	client.Timeout = 10 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxSiteverifyBody))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	var result FriendlyResponse
	jsonErr := json.Unmarshal(raw, &result)
	if resp.StatusCode != http.StatusOK {
		//400 / 401 mean a wrong site key or API key: report it to the operator log, never let the visitor in
		if jsonErr == nil && result.Error.Code != "" {
			return fmt.Errorf("verification failed: %s (HTTP %d)", result.Error.Code, resp.StatusCode)
		}
		return fmt.Errorf("verification failed: HTTP %d", resp.StatusCode)
	}
	if jsonErr != nil {
		return fmt.Errorf("failed to parse response: %w", jsonErr)
	}
	if !result.Success {
		code := result.Error.Code
		if code == "" {
			code = "unknown"
		}
		return fmt.Errorf("verification failed: %s", code)
	}
	if exp.Hostname != "" {
		origin := result.Data.Challenge.Origin
		host := origin
		if u, err := url.Parse(origin); err == nil && u.Host != "" {
			host = u.Host
		}
		if host == "" || !sameHost(stripPort(host), exp.Hostname) {
			return fmt.Errorf("verification failed: hostname mismatch (expected %q, got %q)", exp.Hostname, origin)
		}
	}
	return nil
}

func stripPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}
