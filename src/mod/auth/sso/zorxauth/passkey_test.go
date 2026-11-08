package zorxauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Upstream #1073: passkey (WebAuthn) login. The begin step of the ceremony must produce a challenge bound to the
// host the browser used (also behind a TLS-terminating proxy) and a one-shot token for the complete step.
// (The signature verification itself needs an authenticator and is covered by the go-webauthn library.)
func TestPasskeyAuthBeginBindsRelyingPartyToHost(t *testing.T) {
	_, gs := newTestGateway(t)

	begin := func(host, fwdHost, fwdProto string) map[string]any {
		form := url.Values{"redirect": {"/"}}
		req := httptest.NewRequest(http.MethodPost, "/passkey/auth/begin", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = host
		if fwdHost != "" {
			req.Header.Set("X-Forwarded-Host", fwdHost)
		}
		if fwdProto != "" {
			req.Header.Set("X-Forwarded-Proto", fwdProto)
		}
		rec := httptest.NewRecorder()
		gs.handlePasskeyAuthBegin(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("not JSON: %v %q", err, rec.Body.String())
		}
		return out
	}

	out := begin("auth.example.com:8443", "", "https")
	if out["token"] == nil || out["token"] == "" {
		t.Fatalf("no ceremony token: %v", out)
	}
	pk := out["options"].(map[string]any)["publicKey"].(map[string]any)
	if pk["rpId"] != "auth.example.com" || pk["challenge"] == "" {
		t.Fatalf("unexpected options: %v", pk)
	}

	// Behind a proxy the browser-facing host from X-Forwarded-Host is the relying party.
	out = begin("127.0.0.1:9000", "login.example.org", "https")
	pk = out["options"].(map[string]any)["publicKey"].(map[string]any)
	if pk["rpId"] != "login.example.org" {
		t.Fatalf("relying party not taken from X-Forwarded-Host: %v", pk["rpId"])
	}
}
