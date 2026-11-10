package utils

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// Go errors contain quotes and newlines; the body must stay valid JSON (the UI reported
// "Request failed (HTTP 200)" for the invalid body this used to produce).
func TestSendErrorResponseIsValidJSON(t *testing.T) {
	for _, msg := range []string{"plain", `Get "https://example.invalid/x": dial tcp: lookup example.invalid`, "line1\nline2 \\ back", "<b>&</b>"} {
		w := httptest.NewRecorder()
		SendErrorResponse(w, msg)
		var out map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%q: body is not JSON: %v (%s)", msg, err, w.Body.String())
		}
		if out["error"] != msg {
			t.Fatalf("round trip changed the message: %q != %q", out["error"], msg)
		}
	}
	w := httptest.NewRecorder()
	SendErrorResponse(w, "plain")
	if w.Body.String() != `{"error":"plain"}` {
		t.Fatalf("simple messages must keep the exact old format, got %s", w.Body.String())
	}
}
