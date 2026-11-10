package utils

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// SendErrorResponse must always produce valid JSON, also for messages with quotes (the admin UI would otherwise report "Request failed (HTTP 200)").
func TestSendErrorResponseIsValidJSON(t *testing.T) {
	for _, msg := range []string{"plain", `invalid status "abc": use codes`, "back\\slash <b>", "line\nbreak", ""} {
		rec := httptest.NewRecorder()
		SendErrorResponse(rec, msg)
		var out map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["error"] != msg {
			t.Fatalf("message %q produced %q (%v)", msg, rec.Body.String(), err)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content type %q", ct)
		}
	}
}
