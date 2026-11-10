package utils

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestSendErrorResponseIsAlwaysValidJSON(t *testing.T) {
	for _, msg := range []string{"plain", `parse "not host": invalid character " "`, "back\\slash", "line\nbreak", "<b>html</b> & more"} {
		rec := httptest.NewRecorder()
		SendErrorResponse(rec, msg)
		var out map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["error"] != msg {
			t.Errorf("%q: got %q (%v)", msg, rec.Body.String(), err)
		}
	}
}
