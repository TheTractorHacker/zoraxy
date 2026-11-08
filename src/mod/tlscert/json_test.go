package tlscert

import (
	"encoding/json"
	"testing"
)

// The reverse proxy status API marshals the router (including this manager) to
// JSON; callback fields must never break that.
func TestManagerMarshalWithCallback(t *testing.T) {
	m := &Manager{OnCertRemoved: func(string) {}}
	if _, err := json.Marshal(m); err != nil {
		t.Fatalf("manager must be JSON marshalable: %v", err)
	}
}
