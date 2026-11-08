package dynamicproxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// /api/proxy/status marshals RouterOption. Key material must never be part of that
// response, and the struct must stay marshalable (func-typed exported fields made
// the Status page fail before).
func TestRouterOptionJSONHasNoSecrets(t *testing.T) {
	opt := RouterOption{HostUUID: "node-uuid", SessionSecret: "derived-cluster-secret-key"}
	b, err := json.Marshal(&opt)
	if err != nil {
		t.Fatalf("RouterOption must be JSON-marshalable: %v", err)
	}
	if strings.Contains(string(b), "derived-cluster-secret-key") || strings.Contains(string(b), "SessionSecret") {
		t.Fatalf("RouterOption JSON leaks the session secret: %s", b)
	}
}
