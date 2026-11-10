package webserv

import "testing"

// ChangePort used ws.server before the first Start() created it: a nil pointer panic on an
// install where the static server never ran. Invalid ports must be refused before anything else.
func TestChangePortRefusesInvalidPortsWithoutPanic(t *testing.T) {
	ws, _, _ := newTestWebDAV(t) // server is nil, nothing was ever started
	for _, p := range []string{"0", "99999", "-1", "abc", ""} {
		if err := ws.ChangePort(p); err == nil {
			t.Fatalf("port %q must be refused", p)
		}
	}
}
