package main

import (
	"os"
	"strings"
	"testing"
)

// Both admin listeners (plain HTTP and HTTPS via -webui_tls) must confirm a pending in-app update once they are
// bound. The HTTPS branch once returned without doing so, which rolled every update back after 90 seconds.
func TestBothAdminListenersConfirmUpdateHealth(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "updateManager.MarkHealthy()"); n < 2 {
		t.Fatalf("main.go confirms update health %d time(s); the plain and the HTTPS admin listener both need it", n)
	}
}
