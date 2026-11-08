package acme

import (
	"errors"
	"strings"
	"testing"
)

func TestExplainACMEError(t *testing.T) {
	le := errors.New("error: one or more domains had a problem:\n[sub.example.de] acme: error: 400 :: urn:ietf:params:acme:error:connection :: ip: Fetching https://sub.example.de/.well-known/acme-challenge/x: Error getting validation data")
	got := explainACMEError(le, false)
	if !strings.Contains(got.Error(), "port 80") || !strings.Contains(got.Error(), "Error getting validation data") {
		t.Fatalf("missing hint or original text: %v", got)
	}
	if !errors.Is(got, le) {
		t.Fatal("original error must stay unwrappable")
	}
	if again := explainACMEError(got, false); again.Error() != got.Error() {
		t.Fatal("hint added twice")
	}
	if g := explainACMEError(errors.New("disk full"), false); g.Error() != "disk full" {
		t.Fatalf("unknown errors must pass through: %v", g)
	}
	if explainACMEError(nil, false) != nil {
		t.Fatal("nil in, nil out")
	}
	if g := explainACMEError(le, true); strings.Contains(g.Error(), "port 80") {
		t.Fatal("DNS-01 failures must not suggest forwarding port 80")
	}
}
