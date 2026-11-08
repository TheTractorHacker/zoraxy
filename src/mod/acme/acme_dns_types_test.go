package acme_test

import (
	"testing"

	"imuslab.com/zoraxy/mod/acme"
)

// An API client may send non-string JSON for these fields. That must never
// panic the process (it used to type-assert .(string)); it returns an error,
// or accepts numbers where a number is obviously meant.
func TestGetDnsChallengeProviderNonStringFields(t *testing.T) {
	bad := map[string]string{
		"PollingInterval array":     `{"APIKey":"k","Host":"http://127.0.0.1:1","PollingInterval":["5"]}`,
		"PollingInterval object":    `{"APIKey":"k","Host":"http://127.0.0.1:1","PollingInterval":{"a":1}}`,
		"PropagationTimeout bool":   `{"APIKey":"k","Host":"http://127.0.0.1:1","PropagationTimeout":true}`,
		"PropagationTimeout object": `{"APIKey":"k","Host":"http://127.0.0.1:1","PropagationTimeout":{}}`,
		"Host number":               `{"APIKey":"k","Host":12345}`,
		"Host array":                `{"APIKey":"k","Host":["http://127.0.0.1:1"]}`,
	}
	for name, creds := range bad {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			if _, err := acme.GetDnsChallengeProviderByName("pdns", creds, 120); err == nil {
				t.Fatal("expected an error for a non-string value")
			}
		})
	}

	// numeric intervals are accepted
	creds := `{"APIKey":"k","Host":"http://127.0.0.1:1","PollingInterval":5,"PropagationTimeout":60}`
	if p, err := acme.GetDnsChallengeProviderByName("pdns", creds, 120); err != nil || p == nil {
		t.Fatalf("numeric PollingInterval/PropagationTimeout must be accepted: %v", err)
	}
}
