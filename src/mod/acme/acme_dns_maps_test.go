package acme_test

import (
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/acme"
	"imuslab.com/zoraxy/mod/acme/acmedns"
)

// Upstream #1067: selfhost.de needs RecordsMapping, which had no UI field and always failed
// with "missing record mapping".
func TestDNSProviderSelfhostdeRecordsMapping(t *testing.T) {
	ok := []string{
		`{"Username":"u","Password":"p","RecordsMapping":"example.org:12345"}`,
		`{"Username":"u","Password":"p","RecordsMapping":"example.org:12345:67890, other.org:111"}`,
		`{"Username":"u","Password":"p","RecordsMapping":"example.org:1\nother.org:2"}`,
		`{"Username":"u","Password":"p","RecordsMapping":"{\"example.org\":[\"1\",\"2\"]}"}`,
		`{"Username":"u","Password":"p","RecordsMapping":{"example.org":"1"}}`,
	}
	for _, creds := range ok {
		p, err := acme.GetDnsChallengeProviderByName("selfhostde", creds, 120)
		if err != nil || p == nil {
			t.Errorf("%s: want a provider, got %v", creds, err)
		}
	}

	bad := map[string]string{
		`{"Username":"u","Password":"p"}`:                                 "RecordsMapping is required",
		`{"Username":"u","Password":"p","RecordsMapping":""}`:             "RecordsMapping is required",
		`{"Username":"u","Password":"p","RecordsMapping":"example.org"}`:  "domain:id",
		`{"Username":"u","Password":"p","RecordsMapping":"a.org:1:2:3"}`:  "one or two record IDs",
		`{"Username":"u","Password":"p","RecordsMapping":"{not json"}`:    "RecordsMapping",
		`{"Username":"","Password":"p","RecordsMapping":"example.org:1"}`: "selfhostde",
	}
	for creds, wantErr := range bad {
		if _, err := acme.GetDnsChallengeProviderByName("selfhostde", creds, 120); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s: want error containing %q, got %v", creds, wantErr, err)
		}
	}
}

// Upstream #410: Hurricane Electric (and the other providers with a Credentials map) are
// selectable and take "name:token" pairs or a JSON object.
func TestDNSProviderCredentialsMap(t *testing.T) {
	for _, name := range []string{"hurricane", "dnshomede", "myaddr"} {
		structure, err := acmedns.GetProviderConfigStructure(name)
		if err != nil {
			t.Fatalf("%s must be listed as a provider: %v", name, err)
		}
		if structure["Credentials"] != "map[string]string" {
			t.Errorf("%s: Credentials field type = %q", name, structure["Credentials"])
		}
	}

	good := []string{
		`{"Credentials":"my.example.org:token1"}`,
		`{"Credentials":"my.example.org:token1,demo.example.org:token2"}`,
		`{"Credentials":"my.example.org:token1\ndemo.example.org:token2"}`,
		`{"Credentials":"{\"my.example.org\":\"token1\"}"}`,
		`{"Credentials":{"my.example.org":"token1"}}`,
		`{"Credentials":"my.example.org:token1","PropagationTimeout":"300","PollingInterval":"5"}`,
	}
	for _, creds := range good {
		p, err := acme.GetDnsChallengeProviderByName("hurricane", creds, 120)
		if err != nil || p == nil {
			t.Errorf("%s: want a provider, got %v", creds, err)
		}
	}

	bad := map[string]string{
		`{}`:                          "credentials missing",
		`{"Credentials":""}`:          "credentials missing",
		`{"Credentials":"nocolon"}`:   "incorrect pair",
		`{"Credentials":"{bad json"}`: "Credentials",
		`{"Credentials":["a"]}`:       "Credentials",
	}
	for creds, wantErr := range bad {
		if _, err := acme.GetDnsChallengeProviderByName("hurricane", creds, 120); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s: want error containing %q, got %v", creds, wantErr, err)
		}
	}
}

// The selfhost.de mapping is a visible form field now
func TestSelfhostdeRecordsMappingIsConfigurable(t *testing.T) {
	structure, err := acmedns.GetProviderConfigStructure("selfhostde")
	if err != nil {
		t.Fatal(err)
	}
	if structure["RecordsMapping"] != "map[string]*Seq" {
		t.Fatalf("RecordsMapping must be a configurable field, got %v", structure)
	}
}
