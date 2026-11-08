package acme_test

import (
	"testing"

	"imuslab.com/zoraxy/mod/acme"
)

// Upstream #331: Route 53 failed with "cannot unmarshal string into ...MaxRetries of type int".
// The UI now sends int fields as JSON numbers (typeint inputs in acme.html); make sure
// the backend accepts exactly that payload and still rejects the old string form.
func TestRoute53IntCredentialFieldsAccepted(t *testing.T) {
	ok := `{"AccessKeyID":"a","SecretAccessKey":"b","Region":"us-east-1","MaxRetries":10,"PropagationTimeout":"120","PollingInterval":"2"}`
	if _, err := acme.GetDnsChallengeProviderByName("route53", ok, 120); err != nil {
		t.Fatalf("numeric MaxRetries must be accepted: %v", err)
	}
	old := `{"AccessKeyID":"a","SecretAccessKey":"b","Region":"us-east-1","MaxRetries":"10"}`
	if _, err := acme.GetDnsChallengeProviderByName("route53", old, 120); err == nil {
		t.Fatal("string MaxRetries is expected to fail (documents the old UI payload)")
	}
}
