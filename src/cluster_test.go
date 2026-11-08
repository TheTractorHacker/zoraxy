package main

import (
	"testing"

	"imuslab.com/zoraxy/mod/cluster"
)

func payloadOf(files ...cluster.FileEntry) *cluster.Payload {
	return &cluster.Payload{Roots: cluster.ManagedRoots(false), Files: files}
}

func TestValidateClusterPayload(t *testing.T) {
	good := payloadOf(
		cluster.FileEntry{Path: "trusted_proxies.json", Data: []byte(`[{"IP":"10.0.0.0/8","Comment":"x"}]`)},
		cluster.FileEntry{Path: "proxy/a.config", Data: []byte(`{"RootOrMatchingDomain":"a.example.com"}`)},
		cluster.FileEntry{Path: "access/default.json", Data: []byte(`{}`)},
	)
	if err := validateClusterPayload(good); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	badTrusted := payloadOf(cluster.FileEntry{Path: "trusted_proxies.json", Data: []byte(`["10.0.0.0/8"]`)})
	if validateClusterPayload(badTrusted) == nil {
		t.Fatal("schema-invalid trusted_proxies.json accepted")
	}
	badProxy := payloadOf(cluster.FileEntry{Path: "proxy/a.config", Data: []byte(`{"RootOrMatchingDomain":123}`)})
	if validateClusterPayload(badProxy) == nil {
		t.Fatal("schema-invalid proxy config accepted")
	}
}
