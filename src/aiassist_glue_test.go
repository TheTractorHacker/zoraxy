package main

import (
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/blocklog"
)

func TestAIEventLookupAndBackupExclusion(t *testing.T) {
	bl := blocklog.New(filepath.Join(t.TempDir(), "bl.json"), 100, blocklog.DefaultSettings())
	old := blockLog
	blockLog = bl
	defer func() { blockLog = old }()
	bl.Record(blocklog.Entry{Time: 1700000000, IP: "198.51.100.1", Host: "a.test", Method: "GET", Path: "/x", Status: 403, Reason: "waf"})
	bl.Record(blocklog.Entry{Time: 1700000001, IP: "198.51.100.2", Host: "a.test", Method: "GET", Path: "/y", Status: 403, Reason: "waf"})
	var ev aiEvents
	e, ok := ev.BlockEntry(1)
	if !ok || e.Path != "/x" {
		t.Fatalf("seq 1: %+v %v", e, ok)
	}
	if e, ok = ev.BlockEntry(2); !ok || e.Path != "/y" {
		t.Fatalf("seq 2: %+v %v", e, ok)
	}
	if _, ok = ev.BlockEntry(99); ok {
		t.Fatal("unknown seq found")
	}
	if _, ok = ev.WAFEvent("nope"); ok {
		t.Fatal("unknown txid found")
	}
}
