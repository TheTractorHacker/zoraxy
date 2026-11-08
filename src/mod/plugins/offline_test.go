package plugins

import (
	"errors"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/offline"
	"imuslab.com/zoraxy/mod/offline/offlinetest"
)

func TestPluginStoreDoesNotDialOffline(t *testing.T) {
	dials := offlinetest.Install(t)
	m := &Manager{}

	offline.Set(false)
	m.getPluginListFromURL("http://plugins.invalid/index.json")
	if dials.Count() == 0 {
		t.Fatal("control run should dial")
	}

	before := dials.Count()
	offline.Set(true)
	if _, err := m.getPluginListFromURL("http://plugins.invalid/index.json"); !errors.Is(err, offline.ErrOffline) {
		t.Fatalf("want ErrOffline, got %v", err)
	}
	if err := downloadFileTo("http://plugins.invalid/p.bin", filepath.Join(t.TempDir(), "p")); !errors.Is(err, offline.ErrOffline) {
		t.Fatalf("want ErrOffline, got %v", err)
	}
	if dials.Count() != before {
		t.Fatal("offline plugin store access attempted a connection")
	}
}
