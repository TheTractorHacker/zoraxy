package updater

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"imuslab.com/zoraxy/mod/offline"
	"imuslab.com/zoraxy/mod/offline/offlinetest"
)

func TestUpdateCheckDoesNotDialOffline(t *testing.T) {
	dials := offlinetest.Install(t)
	s := &source{repo: "o/r", apiBase: "https://api.invalid", client: &http.Client{Transport: &http.Transport{DialContext: dials.FailingDial}}}

	offline.Set(false)
	s.get(context.Background(), "https://api.invalid/x")
	if dials.Count() == 0 {
		t.Fatal("control run should dial")
	}

	before := dials.Count()
	offline.Set(true)
	if _, err := s.get(context.Background(), "https://api.invalid/x"); !errors.Is(err, offline.ErrOffline) {
		t.Fatalf("want ErrOffline, got %v", err)
	}
	if dials.Count() != before {
		t.Fatal("offline update check attempted a connection")
	}
}
