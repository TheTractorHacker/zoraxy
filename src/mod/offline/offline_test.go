package offline_test

import (
	"errors"
	"testing"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/geodb"
	"imuslab.com/zoraxy/mod/offline"
	"imuslab.com/zoraxy/mod/offline/offlinetest"
)

func TestCheck(t *testing.T) {
	offline.Set(false)
	if offline.Check() != nil || offline.Enabled() {
		t.Fatal("default must be online")
	}
	offline.Set(true)
	defer offline.Set(false)
	if !errors.Is(offline.Check(), offline.ErrOffline) {
		t.Fatal("offline must return ErrOffline")
	}
}

// Start-up and background paths must not even try to connect in offline mode, and the same harness must
// see the dial when online (control run) so the test cannot pass vacuously.
func TestGeoDBDownloadDoesNotDialOffline(t *testing.T) {
	dials := offlinetest.Install(t)

	offline.Set(false)
	geodb.DownloadGeoDBUpdateToPath(t.TempDir())
	if dials.Count() == 0 {
		t.Fatal("control run: the online path should have attempted a dial")
	}

	before := dials.Count()
	offline.Set(true)
	if err := geodb.DownloadGeoDBUpdateToPath(t.TempDir()); !errors.Is(err, offline.ErrOffline) {
		t.Fatalf("want ErrOffline, got %v", err)
	}
	if dials.Count() != before {
		t.Fatal("offline GeoIP update attempted a connection")
	}
}

func TestPublicIPLookupDoesNotDialOffline(t *testing.T) {
	dials := offlinetest.Install(t)
	c := &access.Controller{}

	offline.Set(false)
	c.UpdatePublicIP()
	if dials.Count() == 0 {
		t.Fatal("control run: the online path should have attempted a dial")
	}

	before := dials.Count()
	offline.Set(true)
	if err := c.UpdatePublicIP(); !errors.Is(err, offline.ErrOffline) {
		t.Fatalf("want ErrOffline, got %v", err)
	}
	if dials.Count() != before {
		t.Fatal("offline public IP lookup attempted a connection")
	}
}
