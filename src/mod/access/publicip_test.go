package access

import (
	"errors"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, errors.New("network disabled in tests")
}

func newPublicIPTestController(t *testing.T, skip bool) *Controller {
	t.Helper()
	dir := t.TempDir()
	db, err := database.NewDatabase(filepath.Join(dir, "db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	lg, _ := logger.NewFmtLogger()
	c, err := NewAccessController(&Options{
		Logger:             *lg,
		ConfigFolder:       filepath.Join(dir, "access"),
		TrustedProxiesFile: filepath.Join(dir, "tp.json"),
		Database:           db,
		SkipPublicIPCheck:  skip,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Tests must be able to build an access controller without calling
// checkip.amazonaws.com (fork #250).
func TestSkipPublicIPCheckMakesNoNetworkCall(t *testing.T) {
	orig := http.DefaultTransport
	ct := &countingTransport{}
	http.DefaultTransport = ct
	t.Cleanup(func() { http.DefaultTransport = orig })

	c := newPublicIPTestController(t, true)
	time.Sleep(200 * time.Millisecond)
	if n := ct.n.Load(); n != 0 {
		t.Fatalf("public IP lookup made %d network calls despite SkipPublicIPCheck", n)
	}
	if c.ServerPublicIP != "127.0.0.1" {
		t.Errorf("unexpected public IP %q", c.ServerPublicIP)
	}
}
