package tlscert

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/acme"
)

func TestCertListShowsIssuerKeyTypeAndManagedBy(t *testing.T) {
	m := newTestManager(t)
	put := func(name string, cn string, info *acme.CertificateInfoJSON) {
		c, k := selfPair(t, cn, time.Now().Add(10*24*time.Hour))
		os.WriteFile(filepath.Join(m.CertStore, name+".pem"), c, 0o644)
		os.WriteFile(filepath.Join(m.CertStore, name+".key"), k, 0o600)
		if info != nil {
			acme.SaveCertInfoJSON(filepath.Join(m.CertStore, name+".json"), info, 0o644)
		}
	}
	put("le", "le.example", &acme.CertificateInfoJSON{AcmeName: "Let's Encrypt", ManagedBy: "acme", CAProfileID: "p1"})
	put("legacy", "legacy.example", &acme.CertificateInfoJSON{AcmeName: "Let's Encrypt"})
	put("up", "up.example", nil)
	put("dir", "dir.example", &acme.CertificateInfoJSON{ManagedBy: "mapdir", Source: "/certs/dir"})
	put("req", "req.example", &acme.CertificateInfoJSON{ManagedBy: "csr"})

	rec := httptest.NewRecorder()
	m.HandleListCertificate(rec, httptest.NewRequest("GET", "/api/cert/list?date=true", nil))
	var list []struct {
		Filename, Issuer, KeyType, ManagedBy, CAProfileID, Source string
		Renewable                                                 bool
		RemainingDays                                             int
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	got := map[string]int{}
	for i, c := range list {
		got[c.Filename] = i
	}
	check := func(name, managed string, renewable bool) {
		c := list[got[name]]
		if c.ManagedBy != managed || c.Renewable != renewable || c.KeyType != "EC256" {
			t.Errorf("%s: %+v", name, c)
		}
		if c.RemainingDays < 8 || c.RemainingDays > 10 {
			t.Errorf("%s: remaining days %d", name, c.RemainingDays)
		}
	}
	check("le", "acme", true)
	check("legacy", "acme", true)
	check("up", "upload", true)
	check("dir", "mapdir", false)
	check("req", "csr", false)
	if list[got["le"]].Issuer != "Let's Encrypt" || list[got["le"]].CAProfileID != "p1" || list[got["dir"]].Source != "/certs/dir" {
		t.Errorf("issuer/profile/source missing: %+v", list)
	}
}
