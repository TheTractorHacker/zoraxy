package ech

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestClassifyConfigs(t *testing.T) {
	m := newMgr(t, true)
	first := m.Keys()[0]
	if _, err := m.Rotate(); err != nil {
		t.Fatal(err)
	}
	keys := m.Keys()
	var active, retired KeyInfo
	for _, k := range keys {
		if k.State == StateActive {
			active = k
		} else {
			retired = k
		}
	}
	if retired.ID != first.ID {
		t.Fatal("expected the first key to be retired")
	}
	cl := func(cfgB64 string) ParsedConfig {
		raw, _ := base64.StdEncoding.DecodeString(cfgB64)
		out, err := Classify(base64.StdEncoding.EncodeToString(ConfigList(raw)), keys, pubName)
		if err != nil || len(out) != 1 {
			t.Fatalf("classify: %v %v", out, err)
		}
		return out[0]
	}
	if c := cl(active.Config); c.Class != ClassOursActive || c.PublicName != pubName || c.ConfigID != active.ConfigID {
		t.Errorf("active: %+v", c)
	}
	if c := cl(retired.Config); c.Class != ClassOursRetired {
		t.Errorf("retired: %+v", c)
	}
	// same public name and id, other key material -> a key that was purged
	other := base64.StdEncoding.EncodeToString(BuildConfig(active.ConfigID, make([]byte, 32), 64, pubName))
	if c := cl(other); c.Class != ClassOursPurged {
		t.Errorf("purged: %+v", c)
	}
	// a CDN's config
	foreign := base64.StdEncoding.EncodeToString(BuildConfig(7, make([]byte, 32), 64, "cloudflare-ech.com"))
	if c := cl(foreign); c.Class != ClassForeign || c.PublicName != "cloudflare-ech.com" {
		t.Errorf("foreign: %+v", c)
	}
	if _, err := ParseConfigList([]byte{0, 9, 1}); err == nil {
		t.Error("garbage must not parse")
	}
}

func TestViewFromRecordsAndAdvice(t *testing.T) {
	m := newMgr(t, true)
	v := m.viewFromRecords(DomainView{}, nil)
	if v.Status != ClassNone || v.Advice == "" {
		t.Errorf("no record: %+v", v)
	}
	foreign := BuildConfig(7, make([]byte, 32), 64, "cloudflare-ech.com")
	rr := &dns.HTTPS{SVCB: dns.SVCB{Priority: 1, Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: ConfigList(foreign)}}}}
	v = m.viewFromRecords(DomainView{}, []*dns.HTTPS{rr})
	if v.Status != ClassForeign || !strings.Contains(v.Advice, "cloudflare-ech.com") {
		t.Errorf("foreign record: %+v", v)
	}
}

func TestNoteOuterHandshakeRateLimit(t *testing.T) {
	m := newMgr(t, true)
	if m.NoteOuterHandshake(true) {
		t.Error("valid cert must not warn")
	}
	if !m.NoteOuterHandshake(false) || m.NoteOuterHandshake(false) {
		t.Error("exactly one warning expected inside the rate limit window")
	}
	if tot, bad := m.OuterStats(); tot != 3 || bad != 2 {
		t.Errorf("stats %d %d", tot, bad)
	}
}
