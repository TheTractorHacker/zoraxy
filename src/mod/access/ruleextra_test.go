package access

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDuplicateRuleIsDeepAndPersisted(t *testing.T) {
	c, dir := newTestController(t)
	src := &AccessRule{ID: "src", Name: "Office", BlacklistEnabled: true, DropOnBlock: true,
		BlackListIP: &map[string]string{"203.0.113.0/24": "bad"}}
	if err := c.AddNewAccessRule(src); err != nil {
		t.Fatal(err)
	}
	src.AddChallengeCountry("cn", "x")

	cp, err := c.DuplicateAccessRule("src", "")
	if err != nil {
		t.Fatal(err)
	}
	if cp.ID == "src" || cp.Name != "Office (copy)" || !cp.BlacklistEnabled || !cp.DropOnBlock {
		t.Fatalf("bad copy: %+v", cp)
	}
	if (*cp.BlackListIP)["203.0.113.0/24"] != "bad" || cp.ListChallengeCountries()["cn"] != "x" {
		t.Fatal("lists not copied")
	}
	// deep: editing the copy must not touch the source
	cp.AddIPToBlackList("198.51.100.1", "new")
	cp.AddChallengeCountry("ru", "")
	if _, ok := (*src.BlackListIP)["198.51.100.1"]; ok {
		t.Fatal("copy shares its blacklist map with the source")
	}
	if _, ok := src.ListChallengeCountries()["ru"]; ok {
		t.Fatal("copy shares its challenge list with the source")
	}
	if _, err := os.Stat(filepath.Join(dir, cp.ID+".json")); err != nil {
		t.Fatalf("copy not persisted: %v", err)
	}
	if _, err := c.DuplicateAccessRule("nope", ""); err == nil {
		t.Fatal("duplicating an unknown rule succeeded")
	}
	// the default rule can be duplicated too (the test controller has none loaded)
	c.DefaultAccessRule = &AccessRule{ID: "default", Name: "Default", parent: c}
	if cp, err := c.DuplicateAccessRule("default", "from default"); err != nil || cp.ID == "default" {
		t.Fatal(err)
	}
}

func TestSortAndOrder(t *testing.T) {
	c, _ := newTestController(t)
	c.DefaultAccessRule = &AccessRule{ID: "default", Name: "Default", parent: c}
	for _, n := range []string{"charlie", "Alpha", "bravo"} {
		c.AddNewAccessRule(&AccessRule{ID: "id-" + n, Name: n})
	}
	names := func(mode string) string {
		var out []string
		for _, r := range SortRules(c.ListAllAccessRules(), mode) {
			out = append(out, r.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names("name"); !strings.HasSuffix(got, "Alpha,bravo,charlie") {
		t.Fatalf("name sort: %s", got)
	}
	if r := SortRules(c.ListAllAccessRules(), "name")[0]; r.ID != "default" {
		t.Fatal("default must stay first")
	}
	if err := c.SetRuleOrder([]string{"id-charlie", "id-Alpha", "default", "id-bravo"}); err != nil {
		t.Fatal(err)
	}
	if got := names("manual"); !strings.HasSuffix(got, "charlie,Alpha,bravo") {
		t.Fatalf("manual order: %s", got)
	}
	// stable across repeated listing (sync.Map iteration order is random)
	for i := 0; i < 20; i++ {
		if got := names(""); !strings.HasSuffix(got, "charlie,Alpha,bravo") {
			t.Fatalf("listing not deterministic: %s", got)
		}
	}
	// bad input is rejected without partial writes
	if err := c.SetRuleOrder([]string{"id-bravo", "ghost"}); err == nil {
		t.Fatal("unknown id accepted")
	}
	if err := c.SetRuleOrder([]string{"id-bravo", "id-bravo"}); err == nil {
		t.Fatal("duplicate id accepted")
	}
	if got := names("manual"); !strings.HasSuffix(got, "charlie,Alpha,bravo") {
		t.Fatalf("failed reorder changed the order: %s", got)
	}
}

func TestChallengeCountryValidationAndMatching(t *testing.T) {
	c, _ := newTestController(t)
	c.CountryResolver = func(ip string) (string, error) {
		if ip == "198.51.100.9" {
			return "CN", nil
		}
		return "US", nil
	}
	r := &AccessRule{ID: "r", parent: c}
	for _, bad := range []string{"", "c", "chn", "1x", "c n", "../", "c\x00"} {
		if r.AddChallengeCountry(bad, "") == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	r.parent = c
	r.SaveChanges()
	if r.IsCountryChallenged("198.51.100.9") {
		t.Fatal("empty list must challenge nobody")
	}
	r.AddChallengeCountry("CN", "")
	if !r.IsCountryChallenged("198.51.100.9") || r.IsCountryChallenged("192.0.2.1") || r.IsCountryChallenged("") {
		t.Fatal("matching wrong")
	}
	r.RemoveChallengeCountry("cn")
	if r.IsCountryChallenged("198.51.100.9") {
		t.Fatal("removal failed")
	}
}

// Rules saved by older versions load unchanged, and new fields stay out of the JSON until used
func TestOldRuleJSONCompat(t *testing.T) {
	r := AccessRule{ID: "x", Name: "n"}
	js, _ := json.Marshal(r)
	for _, f := range []string{"SortOrder", "DropOnBlock", "ChallengeCountryCode"} {
		if strings.Contains(string(js), f) {
			t.Errorf("%s serialised while unset", f)
		}
	}
	var back AccessRule
	if err := json.Unmarshal([]byte(`{"ID":"old","Name":"o","BlacklistEnabled":true}`), &back); err != nil || back.DropOnBlock || back.ChallengeCountryCode != nil {
		t.Fatal("old config changed meaning")
	}
}
