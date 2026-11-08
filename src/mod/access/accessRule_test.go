package access

import (
	"errors"
	"testing"
)

func newGeoErrRule(t *testing.T) *AccessRule {
	c, _ := newTestController(t)
	c.CountryResolver = func(string) (string, error) { return "", errors.New("lookup failed") }
	return &AccessRule{
		ID:                   "t",
		BlacklistEnabled:     true,
		WhitelistEnabled:     true,
		WhiteListCountryCode: &map[string]string{"us": ""},
		WhiteListIP:          &map[string]string{"10.1.0.0/16": ""},
		BlackListContryCode:  &map[string]string{},
		BlackListIP:          &map[string]string{"203.0.113.7": "", "198.51.100.0/24": ""},
		parent:               c,
	}
}

// A GeoIP error must not let a blacklisted IP / CIDR through
func TestIsBlacklisted_GeoErrorStillAppliesIPRules(t *testing.T) {
	r := newGeoErrRule(t)
	for _, ip := range []string{"203.0.113.7", "198.51.100.33"} {
		if !r.IsBlacklisted(ip) {
			t.Errorf("%s should be blacklisted despite GeoIP error", ip)
		}
	}
	if r.IsBlacklisted("192.0.2.1") {
		t.Error("unlisted IP should stay allowed (country check fails open)")
	}
}

// A GeoIP error must not allow-list; explicit IP whitelist still works
func TestIsWhitelisted_GeoErrorFailsClosed(t *testing.T) {
	r := newGeoErrRule(t)
	if r.IsWhitelisted("192.0.2.1") {
		t.Error("non-whitelisted IP must not pass on GeoIP error")
	}
	if !r.IsWhitelisted("10.1.2.3") {
		t.Error("explicitly whitelisted CIDR must pass without GeoIP")
	}
	if r.AllowIpAccess("203.0.113.7") {
		t.Error("blacklisted IP must be denied")
	}
}
