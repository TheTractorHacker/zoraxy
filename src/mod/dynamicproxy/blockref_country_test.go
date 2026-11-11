package dynamicproxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/blocklog"
)

// country challenge without a CAPTCHA: it is a region block, so the region sentence is right here
func TestCountryChallengeUnavailableIsARegionBlock(t *testing.T) {
	router, sep, bl := refRouter(t, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.RemoteAddr = "198.51.100.3:1000"
	if !router.captchaChallengeFor(w, r, sep, "country", "", "access:Default") {
		t.Fatal("not handled")
	}
	if w.Code != 403 || !strings.Contains(w.Body.String(), "region limit") || !zxRef.MatchString(w.Header().Get("X-Zoraxy-Ref")) {
		t.Errorf("%d %s", w.Code, w.Header())
	}
	e := waitBlocked(t, bl, 1)[0]
	if e.Reason != blocklog.ReasonCountryChallenge || e.Detail != blocklog.DetailChallengeUnavailable || e.RuleID != "access:Default" {
		t.Errorf("entry: %+v", e)
	}
}
