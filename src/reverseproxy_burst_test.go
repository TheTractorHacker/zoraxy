package main

import (
	"net/url"
	"testing"
)

// The rate limit burst is optional in the proxy add/edit API: an absent
// parameter keeps the current value so existing configs and old clients are
// unaffected (fork #168).
func TestRateLimitBurstFromRequest(t *testing.T) {
	cases := []struct {
		name    string
		form    url.Values
		current int64
		want    int64
		wantErr bool
	}{
		{"absent keeps current", url.Values{}, 25, 25, false},
		{"absent keeps zero", url.Values{}, 0, 0, false},
		{"set", url.Values{"rateburst": {"50"}}, 0, 50, false},
		{"zero means same as rate", url.Values{"rateburst": {"0"}}, 25, 0, false},
		{"empty keeps current", url.Values{"rateburst": {""}}, 25, 25, false},
		{"negative rejected", url.Values{"rateburst": {"-1"}}, 25, 0, true},
		{"garbage rejected", url.Values{"rateburst": {"abc"}}, 25, 0, true},
	}
	for _, c := range cases {
		got, err := rateLimitBurstFromRequest(authProviderForm(c.form), c.current)
		if (err != nil) != c.wantErr || (!c.wantErr && got != c.want) {
			t.Errorf("%s: got %d err=%v, want %d err=%v", c.name, got, err, c.want, c.wantErr)
		}
	}
}
