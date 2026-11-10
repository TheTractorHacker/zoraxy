package main

import "testing"

func TestIsDevOnlyPage(t *testing.T) {
	cases := map[string]bool{
		"/ui/kit.html":        true,
		"/index.html":         false,
		"/components/ui.html": false,
		"/ui/kit.css":         false,
	}
	for p, want := range cases {
		if got := isDevOnlyPage(p); got != want {
			t.Errorf("isDevOnlyPage(%q) = %v, want %v", p, got, want)
		}
	}
}
