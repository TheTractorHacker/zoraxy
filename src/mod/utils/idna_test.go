package utils

import "testing"

func TestNormalizeHostname(t *testing.T) {
	cases := map[string]string{
		"bücher.example":          "xn--bcher-kva.example",
		"BÜCHER.Example.":         "xn--bcher-kva.example",
		"xn--bcher-kva.example":   "xn--bcher-kva.example",
		"XN--BCHER-KVA.example":   "xn--bcher-kva.example",
		"*.bücher.example":        "*.xn--bcher-kva.example",
		"www.münchen.de":          "www.xn--mnchen-3ya.de",
		"例え.jp":                   "xn--r8jz45g.jp",
		"plain.example.com":       "plain.example.com",
		"":                        "",
		"192.168.1.1":             "192.168.1.1",
		"a_b.example.com":         "a_b.example.com",
		"xn--invalid-punycode-.x": "xn--invalid-punycode-.x",
	}
	for in, want := range cases {
		if got := NormalizeHostname(in); got != want {
			t.Errorf("NormalizeHostname(%q) = %q, want %q", in, got, want)
		}
	}
	if got := DisplayHostname("xn--bcher-kva.example"); got != "bücher.example" {
		t.Errorf("DisplayHostname = %q", got)
	}
	got := NormalizeHostnames([]string{"bücher.example", "xn--bcher-kva.example", " ", "b.example"})
	if len(got) != 2 || got[0] != "xn--bcher-kva.example" || got[1] != "b.example" {
		t.Errorf("NormalizeHostnames = %v", got)
	}
}
