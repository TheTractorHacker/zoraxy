package botrules

import (
	"strings"
	"testing"
)

func TestNormalizeAllowUA(t *testing.T) {
	ok := map[string]string{"curl/": "curl/", "  CURL/ ": "curl/", "python-requests/": "python-requests/", "okhttp": "okhttp", "Go-http-client/": "go-http-client/"}
	for in, want := range ok {
		if got, err := NormalizeAllowUA(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	bad := []string{"", "cur", "a/", "///", "mozilla", "Mozilla/", "mozilla/5.0", "chrome", "chrome/", "safari/", "gecko", "applewebkit/537.36", "bot", "http", "windows", "android",
		"firefox/127", "linux", "x86_64", "intel mac", strings.Repeat("a", 65), "curl/\x00", "10.0.0"}
	for _, in := range bad {
		if got, err := NormalizeAllowUA(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestAllowUAToken(t *testing.T) {
	good := map[string]string{"curl/8.18.0": "curl/", "python-requests/2.31.0": "python-requests/", "Wget/1.21.4 (linux-gnu)": "wget/", "okhttp/4.12.0": "okhttp/",
		"Go-http-client/1.1": "go-http-client/", "Java/17.0.2": "java/", "Dalvik/2.1.0 (Linux; U; Android 13)": "dalvik/"}
	for ua, want := range good {
		if got, err := AllowUAToken(ua); err != nil || got != want {
			t.Errorf("%q: %q %v", ua, got, err)
		}
	}
	for _, ua := range []string{"", "Mozilla/5.0 (compatible; Googlebot/2.1)", "Mozilla/5.0 (X11; Linux x86_64) Chrome/1", "Opera/9.80", "ab/1", "(odd)"} {
		if got, err := AllowUAToken(ua); err == nil {
			t.Errorf("%q gave %q", ua, got)
		}
	}
}

func TestAllowUAListAndMatch(t *testing.T) {
	if l, err := NormalizeAllowUAList(nil); l != nil || err != nil {
		t.Fatal(l, err)
	}
	l, err := NormalizeAllowUAList([]string{"CURL/", "curl/", "wget/"})
	if err != nil || len(l) != 2 {
		t.Fatal(l, err)
	}
	many := make([]string, MaxAllowUAs+1)
	for i := range many {
		many[i] = "agent" + string(rune('a'+i)) + "/"
	}
	if _, err := NormalizeAllowUAList(many); err == nil {
		t.Error("over the cap accepted")
	}
	if !AllowedUA(l, "Curl/8.1") || AllowedUA(l, "sqlmap") || AllowedUA(l, "") || AllowedUA(nil, "curl/") {
		t.Error("match")
	}
	if AllowedUA([]string{"ab"}, "ab/1") {
		t.Error("a too short stored entry must never match")
	}
}
