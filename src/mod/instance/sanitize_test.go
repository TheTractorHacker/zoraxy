package instance

import "testing"

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"plain /usr/bin/zoraxy -port :8000": "plain /usr/bin/zoraxy -port :8000",
		"naïve ünïcode 日本":                  "naïve ünïcode 日本",
		"a\x1b[2Jb":                         `a\x1b[2Jb`,
		"title\x1b]0;pwned\x07":             `title\x1b]0;pwned\x07`,
		"c1\u009b31m":                       "c1\\x9b31m",
		"bad\xffutf":                        `bad\xffutf`,
		"line\nbreak\rx":                    `line\x0abreak\x0dx`,
		"bidi\u202eevil":                    "bidi\\u202eevil",
		"del\x7f":                           `del\x7f`,
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
