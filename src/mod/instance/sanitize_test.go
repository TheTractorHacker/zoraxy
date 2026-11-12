package instance

import (
	"strings"
	"testing"
	"time"
)

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

func TestDoctorNeverPrintsEscapes(t *testing.T) {
	evil := "\x1b]0;owned\x07\x1b[2J\x1b[31m"
	a := ProcInfo{Pid: 100, PPid: 90, Comm: "zoraxy" + evil, Exe: "/opt/" + evil + "/zoraxy" + evil, Cmdline: []string{"/x/zoraxy", evil},
		State: 'T', Visible: true, Scope: "session-" + evil + ".scope", CgroupRaw: "/" + evil, Age: time.Minute}
	b := ProcInfo{Pid: 200, Comm: "zoraxy", Exe: "/opt/zoraxy", State: 'S', Visible: true, Unit: "zoraxy" + evil + ".service"}
	r := RunDoctor(opts, probeFor([]ProcInfo{a, b}, []int{100},
		[]ListenSocket{sock(443, 4097, 4096, 100)},
		UnitStatus{Available: true, Exists: true, Active: "active", Sub: "running", MainPID: 200, Fragment: "/etc/" + evil}))
	out := r.String()
	for _, c := range out {
		if c < 0x20 && c != '\n' || c == 0x7f || (c >= 0x80 && c <= 0x9f) {
			t.Fatalf("raw control character %q in report:\n%q", c, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Fatal("ESC leaked")
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatal("expected the escape to be shown in visible form")
	}
	for _, p := range r.Problems {
		if strings.ContainsAny(p.Text, "\x1b\x07") {
			t.Fatal("problem text not sanitised")
		}
	}
}
