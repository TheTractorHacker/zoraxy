package aiassist

import (
	"math/rand"
	"strings"
	"testing"
)

func TestPathDelimitersNeverLeakValues(t *testing.T) {
	r := testRedactor(Policy{SendPaths: true})
	cases := []struct{ in, want string }{
		{"/search%3Fq=hunter2", "/search"},
		{"/search%3fq=hunter2", "/search"},
		{"/a%23frag=secret", "/a"},
		{"/a%3Bfoo=bar", "/a"},
		{"/a%3bfoo=bar", "/a"},
		{"/a;foo=bar", "/a"},
		{"/search%253Fq=hunter2", "/search"},
		{"/search%25253Fq=hunter2", "/search"},
		{"/search%2523frag=secret", "/search"},
		{"/search%253Bk=v", "/search"},
		{"/x%3Fq=hunter2?real=1", "/x?real=[v]"},
		{"/x%3Fq=hunter2#f", "/x"},
		{"/ok/path%20with%20space", "/ok/path with space"},
		{"/bad%zzescape?k=v", "/bad%zzescape?k=[v]"},
		{"/trunc%", "/trunc%"},
		{"/a%3Fb%3Dc", "/a"},
	}
	for _, c := range cases {
		got := r.Path(c.in)
		if got != c.want {
			t.Errorf("Path(%q) = %q, want %q", c.in, got, c.want)
		}
		if strings.Contains(got, "hunter2") || strings.Contains(got, "secret") {
			t.Errorf("Path(%q) leaked: %q", c.in, got)
		}
	}
}

func TestPathPropertyNoQueryValueInOutput(t *testing.T) {
	r := testRedactor(Policy{SendPaths: true})
	rnd := rand.New(rand.NewSource(7))
	delims := []string{"?", "#", ";", "%3F", "%3f", "%23", "%3B", "%3b", "%253F", "%2523", "%25253F"}
	for i := 0; i < 3000; i++ {
		val := "VAL" + strings.Repeat("x", rnd.Intn(4)) + "zq"
		in := "/p" + delims[rnd.Intn(len(delims))] + "k=" + val
		if rnd.Intn(2) == 0 {
			in = "/p/q" + delims[rnd.Intn(len(delims))] + "a=1&" + delims[rnd.Intn(len(delims))] + "k=" + val
		}
		out := r.Path(in)
		if strings.Contains(out, "VAL") {
			t.Fatalf("Path(%q) = %q leaks a value", in, out)
		}
		// the only legitimate '=' in the output is the [v] placeholder of a real raw query
		if strings.Contains(out, "=") && !strings.Contains(out, "=[v]") {
			t.Fatalf("Path(%q) = %q contains a raw =", in, out)
		}
		if strings.Count(out, "?") > 1 || strings.Contains(out, "#") || strings.Contains(out, ";") {
			t.Fatalf("Path(%q) = %q has stray delimiters", in, out)
		}
	}
}
