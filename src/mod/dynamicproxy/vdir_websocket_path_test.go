package dynamicproxy

import "testing"

func TestVdirWebsocketPath(t *testing.T) {
	cases := []struct{ base, rest, want string }{
		{"", "", "/"},
		{"", "/", "/"},
		{"", "/a/b", "/a/b"},
		{"/websocket", "", "/websocket"},
		{"/websocket/", "", "/websocket"},
		{"/websocket", "/", "/websocket/"},
		{"/websocket", "/x/y", "/websocket/x/y"},
		{"/base/", "/x", "/base/x"},
	}
	for _, c := range cases {
		if got := vdirWebsocketPath(c.base, c.rest); got != c.want {
			t.Errorf("vdirWebsocketPath(%q,%q)=%q want %q", c.base, c.rest, got, c.want)
		}
	}
}
