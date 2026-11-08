package dynamicproxy

import "strings"

// vdirWebsocketPath joins the base path of a virtual directory target with the remainder of the request path
// (the matching prefix is already removed). An empty remainder maps to the base path itself, without a trailing
// slash, so that "/websocket" -> "host:8072/websocket" reaches "/websocket" (Odoo, upstream #314).
func vdirWebsocketPath(base, rest string) string {
	base = strings.TrimRight(base, "/")
	if rest == "" {
		if base == "" {
			return "/"
		}
		return base
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	return base + rest
}
