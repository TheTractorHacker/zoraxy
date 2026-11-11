package dynamicproxy

import (
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/blocklog"
)

/*
	blockref.go

	The reference ID a visitor gets with a block page (header X-Zoraxy-Ref and the {{ref}} placeholder
	of the error page) and that the blocked-request log stores with the entry, so an admin can search
	it. The ID says nothing about the rule: the rule name is never sent to the visitor.

	The page is written before or after the entry is logged depending on the code path, so both sides
	call requestRef, which makes the ID once per request and keeps it on the request.
*/

// refRequestKey keeps the reference on the request while it is handled. A blocked request is never
// forwarded, so the value cannot reach an upstream.
const refRequestKey = "X-Zoraxy-Internal-Ref"

// RefHeader is the response header that carries the reference ID of a block page
const RefHeader = "X-Zoraxy-Ref"

// blockRefEnabled reports whether blocks of this router get a reference ID: only when the
// blocked-request log records them, otherwise the ID could not be found again.
func (router *Router) blockRefEnabled() bool {
	if router == nil || router.Option == nil {
		return false
	}
	bl := router.Option.BlockLog
	return bl != nil && bl.Enabled()
}

// requestRef returns the reference of this request (8 stored characters), creating it on first use.
// "" when references are not in use.
func (router *Router) requestRef(r *http.Request) string {
	if r == nil || !router.blockRefEnabled() {
		return ""
	}
	if r.Header == nil {
		r.Header = http.Header{}
	}
	if v := r.Header.Get(refRequestKey); v != "" {
		return v
	}
	ref := blocklog.NewRef()
	if ref != "" {
		r.Header.Set(refRequestKey, ref)
	}
	return ref
}

// Markers of the built-in error page: the block between <!--ref--> and <!--/ref--> is only kept when
// there is a reference to show, the one between <!--region--> and <!--/region--> only when the block
// was caused by a country setting.
const (
	refTag      = "{{ref}}"
	refOpen     = "<!--ref-->"
	refClose    = "<!--/ref-->"
	regionOpen  = "<!--region-->"
	regionClose = "<!--/region-->"
)

// renderErrorPage fills the placeholders of an error page. {{ref}} becomes ZX-XXXX-XXXX (empty when
// there is no reference). Pages without any placeholder, such as templates written for older
// versions, are returned untouched.
func renderErrorPage(page []byte, ref string, region bool) []byte {
	s := string(page)
	if !strings.Contains(s, refTag) && !strings.Contains(s, refOpen) && !strings.Contains(s, regionOpen) {
		return page
	}
	shown := blocklog.FormatRef(ref)
	s = keepBlock(s, refOpen, refClose, shown != "")
	s = keepBlock(s, regionOpen, regionClose, region)
	s = strings.ReplaceAll(s, refTag, shown)
	return []byte(s)
}

// keepBlock removes the markers (keep) or the markers and what is between them (drop)
func keepBlock(s, open, close string, keep bool) string {
	for {
		i := strings.Index(s, open)
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], close)
		if j < 0 {
			return s
		}
		j += i
		if keep {
			s = s[:i] + s[i+len(open):j] + s[j+len(close):]
		} else {
			s = s[:i] + s[j+len(close):]
		}
	}
}

// writeForbiddenPage writes a block page with the reference ID header and placeholders filled in.
// The page is the built-in one (localized by the caller) or an operator template.
func (router *Router) writeForbiddenPage(w http.ResponseWriter, r *http.Request, status int, page []byte, region bool) {
	ref := router.requestRef(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ref != "" {
		w.Header().Set(RefHeader, blocklog.FormatRef(ref))
	}
	w.WriteHeader(status)
	w.Write(renderErrorPage(page, ref, region))
}
