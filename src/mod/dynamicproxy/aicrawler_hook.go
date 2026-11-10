package dynamicproxy

import (
	"net/http"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/abuse"
	"imuslab.com/zoraxy/mod/aicrawler"
	"imuslab.com/zoraxy/mod/metrics"
)

/*
	AI crawler policy glue, see mod/aicrawler and DEVELOPMENT.md ("AI crawler policy").

	Where it sits in runEndpointChain (Server.go):
	  access -> rules engine -> /robots.txt and /llms.txt answers -> client cert / path rules / header rules
	  -> AI CRAWLER POLICY -> bot rules -> plugin pre_auth -> WAF -> exploit detector -> rate limit -> CAPTCHA gating -> auth

	An allowed crawler (action allow, or rate limit while under its limit) is only exempted from the two checks that
	would otherwise stop it by name: the "ai_crawler" category of the bot rules and the AI crawler switch of the
	exploit detector. It is still subject to everything else, the WAF included, unless the admin ticked the WAF bypass
	AND the crawler's identity was verified. Without a policy for the crawler, or with the policy off, nothing changes.
*/

type crawlerResult struct {
	allowed   bool // skip the AI signature checks of the bot rules and the exploit detector
	bypassWAF bool // verified and the admin ticked the bypass
}

func (h *ProxyHandler) handleAICrawlers(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) (bool, crawlerResult) {
	eng := h.Parent.Option.AICrawlers
	if eng == nil || !eng.Enabled() {
		return false, crawlerResult{}
	}
	uas := r.Header.Values("User-Agent")
	if len(uas) > 4 {
		uas = uas[:4]
	}
	ipFn := func() string { return h.Parent.GetClientIPForEndpoint(r, sep) }
	d := eng.Evaluate(sep.RootOrMatchingDomain, uas, ipFn)
	if !d.Matched {
		return false, crawlerResult{}
	}
	kind := "blocked"
	if d.Spoofed {
		kind = "spoofed"
	}
	switch d.Outcome {
	case aicrawler.OutAllow:
		return false, crawlerResult{allowed: true, bypassWAF: d.BypassWAF}
	case aicrawler.OutLogOnly:
		h.Parent.logRequestDetail(r, true, 200, "aicrawler-"+kind+"-logonly", r.Host, "", sep, d.Detail())
		return false, crawlerResult{}
	case aicrawler.OutChallenge:
		return h.Parent.captchaChallengeDetail(w, r, sep, "aicrawler", d.Detail()), crawlerResult{}
	case aicrawler.OutLimited:
		h.Parent.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "aicrawler")
		h.Parent.logRequestDetail(r, false, http.StatusTooManyRequests, "aicrawler-ratelimited", r.Host, "", sep, d.Detail())
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return true, crawlerResult{}
	case aicrawler.OutBlock:
		h.Parent.Option.Metrics.Event(metrics.EventAccessBlocked, endpointLabel(sep), "aicrawler")
		h.Parent.logRequestDetail(r, false, http.StatusForbidden, "aicrawler-"+kind, r.Host, "", sep, d.Detail())
		abuseNoteKind(r, abuse.KindBot)
		serveProxyRequestError(w, r, http.StatusForbidden, h.Parent, ErrorTemplateForbidden)
		return true, crawlerResult{}
	}
	return false, crawlerResult{} // no policy for this crawler
}

/* ---- /robots.txt and /llms.txt ---- */

func crawlerFilePath(r *http.Request) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return ""
	}
	p := r.URL.Path
	if p == "/robots.txt" || p == "/llms.txt" {
		return p
	}
	return ""
}

// handleCrawlerFiles answers /robots.txt and /llms.txt itself in "serve" mode
func (h *ProxyHandler) handleCrawlerFiles(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	eng := h.Parent.Option.AICrawlers
	if eng == nil {
		return false
	}
	p := crawlerFilePath(r)
	if p == "" {
		return false
	}
	fm := eng.FileFor(sep.RootOrMatchingDomain, p)
	if fm.Mode != "serve" {
		return false
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Content-Length", strconv.Itoa(len(fm.Body)))
	hd.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write([]byte(fm.Body))
	}
	h.Parent.logRequest(r, true, http.StatusOK, "static-response", r.Host, "", sep)
	return true
}

// crawlerFileWrap wraps the response of a request for /robots.txt or /llms.txt when the site merges the generated text
// into the upstream file ("merge" for robots.txt, "fallback" for llms.txt). done must be called after the request was
// proxied. For every other request it returns w unchanged.
func (router *Router) crawlerFileWrap(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) (http.ResponseWriter, func()) {
	noop := func() {}
	eng := router.Option.AICrawlers
	if eng == nil || sep == nil {
		return w, noop
	}
	p := crawlerFilePath(r)
	if p == "" {
		return w, noop
	}
	fm := eng.FileFor(sep.RootOrMatchingDomain, p)
	if (fm.Mode != "merge" && fm.Mode != "fallback") || fm.Body == "" {
		return w, noop
	}
	cw := &crawlerFileWriter{ResponseWriter: w, head: r.Method == http.MethodHead, mode: fm.Mode, body: fm.Body}
	return cw, cw.finish
}

// crawlerFileWriter appends the generated text to a 200 text answer of the upstream, or replaces a 404 / 410 by it.
// Compressed answers cannot be extended and pass through untouched.
type crawlerFileWriter struct {
	http.ResponseWriter
	head  bool
	mode  string // merge | fallback
	body  string
	state int // 0 undecided, 1 pass through, 2 append at the end, 3 upstream has no file: swallow and serve ours
}

func (c *crawlerFileWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *crawlerFileWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok && c.state != 3 {
		f.Flush()
	}
}

func (c *crawlerFileWriter) WriteHeader(code int) {
	if c.state != 0 {
		return
	}
	h := c.ResponseWriter.Header()
	switch {
	case code == http.StatusNotFound || code == http.StatusGone:
		c.state = 3
		return
	case code == http.StatusOK && c.mode == "merge" && h.Get("Content-Encoding") == "" && h.Get("Content-Range") == "" &&
		(h.Get("Content-Type") == "" || strings.HasPrefix(strings.ToLower(h.Get("Content-Type")), "text/plain")):
		c.state = 2
		h.Del("Content-Length")
		h.Del("Etag")
		h.Del("Content-MD5")
	default:
		c.state = 1
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *crawlerFileWriter) Write(b []byte) (int, error) {
	if c.state == 0 {
		c.WriteHeader(http.StatusOK)
	}
	if c.state == 3 {
		return len(b), nil // the upstream's "not found" page is dropped
	}
	return c.ResponseWriter.Write(b)
}

func (c *crawlerFileWriter) finish() {
	switch c.state {
	case 2:
		if !c.head {
			c.ResponseWriter.Write([]byte(c.body))
		}
	case 3:
		body := c.body
		if c.mode == "merge" {
			body = strings.TrimPrefix(body, "\n")
		}
		h := c.ResponseWriter.Header()
		for _, k := range []string{"Content-Encoding", "Etag", "Last-Modified", "Content-Range", "Content-MD5", "Cache-Control", "Expires"} {
			h.Del(k)
		}
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Content-Length", strconv.Itoa(len(body)))
		h.Set("X-Content-Type-Options", "nosniff")
		c.ResponseWriter.WriteHeader(http.StatusOK)
		if !c.head {
			c.ResponseWriter.Write([]byte(body))
		}
	}
}
