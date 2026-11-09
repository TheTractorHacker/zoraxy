package waf

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

/*
	respinspect.go

	Response inspection (outbound data-leak detection). Self-contained: it does
	not use the Coraza response phases, which need the whole body buffered and
	cannot coexist with streaming.

	The proxy core calls ResponseGuard.Inspect once per upstream response, after
	the response headers arrived and before anything is sent to the client:

	  1. header banners (Server, X-Powered-By, ...) are logged or stripped
	  2. if the response is a candidate for body inspection, at most Window bytes
	     of the body are read into a buffer. The buffer is put back in front of
	     the rest of the body, so the client receives the original bytes. The rest
	     of the body is never read here: it streams through untouched.
	  3. the window is scanned. "log" only records an event. "block" makes
	     Inspect return a status code, and the caller replaces the response with a
	     generic error page; the upstream body is closed without ever being sent.

	Body candidates (everything else passes through without a single extra read):
	  - known length (Content-Length > 0): chunked / unknown length responses may
	    be streams and are never held back
	  - text-like content type: text/* (not text/event-stream), JSON, XML, JavaScript
	  - not HEAD, not 1xx/204/304, not 206 / Content-Range, no trailers, not a
	    protocol upgrade request, not flagged as streaming by the caller (gRPC and
	    bidirectional HTTP/2 streams)
	  - Content-Encoding identity, gzip or deflate. gzip/deflate are decoded
	    with a hard cap: at most Window decompressed bytes are ever produced and
	    at most 2*Window+16 KiB compressed bytes are buffered, whatever the
	    stream claims, so a decompression bomb costs the same as a normal page.
	    br, zstd and stacked encodings are not decoded and pass through uninspected.
*/

// ResponseInfo carries what the waf package needs to know about the request of a response
type ResponseInfo struct {
	Endpoint string
	ClientIP string
	Source   string // where the effective config comes from (global, profile:X, custom, endpoint)
	Method   string
	Host     string
	Path     string
	URI      string
	// OnBlock (optional) is called once when a response is blocked, e.g. to raise a notification
	OnBlock func(ev Event)
}

// ResponseHit is the response specific part of an Event
type ResponseHit struct {
	Group       string `json:"group"`
	Signature   string `json:"signature"`
	Name        string `json:"name"`
	Sample      string `json:"sample"` // redacted, never the full secret
	Confidence  string `json:"confidence,omitempty"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Offset      int    `json:"offset,omitempty"` // position of the hit in the inspected window
	Header      string `json:"header,omitempty"` // for the headers group
}

// Event kinds
const (
	KindRequest  = "request"
	KindResponse = "response"
)

const (
	maxHitsPerResponse   = 8
	headerEventInterval  = time.Hour
	maxHeaderSeen        = 512
	compressedSlackBytes = 16 * 1024
)

// ResponseGuard is the compiled response protection of one endpoint. Safe for concurrent use.
type ResponseGuard struct {
	window  int // bytes
	act     map[string]string
	enforce bool // block / strip really happen (WAF mode block); otherwise they are logged as would-be
	events  *eventStore
	sigs    []*signature // signatures of the enabled body groups
	body    bool
	hdr     string

	mu       sync.Mutex
	hdrSeen  map[string]time.Time
	scanHook func() // tests
}

// NewResponseGuard compiles a ResponseConfig. It returns nil when nothing is enabled, so the
// caller's disabled path is a nil check. mode is the effective WAF mode of the endpoint: in
// detection_only mode nothing is blocked or stripped, only reported.
func (m *Manager) NewResponseGuard(rc *ResponseConfig, mode string) *ResponseGuard {
	if rc == nil || !rc.Active() || rc.Validate() != nil {
		return nil
	}
	g := &ResponseGuard{
		window:  DefaultResponseWindowKiB * 1024,
		act:     map[string]string{},
		enforce: mode == ModeBlock,
		events:  m.events,
		hdrSeen: map[string]time.Time{},
	}
	if rc.WindowKiB > 0 {
		g.window = rc.WindowKiB * 1024
	}
	for _, grp := range ResponseGroups {
		a := rc.Action(grp)
		if a == "" || a == RespActionOff {
			continue
		}
		g.act[grp] = a
	}
	g.hdr = g.act[GroupHeaders]
	for _, s := range builtinSignatures {
		if g.act[s.Group] != "" && s.Group != GroupHeaders {
			g.sigs = append(g.sigs, s)
			g.body = true
		}
	}
	return g
}

// Window returns the inspection window in bytes
func (g *ResponseGuard) Window() int { return g.window }

func newEventID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// textLike reports whether a Content-Type is worth scanning
func textLike(ct string) (ok bool, flags int) {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	}
	switch {
	case mt == "":
		return false, 0
	case mt == "text/event-stream":
		return false, 0
	case mt == "text/plain":
		return true, ctxPlain
	case strings.HasPrefix(mt, "text/"):
		return true, 0
	case mt == "application/json" || strings.HasSuffix(mt, "+json") || mt == "application/x-ndjson":
		return true, ctxJSON
	case mt == "application/xml" || strings.HasSuffix(mt, "+xml"):
		return true, 0
	case mt == "application/javascript" || mt == "application/x-javascript" || mt == "application/ecmascript":
		return true, 0
	}
	return false, 0
}

// Inspect examines one upstream response. It may delete headers and replace res.Body (by a reader that
// yields the same bytes). It returns a non zero HTTP status when the response must be replaced by a
// generic error page; the caller then discards res (res.Body is already closed).
// streaming is true when the caller knows the response is a stream (gRPC, bidirectional HTTP/2).
func (g *ResponseGuard) Inspect(info ResponseInfo, req *http.Request, res *http.Response, streaming bool) (blockStatus int) {
	if g == nil {
		return 0
	}
	// Inspection must never take the proxy down: fail open
	defer func() {
		if rec := recover(); rec != nil {
			blockStatus = 0
		}
	}()
	if res.StatusCode == http.StatusSwitchingProtocols {
		return 0
	}
	if g.hdr != "" {
		g.inspectHeaders(info, res)
	}
	if !g.body || streaming || !candidate(req, res) {
		return 0
	}
	ct := res.Header.Get("Content-Type")
	ok, flags := textLike(ct)
	if !ok {
		return 0
	}
	data, ok := g.fillWindow(res)
	if !ok || len(data) == 0 {
		return 0
	}
	if g.scanHook != nil {
		g.scanHook()
	}
	hits := g.scan(data, flags)
	block := false
	for _, h := range hits {
		act := g.act[h.sig.Group]
		ev := g.newEvent(info, res, ct, h)
		wouldBlock := act == RespActionBlock && h.conf == confHigh
		if wouldBlock && g.enforce {
			ev.Action = "blocked"
			block = true
		} else {
			ev.Action = "detected"
		}
		ev.WouldBlock = wouldBlock
		g.events.add(ev)
		if ev.Action == "blocked" && info.OnBlock != nil {
			info.OnBlock(ev)
		}
	}
	if block {
		res.Body.Close()
		return http.StatusBadGateway
	}
	return 0
}

func (g *ResponseGuard) newEvent(info ResponseInfo, res *http.Response, ct string, h scanHit) Event {
	mode := ModeDetectionOnly
	if g.enforce {
		mode = ModeBlock
	}
	conf := "high"
	if h.conf == confLow {
		conf = "low"
	}
	return Event{
		Time: time.Now(), TransactionID: newEventID(), Endpoint: info.Endpoint, ClientIP: info.ClientIP,
		Method: info.Method, Host: info.Host, Path: info.Path, URI: truncate(info.URI, 512),
		Mode: mode, Source: info.Source, Rules: []RuleHit{},
		Kind: KindResponse,
		Response: &ResponseHit{Group: h.sig.Group, Signature: h.sig.ID, Name: h.sig.Name, Sample: h.sample,
			Confidence: conf, Status: res.StatusCode, ContentType: truncate(ct, 100), Offset: h.offset},
	}
}

// candidate applies the streaming safety rules for body inspection
func candidate(req *http.Request, res *http.Response) bool {
	if req != nil {
		if req.Method == http.MethodHead || req.Header.Get("Upgrade") != "" {
			return false
		}
	}
	switch {
	case res.StatusCode < 200, res.StatusCode == http.StatusNoContent, res.StatusCode == http.StatusResetContent,
		res.StatusCode == http.StatusPartialContent, res.StatusCode == http.StatusNotModified:
		return false
	}
	if res.ContentLength <= 0 || len(res.Trailer) > 0 || res.Header.Get("Content-Range") != "" || res.Body == nil || res.Body == http.NoBody {
		return false
	}
	return true
}

// recorder keeps everything read from the upstream so it can be replayed. It fails (and stops the decoder)
// once more than limit bytes were recorded.
type recorder struct {
	buf   bytes.Buffer
	limit int
}

func (r *recorder) Write(p []byte) (int, error) {
	r.buf.Write(p)
	if r.buf.Len() > r.limit {
		return len(p), io.ErrShortBuffer
	}
	return len(p), nil
}

// fillWindow reads at most the first window bytes of the (decoded) body and puts the raw bytes back in
// front of the rest of the body. ok is false when the body cannot be inspected; res.Body then still
// yields the complete original bytes.
func (g *ResponseGuard) fillWindow(res *http.Response) (data []byte, ok bool) {
	orig := res.Body
	enc := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding")))
	switch enc {
	case "", "identity":
		n := g.window
		if res.ContentLength > 0 && res.ContentLength < int64(n) {
			n = int(res.ContentLength)
		}
		buf := make([]byte, n)
		got, _ := io.ReadFull(orig, buf) // an error here is sticky in the body and surfaces again when the client copy reads on
		buf = buf[:got]
		res.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf), orig), closer: orig}
		return buf, true
	case "gzip", "x-gzip", "deflate":
		rec := &recorder{limit: 2*g.window + compressedSlackBytes}
		tee := io.TeeReader(orig, rec)
		var dec io.Reader
		var err error
		if enc == "deflate" {
			dec, err = zlib.NewReader(tee)
		} else {
			dec, err = gzip.NewReader(tee)
		}
		var out []byte
		if err == nil {
			// Never produce more than window bytes, whatever the stream declares
			out, _ = io.ReadAll(io.LimitReader(dec, int64(g.window)))
		}
		res.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(rec.buf.Bytes()), orig), closer: orig}
		return out, len(out) > 0
	}
	return nil, false
}

type scanHit struct {
	sig    *signature
	conf   int
	offset int
	sample string
}

const (
	sigSpan          = 1536     // bytes around an anchor in which a signature may match
	maxSigWindows    = 6        // regex windows per signature
	regexBudgetBytes = 64 << 10 // regex input per response, bounds the cost of a hostile page
)

var sigMatcher *acMatcher

func init() {
	idx := map[string]int{}
	var all [][]byte
	for _, s := range builtinSignatures {
		if len(s.pre) == 0 {
			panic("response signature " + s.ID + " has no anchor literal")
		}
		for _, l := range s.pre {
			id, ok := idx[string(l)]
			if !ok {
				id = len(all)
				idx[string(l)] = id
				all = append(all, l)
			}
			s.preIDs = append(s.preIDs, id)
		}
	}
	sigMatcher = buildAC(all)
}

type span struct{ lo, hi int }

// windowsFor merges the regions around the anchor occurrences of a signature
func windowsFor(s *signature, hits anchorHits, n int) []span {
	var pos []int
	for _, id := range s.preIDs {
		for _, p := range hits[id] {
			pos = append(pos, int(p))
		}
	}
	if len(pos) == 0 {
		return nil
	}
	sort.Ints(pos)
	var out []span
	for _, p := range pos {
		lo, hi := p-sigSpan, p+sigSpan
		if lo < 0 {
			lo = 0
		}
		if hi > n {
			hi = n
		}
		if k := len(out); k > 0 && lo <= out[k-1].hi {
			if hi > out[k-1].hi {
				out[k-1].hi = hi
			}
			continue
		}
		if len(out) >= maxSigWindows {
			break
		}
		out = append(out, span{lo, hi})
	}
	return out
}

// scan runs the enabled body signatures over the window. One hit per signature at most. A single pass
// finds the anchors of all signatures; a signature's regex only sees the regions around its anchors.
func (g *ResponseGuard) scan(data []byte, flags int) []scanHit {
	var hits []scanHit
	var anchors anchorHits
	budget := regexBudgetBytes
	for _, s := range g.sigs {
		if s.need != 0 && s.need&flags == 0 {
			continue
		}
		if anchors == nil {
			anchors = sigMatcher.find(data)
		}
		best := scanHit{conf: confNone}
	windows:
		for _, w := range windowsFor(s, anchors, len(data)) {
			if budget -= w.hi - w.lo; budget < 0 {
				break
			}
			for _, loc := range s.re.FindAllSubmatchIndex(data[w.lo:w.hi], 6) {
				for i := range loc {
					if loc[i] >= 0 {
						loc[i] += w.lo
					}
				}
				c := confHigh
				if s.check != nil {
					c = s.check(data, loc)
				}
				if c > best.conf {
					best = scanHit{sig: s, conf: c, offset: loc[0], sample: sampleOf(s, data, loc)}
					if c == confHigh {
						break windows
					}
				}
			}
		}
		if best.conf > confNone {
			hits = append(hits, best)
			if len(hits) >= maxHitsPerResponse {
				break
			}
		}
	}
	return hits
}

var quotedRun = regexp.MustCompile(`'[^'\n]*'|"[^"\n]*"`)

// sampleOf builds the text stored in an event. Secrets are masked in the middle, other groups lose the
// quoted values (which may be user data) and are truncated.
func sampleOf(s *signature, data []byte, loc []int) string {
	if s.Group == GroupSecrets {
		vs, ve := loc[0], loc[1]
		if s.value > 0 && len(loc) > 2*s.value+1 && loc[2*s.value] >= 0 {
			vs, ve = loc[2*s.value], loc[2*s.value+1]
		}
		prefix := string(data[loc[0]:vs])
		if len(prefix) > 40 {
			prefix = prefix[len(prefix)-40:]
		}
		prefix = cleanSample(prefix)
		return prefix + maskSecret(string(data[vs:ve]), s.keep)
	}
	end := loc[1]
	if end-loc[0] > 120 {
		end = loc[0] + 120
	}
	t := cleanSample(string(data[loc[0]:end]))
	t = quotedRun.ReplaceAllStringFunc(t, func(q string) string { return q[:1] + "..." + q[len(q)-1:] })
	return truncate(t, 80)
}

// maskSecret keeps at most keep leading and 2 trailing characters of a secret and hides the middle;
// short values are hidden completely. The length is reported so the finding stays useful.
func maskSecret(v string, keep int) string {
	n := len(v)
	if keep < 0 {
		keep = 0
	}
	if n <= 12 {
		return fmt.Sprintf("[%d chars hidden]", n)
	}
	tail := 2
	if keep == 0 {
		tail = 0
	}
	if keep > n/4 {
		keep = n / 4
	}
	return fmt.Sprintf("%s...%s [%d chars]", v[:keep], v[n-tail:], n)
}

func cleanSample(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

/* ---- header banners ---- */

var serverVersion = regexp.MustCompile(`/\s?\d|\b\d+\.\d+`)

type bannerHeader struct {
	name     string
	anyValue bool // any non empty value is a leak (otherwise only values carrying a version)
}

var bannerHeaders = []bannerHeader{
	{"Server", false},
	{"X-Powered-By", true},
	{"X-AspNet-Version", true},
	{"X-AspNetMvc-Version", true},
}

func (g *ResponseGuard) inspectHeaders(info ResponseInfo, res *http.Response) {
	for _, bh := range bannerHeaders {
		vals := res.Header.Values(bh.name)
		if len(vals) == 0 {
			continue
		}
		leak := false
		for _, v := range vals {
			if strings.TrimSpace(v) != "" && (bh.anyValue || serverVersion.MatchString(v)) {
				leak = true
			}
		}
		if !leak {
			continue
		}
		value := truncate(cleanSample(strings.Join(vals, ", ")), 80)
		strip := g.hdr == RespActionStrip && g.enforce
		if strip {
			res.Header.Del(bh.name)
		}
		// One event per endpoint, header and value per hour: every response carries the banner
		key := info.Endpoint + "\x00" + bh.name + "\x00" + value
		if !g.firstSeen(key) {
			continue
		}
		ev := Event{
			Time: time.Now(), TransactionID: newEventID(), Endpoint: info.Endpoint, ClientIP: info.ClientIP,
			Method: info.Method, Host: info.Host, Path: info.Path, URI: truncate(info.URI, 512),
			Action: "detected", Mode: map[bool]string{true: ModeBlock, false: ModeDetectionOnly}[g.enforce], Source: info.Source,
			Rules: []RuleHit{}, Kind: KindResponse,
			Response: &ResponseHit{Group: GroupHeaders, Signature: "HDR-" + strings.ToUpper(bh.name), Name: bh.name + " banner",
				Sample: bh.name + ": " + value, Confidence: "high", Status: res.StatusCode, Header: bh.name},
		}
		if strip {
			ev.Action = "stripped"
		}
		ev.WouldBlock = g.hdr == RespActionStrip && !g.enforce
		g.events.add(ev)
	}
}

func (g *ResponseGuard) firstSeen(key string) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if t, ok := g.hdrSeen[key]; ok && now.Sub(t) < headerEventInterval {
		return false
	}
	if len(g.hdrSeen) >= maxHeaderSeen {
		g.hdrSeen = map[string]time.Time{}
	}
	g.hdrSeen[key] = now
	return true
}

/* ---- signature reference (documentation, UI) ---- */

// SignatureInfo describes one built-in signature
type SignatureInfo struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	Name  string `json:"name"`
	Doc   string `json:"doc"`
}

// ResponseSignatures lists the built-in signatures, plus the header banner checks
func ResponseSignatures() []SignatureInfo {
	var out []SignatureInfo
	for _, s := range builtinSignatures {
		out = append(out, SignatureInfo{ID: s.ID, Group: s.Group, Name: s.Name, Doc: s.Doc})
	}
	out = append(out,
		SignatureInfo{ID: "HDR-SERVER", Group: GroupHeaders, Name: "Server banner", Doc: "Server header carrying a version (nginx/1.18.0, Apache/2.4.41 (Ubuntu), Microsoft-IIS/10.0). A bare product name is not reported."},
		SignatureInfo{ID: "HDR-X-POWERED-BY", Group: GroupHeaders, Name: "X-Powered-By", Doc: "Any X-Powered-By header (PHP/8.1.2, Express, ASP.NET)."},
		SignatureInfo{ID: "HDR-X-ASPNET-VERSION", Group: GroupHeaders, Name: "X-AspNet-Version / X-AspNetMvc-Version", Doc: "Any X-AspNet-Version or X-AspNetMvc-Version header."},
	)
	return out
}
