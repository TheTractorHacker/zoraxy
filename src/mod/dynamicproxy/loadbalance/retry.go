package loadbalance

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

/*
	Request serving with passive health reporting, latency tracking and retries

	The proxy core (dpcore) writes straight into the client response, so a
	retry is only possible while nothing was sent. responseGate sits in front
	of the client ResponseWriter, remembers whether the response started, and
	can swallow a response with a configured "retry" status before it reaches
	the client. The request body is only ever re-sent if it was empty or fully
	buffered in memory before the first attempt, so a body is never half
	consumed by one upstream and then replayed to another.
*/

// ServeFunc proxies the request to the given upstream and returns the status code and error, like Upstream.ServeHTTP
type ServeFunc func(w http.ResponseWriter, r *http.Request, u *Upstream) (int, error)

// ServeResult describes how the request ended
type ServeResult struct {
	Upstream        *Upstream //The upstream that produced the final outcome
	Status          int
	Err             error
	Attempts        int  //Number of upstreams tried, 1 = no retry happened
	ResponseStarted bool //True if response header bytes reached the client
}

// responseGate wraps the client ResponseWriter
type responseGate struct {
	rw          http.ResponseWriter
	base        http.Header //Header snapshot to restore when an attempt is discarded
	retryStatus func(int) bool
	now         func() time.Time

	started    bool      //Response header was forwarded to the client
	suppressed bool      //This attempt's response was discarded
	firstByte  time.Time //When the upstream response header arrived
}

func newResponseGate(rw http.ResponseWriter, now func() time.Time) *responseGate {
	return &responseGate{rw: rw, base: rw.Header().Clone(), now: now}
}

func (g *responseGate) Header() http.Header { return g.rw.Header() }

func (g *responseGate) WriteHeader(code int) {
	if g.started || g.suppressed {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		g.rw.WriteHeader(code) //Informational responses do not finish the response
		return
	}
	g.firstByte = g.now()
	if g.retryStatus != nil && g.retryStatus(code) {
		g.suppressed = true
		h := g.rw.Header()
		for k := range h {
			delete(h, k)
		}
		for k, v := range g.base {
			h[k] = append([]string(nil), v...)
		}
		return
	}
	g.started = true
	g.rw.WriteHeader(code)
}

func (g *responseGate) Write(b []byte) (int, error) {
	if g.suppressed {
		return len(b), nil
	}
	if !g.started {
		g.WriteHeader(http.StatusOK)
	}
	return g.rw.Write(b)
}

func (g *responseGate) Flush() {
	if g.suppressed {
		return
	}
	if !g.started {
		g.WriteHeader(http.StatusOK)
	}
	http.NewResponseController(g.rw).Flush()
}

// Hijack hands the connection over (protocol upgrades). After this nothing can be retried
func (g *responseGate) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	g.started = true
	g.firstByte = g.now()
	return http.NewResponseController(g.rw).Hijack()
}

func (g *responseGate) Unwrap() http.ResponseWriter { return g.rw }

// retryMethodAllowed reports whether the method may be retried: GET, HEAD, OPTIONS always, others only if listed
func retryMethodAllowed(method string, rc RetryConfig) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	case http.MethodConnect:
		return false
	}
	for _, m := range rc.ExtraMethods {
		if m == method {
			return true
		}
	}
	return false
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// prepareRetryBody decides whether the request body can be replayed. It returns a function giving a
// fresh body for every attempt, or ok=false when the request can only be sent once. A body is
// replayable if it is empty, or has a known length within the limit and is fully buffered here
func prepareRetryBody(r *http.Request, rc RetryConfig) (newBody func() io.ReadCloser, ok bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return func() io.ReadCloser { return http.NoBody }, true
	}
	limit := int64(rc.MaxBodyKB) * 1024
	if r.ContentLength <= 0 || r.ContentLength > limit {
		return nil, false
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, r.ContentLength))
	if err != nil || int64(len(buf)) != r.ContentLength {
		//The client broke the upload. Hand what we have plus the error to the single attempt
		cause := err
		if cause == nil {
			cause = io.ErrUnexpectedEOF
		}
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), errReader{cause}))
		return nil, false
	}
	r.Body.Close()
	return func() io.ReadCloser { return io.NopCloser(bytes.NewReader(buf)) }, true
}

// isUpgradeLike returns true for requests that become a tunnel and cannot be replayed
func isUpgradeLike(r *http.Request) bool {
	return r.Method == http.MethodConnect || r.Header.Get("Upgrade") != ""
}

// ServeWithRetry serves the request on the first upstream and, if it fails before any response byte
// reached the client, on other upstreams as configured. It also tracks in-flight requests, response
// time and passive health of every upstream it uses. first must already be selected by SelectUpstream
func (m *RouteManager) ServeWithRetry(w http.ResponseWriter, r *http.Request, origins []*Upstream, first *Upstream, opt *SelectOptions, serve ServeFunc) ServeResult {
	cfg := opt.Config
	passive, passiveOn := cfg.passive()
	rc, retryOn := cfg.retry()

	if cfg == nil {
		//No config: historical behavior, only count the request
		first.Acquire()
		defer first.Release()
		status, err := serve(w, r, first)
		return ServeResult{Upstream: first, Status: status, Err: err, Attempts: 1, ResponseStarted: err == nil}
	}

	maxRetries := 0
	var newBody func() io.ReadCloser
	if retryOn && !isUpgradeLike(r) && retryMethodAllowed(r.Method, rc) {
		var bodyOK bool
		if newBody, bodyOK = prepareRetryBody(r, rc); bodyOK {
			maxRetries = rc.MaxRetries
		} else {
			newBody = nil
		}
	}

	gate := newResponseGate(w, m.now)
	u := first
	var tried []*Upstream
	for attempt := 0; ; attempt++ {
		canRetry := attempt < maxRetries && r.Context().Err() == nil
		if canRetry {
			probe := *opt
			probe.Exclude = append(append([]*Upstream(nil), tried...), u)
			canRetry = m.HasAlternative(r, origins, &probe)
		}
		gate.retryStatus = nil
		if canRetry && len(rc.RetryStatuses) > 0 {
			statuses := rc.RetryStatuses
			gate.retryStatus = func(code int) bool { return containsInt(statuses, code) }
		}
		gate.suppressed, gate.firstByte = false, time.Time{}
		if newBody != nil {
			r.Body = newBody()
		}

		start := m.now()
		status, err := m.serveOnce(gate, r, u, serve)

		failed := err != nil && !errors.Is(err, context.Canceled)
		if passiveOn && !errors.Is(err, context.Canceled) {
			if failed || containsInt(passive.FailureStatuses, status) {
				if u.reportPassive(passive, true, m.now()) {
					m.println("Upstream "+u.OriginIpOrDomain+" ejected after "+strconv.Itoa(passive.FailThreshold)+" consecutive failures", nil)
				}
			} else {
				u.reportPassive(passive, false, m.now())
			}
		}
		if err == nil && status < 500 && status != http.StatusSwitchingProtocols && !gate.firstByte.IsZero() {
			u.observeLatency(gate.firstByte.Sub(start))
		}

		retryable := gate.suppressed || (failed && !gate.started && r.Context().Err() == nil)
		if !retryable || !canRetry {
			return ServeResult{Upstream: u, Status: status, Err: err, Attempts: attempt + 1, ResponseStarted: gate.started}
		}

		tried = append(tried, u)
		sel := *opt
		sel.Exclude = tried
		next, selErr := m.SelectUpstream(w, r, origins, &sel)
		if selErr != nil {
			if err == nil {
				err = selErr //The failed response was discarded, report why nothing was sent
				status = http.StatusBadGateway
			}
			return ServeResult{Upstream: u, Status: status, Err: err, Attempts: attempt + 1}
		}
		u = next
	}
}

// serveOnce runs one attempt with in-flight accounting
func (m *RouteManager) serveOnce(w http.ResponseWriter, r *http.Request, u *Upstream, serve ServeFunc) (int, error) {
	u.Acquire()
	defer u.Release()
	return serve(w, r, u)
}
