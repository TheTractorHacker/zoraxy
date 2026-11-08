package metrics

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

type countingBody struct {
	io.ReadCloser
	n *atomic.Uint64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(uint64(n))
	return n, err
}

// recorder captures status and response size. It keeps the optional
// interfaces (Flusher, Hijacker, Unwrap for ResponseController) working.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  atomic.Uint64
	wrote  bool
}

func (w *recorder) WriteHeader(code int) {
	if !w.wrote && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recorder) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes.Add(uint64(n))
	return n, err
}

func (w *recorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := h.Hijack()
	if err == nil && !w.wrote {
		w.status = http.StatusSwitchingProtocols
		w.wrote = true
	}
	return conn, rw, err
}

func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Begin starts measuring a request for the named endpoint (the configured
// rule name). The returned done function must be called once when the
// request has been served. When metrics are disabled it returns the inputs
// unchanged and a no-op.
func (r *Registry) Begin(w http.ResponseWriter, req *http.Request, endpoint string) (http.ResponseWriter, *http.Request, func()) {
	if !r.Enabled() {
		return w, req, noop
	}
	e := r.endpoint(endpoint)
	e.inflight.Add(1)
	start := time.Now()
	rec := &recorder{ResponseWriter: w}
	in := &atomic.Uint64{}
	if req.Body != nil && req.Body != http.NoBody {
		req.Body = &countingBody{ReadCloser: req.Body, n: in}
	}
	method := methodIndex(req.Method)
	return rec, req, func() {
		e.inflight.Add(-1)
		status := rec.status
		if !rec.wrote {
			status = http.StatusOK //handler returned without writing, net/http sends 200
		}
		e.requests[classIndex(status)][method].Add(1)
		e.bytesIn.Add(in.Load())
		e.bytesOut.Add(rec.bytes.Load())
		observeDuration(e, time.Since(start))
	}
}

func noop() {}
