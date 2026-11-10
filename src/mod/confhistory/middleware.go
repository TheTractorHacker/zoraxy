package confhistory

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// statusRecorder remembers the status code and passes everything else through.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Flush keeps streaming handlers working.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Middleware wraps an HTTP handler tree. After a successful (2xx / 3xx)
// POST, PUT, PATCH or DELETE under /api/ it schedules a debounced snapshot.
// A snapshot is only stored when the allow-listed configuration really
// changed, so read-only POST endpoints and failed changes (the admin API
// reports many errors as 200 with an error body) create nothing.
//
// actor resolves the acting admin (session user or API token name); it is
// called before the handler runs, while the request is still intact; false
// means the request is not authenticated and is passed through untouched.
func (m *Manager) Middleware(actor func(w http.ResponseWriter, r *http.Request) (string, bool)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !Mutating(r.Method) || !strings.HasPrefix(r.URL.Path, "/api/") || SkipPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			who := "admin"
			if actor != nil {
				a, ok := actor(w, r)
				if !ok { //not an authenticated admin request: nothing to record
					next.ServeHTTP(w, r)
					return
				}
				if a != "" {
					who = a
				}
			}
			// Peek at a small urlencoded body for the summary without consuming it: the body is
			// restored for the handlers, which may read it raw.
			var form url.Values
			if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/x-www-form-urlencoded") && r.Body != nil && r.ContentLength >= 0 && r.ContentLength <= 64<<10 {
				if b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1)); err == nil {
					r.Body = io.NopCloser(bytes.NewReader(b))
					form, _ = url.ParseQuery(string(b))
				}
			}
			m.PreChange()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status != 0 && (rec.status < 200 || rec.status >= 400) {
				return
			}
			m.Notify(who, summaryOf(r, form))
		})
	}
}
