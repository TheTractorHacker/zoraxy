package metrics

import (
	"bufio"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Emitter collects metric families for one scrape and writes them in the
// Prometheus text format. HELP and TYPE are written once per family and
// families are sorted by name, so output is deterministic.
type Emitter struct {
	fams  map[string]*family
	order []string
}

type family struct {
	name, help, typ string
	lines           []string
}

// maxCollectedSeries bounds what collectors can add per family in one scrape
const maxCollectedSeries = 5000

func newEmitter() *Emitter { return &Emitter{fams: map[string]*family{}} }

func (e *Emitter) fam(name, help, typ string) *family {
	f := e.fams[name]
	if f == nil {
		f = &family{name: name, help: help, typ: typ}
		e.fams[name] = f
		e.order = append(e.order, name)
	}
	return f
}

// Gauge adds a gauge sample. labels is a flat list of name, value pairs.
func (e *Emitter) Gauge(name, help string, value float64, labels ...string) {
	e.add(name, help, "gauge", name, value, labels)
}

// Counter adds a counter sample (name should end in _total)
func (e *Emitter) Counter(name, help string, value float64, labels ...string) {
	e.add(name, help, "counter", name, value, labels)
}

func (e *Emitter) add(fam, help, typ, sample string, value float64, labels []string) {
	f := e.fam(fam, help, typ)
	if len(f.lines) >= maxCollectedSeries*4 {
		return
	}
	f.lines = append(f.lines, sample+formatLabels(labels, "", "")+" "+formatValue(value))
}

// histogram adds the bucket, sum and count samples of one histogram series
func (e *Emitter) histogram(name, help string, bounds []float64, counts []uint64, sum float64, labels []string) {
	f := e.fam(name, help, "histogram")
	var cum uint64
	for i, b := range bounds {
		cum += counts[i]
		f.lines = append(f.lines, name+"_bucket"+formatLabels(labels, "le", formatValue(b))+" "+strconv.FormatUint(cum, 10))
	}
	cum += counts[len(bounds)]
	f.lines = append(f.lines, name+"_bucket"+formatLabels(labels, "le", "+Inf")+" "+strconv.FormatUint(cum, 10))
	f.lines = append(f.lines, name+"_sum"+formatLabels(labels, "", "")+" "+formatValue(sum))
	f.lines = append(f.lines, name+"_count"+formatLabels(labels, "", "")+" "+strconv.FormatUint(cum, 10))
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func sanitizeLabelName(n string) string {
	var b strings.Builder
	for i, c := range n {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c >= '0' && c <= '9' && i > 0:
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

func formatLabels(labels []string, extraName, extraValue string) string {
	if len(labels) < 2 && extraName == "" {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	first := true
	write := func(n, v string) {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(sanitizeLabelName(n))
		b.WriteString(`="`)
		if !utf8.ValidString(v) {
			v = strings.ToValidUTF8(v, "�")
		}
		b.WriteString(labelEscaper.Replace(v))
		b.WriteByte('"')
	}
	for i := 0; i+1 < len(labels); i += 2 {
		write(labels[i], labels[i+1])
	}
	if extraName != "" {
		write(extraName, extraValue)
	}
	b.WriteByte('}')
	return b.String()
}

// Write renders everything: built in request metrics, then collectors
func (r *Registry) Write(w io.Writer) error {
	e := newEmitter()
	r.gather(e)

	bw := bufio.NewWriter(w)
	names := append([]string(nil), e.order...)
	sort.Strings(names)
	for _, n := range names {
		f := e.fams[n]
		bw.WriteString("# HELP " + f.name + " " + strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(f.help) + "\n")
		bw.WriteString("# TYPE " + f.name + " " + f.typ + "\n")
		for _, l := range f.lines {
			bw.WriteString(l)
			bw.WriteByte('\n')
		}
	}
	return bw.Flush()
}

func (r *Registry) gather(e *Emitter) {
	if r == nil {
		return
	}
	// Make the families exist even before the first request so scrapes of an
	// idle server still carry HELP/TYPE lines
	e.fam("zoraxy_http_requests_total", "Total HTTP requests by endpoint (proxy rule), status class and method.", "counter")
	e.fam("zoraxy_http_requests_in_flight", "Requests currently being served, by endpoint.", "gauge")
	e.fam("zoraxy_http_request_duration_seconds", "Request duration (headers received to response done) by endpoint.", "histogram")
	e.fam("zoraxy_http_request_bytes_total", "Request body bytes received from clients, by endpoint.", "counter")
	e.fam("zoraxy_http_response_bytes_total", "Response body bytes sent to clients, by endpoint.", "counter")

	r.mu.RLock()
	names := make([]string, 0, len(r.endpoints))
	for n := range r.endpoints {
		names = append(names, n)
	}
	r.mu.RUnlock()
	sort.Strings(names)

	bounds := DurationBuckets[:]
	for _, n := range names {
		r.mu.RLock()
		s := r.endpoints[n]
		r.mu.RUnlock()
		if s == nil {
			continue
		}
		for ci, cn := range classNames {
			for mi, mn := range methodNames {
				if v := s.requests[ci][mi].Load(); v > 0 {
					e.Counter("zoraxy_http_requests_total", "", float64(v), "endpoint", n, "status_class", cn, "method", mn)
				}
			}
		}
		e.Gauge("zoraxy_http_requests_in_flight", "", float64(s.inflight.Load()), "endpoint", n)
		e.Counter("zoraxy_http_request_bytes_total", "", float64(s.bytesIn.Load()), "endpoint", n)
		e.Counter("zoraxy_http_response_bytes_total", "", float64(s.bytesOut.Load()), "endpoint", n)
		counts := make([]uint64, len(bounds)+1)
		for i := range counts {
			counts[i] = s.buckets[i].Load()
		}
		// cumulative count is derived from the buckets so _count == +Inf bucket
		e.histogram("zoraxy_http_request_duration_seconds", "", bounds, counts, float64(s.durSumNs.Load())/1e9, []string{"endpoint", n})
	}

	evNames := [numEvents]struct{ name, help, label string }{
		EventRateLimited:      {"zoraxy_ratelimit_rejected_total", "Requests rejected by the endpoint rate limiter.", "reason"},
		EventAccessBlocked:    {"zoraxy_access_blocked_total", "Requests blocked by an access rule (blacklist / whitelist).", "reason"},
		EventCaptchaChallenge: {"zoraxy_captcha_challenges_total", "CAPTCHA challenges served.", "reason"},
		EventCaptchaVerified:  {"zoraxy_captcha_verified_total", "CAPTCHA verifications that succeeded.", "reason"},
		EventCaptchaFailed:    {"zoraxy_captcha_failed_total", "CAPTCHA verifications that failed.", "reason"},
	}
	for k := EventKind(0); k < numEvents; k++ {
		v := &r.events[k]
		e.fam(evNames[k].name, evNames[k].help, "counter")
		v.mu.RLock()
		keys := make([][2]string, 0, len(v.series))
		for key := range v.series {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] != keys[j][0] {
				return keys[i][0] < keys[j][0]
			}
			return keys[i][1] < keys[j][1]
		})
		for _, key := range keys {
			e.Counter(evNames[k].name, "", float64(v.series[key].Load()), "endpoint", key[0], evNames[k].label, key[1])
		}
		v.mu.RUnlock()
	}

	e.Gauge("zoraxy_uptime_seconds", "Seconds since the metrics registry was created (process start).", r.Uptime().Seconds())

	r.collMu.RLock()
	cs := append([]Collector(nil), r.collectors...)
	r.collMu.RUnlock()
	for _, c := range cs {
		func() {
			defer func() { recover() }() //a broken collector must not break the scrape
			c(e)
		}()
	}
}
