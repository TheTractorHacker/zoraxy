package logviewer

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	Access log search

	Scans request log files (global text logs, per-site text and JSON-lines logs,
	plain or gzip) without loading them into memory. Cost is bounded by:

	  - MaxScanBytes   uncompressed bytes read across all files
	  - MaxScanTime    wall clock
	  - MaxLineBytes   longer lines are skipped
	  - the regular expression engine is RE2 (linear time) and the pattern length is capped
	  - at most MaxResults entries are returned / exported

	A search that hits a bound is reported with Truncated=true and a reason,
	never silently cut.
*/

// Search limits
const (
	DefaultScanBytes = 256 << 20
	MaxScanBytesCap  = 2 << 30
	DefaultScanTime  = 10 * time.Second
	MaxScanTimeCap   = 60 * time.Second
	MaxLineBytes     = 64 << 10
	MaxResults       = 1000   // page size cap
	MaxExportRows    = 100000 // download cap
	MaxPatternLength = 200
	maxGzMatches     = 200000
)

// Entry is one parsed request log line
type Entry struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"` // "global" or the site folder name
	Class    string    `json:"class"`
	Origin   string    `json:"origin"`
	Client   string    `json:"client"`
	Agent    string    `json:"useragent"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	Status   int       `json:"status"`
	Country  string    `json:"country,omitempty"`
	Site     string    `json:"site,omitempty"`
	Upstream string    `json:"upstream,omitempty"`
}

var textLine = regexp.MustCompile(`^\[([^\]]+)\] \[router:([^\]]*)\] \[origin:([^\]]*)\] \[client: ([^\]]*)\] \[useragent: (.*)\] (\S+) (\S+) (\d{3})$`)

// ParseLine parses a text or JSON-lines request log line. ok=false for system
// log lines and anything that is not a request record.
func ParseLine(line string) (e Entry, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return e, false
	}
	if line[0] == '{' {
		var j struct {
			Time     time.Time `json:"time"`
			Class    string    `json:"class"`
			Site     string    `json:"site"`
			Origin   string    `json:"origin"`
			Upstream string    `json:"upstream"`
			Client   string    `json:"client"`
			Agent    string    `json:"useragent"`
			Method   string    `json:"method"`
			URI      string    `json:"uri"`
			Status   int       `json:"status"`
		}
		if json.Unmarshal([]byte(line), &j) != nil || j.Status == 0 {
			return e, false
		}
		return Entry{Time: j.Time, Class: j.Class, Origin: j.Origin, Client: j.Client, Agent: j.Agent, Method: j.Method, URI: j.URI, Status: j.Status, Site: j.Site, Upstream: j.Upstream}, true
	}
	m := textLine.FindStringSubmatch(line)
	if m == nil {
		return e, false
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05.000000", m[1], time.Local)
	if err != nil {
		t, err = time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
		if err != nil {
			return e, false
		}
	}
	st, _ := strconv.Atoi(m[8])
	return Entry{Time: t, Class: m[2], Origin: m[3], Client: strings.TrimSpace(m[4]), Agent: m[5], Method: m[6], URI: m[7], Status: st}, true
}

// Query is a compiled search
type Query struct {
	From, To     time.Time
	Source       string // "" = all, "global", or a site folder name
	Host         string // case-insensitive substring of the origin / site
	StatusSet    map[int]bool
	StatusClass  map[int]bool // 2,3,4,5
	Methods      map[string]bool
	Prefixes     []netip.Prefix
	Country      string
	PathContains string
	PathRegex    *regexp.Regexp
	AgentContain string
	Class        string

	Offset int
	Limit  int

	MaxScanBytes int64
	MaxScanTime  time.Duration
}

// ParseQuery builds a Query from request parameters, rejecting invalid or too
// expensive input.
func ParseQuery(get func(string) string) (*Query, error) {
	q := &Query{Limit: 200}
	parseTime := func(name string) (time.Time, error) {
		v := strings.TrimSpace(get(name))
		if v == "" {
			return time.Time{}, nil
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			if n > 1e12 { // milliseconds
				return time.UnixMilli(n), nil
			}
			return time.Unix(n, 0), nil
		}
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
			if t, err := time.ParseInLocation(layout, v, time.Local); err == nil {
				return t, nil
			}
		}
		return time.Time{}, errors.New("invalid " + name + " time")
	}
	var err error
	if q.From, err = parseTime("from"); err != nil {
		return nil, err
	}
	if q.To, err = parseTime("to"); err != nil {
		return nil, err
	}
	q.Source = strings.TrimSpace(get("source"))
	q.Host = strings.ToLower(strings.TrimSpace(get("host")))
	q.Class = strings.TrimSpace(get("class"))
	for _, tok := range strings.FieldsFunc(get("status"), func(r rune) bool { return r == ',' || r == ' ' }) {
		tok = strings.ToLower(tok)
		if len(tok) == 3 && tok[1:] == "xx" && tok[0] >= '1' && tok[0] <= '5' {
			if q.StatusClass == nil {
				q.StatusClass = map[int]bool{}
			}
			q.StatusClass[int(tok[0]-'0')] = true
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil || n < 100 || n > 599 {
			return nil, errors.New("invalid status filter: " + tok)
		}
		if q.StatusSet == nil {
			q.StatusSet = map[int]bool{}
		}
		q.StatusSet[n] = true
	}
	for _, m := range strings.FieldsFunc(get("method"), func(r rune) bool { return r == ',' || r == ' ' }) {
		if q.Methods == nil {
			q.Methods = map[string]bool{}
		}
		q.Methods[strings.ToUpper(m)] = true
	}
	for _, c := range strings.FieldsFunc(get("ip"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if !strings.Contains(c, "/") {
			a, err := netip.ParseAddr(c)
			if err != nil {
				return nil, errors.New("invalid client IP/CIDR: " + c)
			}
			c = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String()
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, errors.New("invalid client IP/CIDR: " + c)
		}
		q.Prefixes = append(q.Prefixes, p.Masked())
		if len(q.Prefixes) > 64 {
			return nil, errors.New("too many IP filters")
		}
	}
	q.Country = strings.ToLower(strings.TrimSpace(get("country")))
	q.AgentContain = strings.ToLower(get("useragent"))
	if len(q.AgentContain) > MaxPatternLength {
		return nil, errors.New("user agent filter too long")
	}
	path := get("path")
	if len(path) > MaxPatternLength {
		return nil, errors.New("path filter too long")
	}
	if re := get("pathregex"); re != "" {
		if len(re) > MaxPatternLength {
			return nil, errors.New("regular expression too long (max " + strconv.Itoa(MaxPatternLength) + ")")
		}
		if q.PathRegex, err = regexp.Compile(re); err != nil {
			return nil, errors.New("invalid regular expression: " + err.Error())
		}
	}
	q.PathContains = strings.ToLower(path)
	if v := get("offset"); v != "" {
		if q.Offset, err = strconv.Atoi(v); err != nil || q.Offset < 0 || q.Offset > 1000000 {
			return nil, errors.New("invalid offset")
		}
	}
	if v := get("limit"); v != "" {
		if q.Limit, err = strconv.Atoi(v); err != nil || q.Limit < 1 {
			return nil, errors.New("invalid limit")
		}
		if q.Limit > MaxResults {
			q.Limit = MaxResults
		}
	}
	q.MaxScanBytes = DefaultScanBytes
	if v := get("maxscanmb"); v != "" {
		mb, err := strconv.ParseInt(v, 10, 64)
		if err != nil || mb < 1 {
			return nil, errors.New("invalid maxscanmb")
		}
		q.MaxScanBytes = mb << 20
		if q.MaxScanBytes > MaxScanBytesCap {
			q.MaxScanBytes = MaxScanBytesCap
		}
	}
	q.MaxScanTime = DefaultScanTime
	if v := get("maxscansec"); v != "" {
		sec, err := strconv.Atoi(v)
		if err != nil || sec < 1 {
			return nil, errors.New("invalid maxscansec")
		}
		q.MaxScanTime = time.Duration(sec) * time.Second
		if q.MaxScanTime > MaxScanTimeCap {
			q.MaxScanTime = MaxScanTimeCap
		}
	}
	return q, nil
}

// Match applies all filters except the country filter (needs a resolver)
func (q *Query) Match(e *Entry) bool {
	if !q.From.IsZero() && e.Time.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && e.Time.After(q.To) {
		return false
	}
	if q.StatusSet != nil || q.StatusClass != nil {
		if !q.StatusSet[e.Status] && !q.StatusClass[e.Status/100] {
			return false
		}
	}
	if q.Methods != nil && !q.Methods[strings.ToUpper(e.Method)] {
		return false
	}
	if q.Class != "" && e.Class != q.Class {
		return false
	}
	if q.Host != "" && !strings.Contains(strings.ToLower(e.Origin), q.Host) && !strings.Contains(strings.ToLower(e.Site), q.Host) {
		return false
	}
	if len(q.Prefixes) > 0 {
		a, err := netip.ParseAddr(strings.Trim(e.Client, "[]"))
		if err != nil {
			return false
		}
		a = a.Unmap()
		in := false
		for _, p := range q.Prefixes {
			if p.Contains(a) {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	if q.PathContains != "" && !strings.Contains(strings.ToLower(e.URI), q.PathContains) {
		return false
	}
	if q.PathRegex != nil && !q.PathRegex.MatchString(e.URI) {
		return false
	}
	if q.AgentContain != "" && !strings.Contains(strings.ToLower(e.Agent), q.AgentContain) {
		return false
	}
	return true
}

// SearchResult is the response of a search
type SearchResult struct {
	Entries         []Entry `json:"entries"`
	Matched         int     `json:"matched"`    // matches seen while scanning (stops once the page is full)
	NextOffset      int     `json:"nextOffset"` // pass as offset to get the next page (0 = no more)
	Truncated       bool    `json:"truncated"`  // a scan bound was hit: older entries may exist
	TruncatedReason string  `json:"truncatedReason,omitempty"`
	ScannedBytes    int64   `json:"scannedBytes"`
	ScannedFiles    int     `json:"scannedFiles"`
	MaxScanBytes    int64   `json:"maxScanBytes"`
}

// CountryResolver maps an IP to a lower-case ISO country code ("" = unknown)
type CountryResolver func(ip string) string

type logFileRef struct {
	path    string
	source  string
	gz      bool
	modTime time.Time
	size    int64
}

// listSearchFiles returns the log files below root (global files and sites/<name>/ files)
// newest first. Only files found by walking root are ever opened.
func (v *Viewer) listSearchFiles(source string) []logFileRef {
	var out []logFileRef
	root := v.option.RootFolder
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		n := d.Name()
		gz := strings.HasSuffix(n, ".log.gz")
		if !gz && !strings.HasSuffix(n, ".log") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		src := "global"
		if len(parts) == 3 && parts[0] == "sites" {
			src = parts[1]
		} else if len(parts) != 1 {
			return nil
		}
		if source != "" && source != src {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		out = append(out, logFileRef{path: p, source: src, gz: gz, modTime: info.ModTime(), size: info.Size()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].modTime.After(out[j].modTime) })
	return out
}

// ListSources returns the selectable log sources ("global" and one per site)
func (v *Viewer) ListSources() []string {
	seen := map[string]bool{}
	for _, f := range v.listSearchFiles("") {
		seen[f.source] = true
	}
	out := []string{}
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type budget struct {
	bytes    int64
	max      int64
	deadline time.Time
	reason   string
}

func (b *budget) exceeded() bool {
	if b.reason != "" {
		return true
	}
	if b.bytes >= b.max {
		b.reason = "scan size limit reached"
		return true
	}
	if time.Now().After(b.deadline) {
		b.reason = "scan time limit reached"
		return true
	}
	return false
}

// Search runs the query newest-file-first. Within a plain file lines are read
// backwards so the newest matches come first and a page can stop early.
func (v *Viewer) Search(q *Query, geo CountryResolver) *SearchResult {
	res := &SearchResult{Entries: []Entry{}, MaxScanBytes: q.MaxScanBytes}
	b := &budget{max: q.MaxScanBytes, deadline: time.Now().Add(q.MaxScanTime)}
	skip := q.Offset
	want := q.Limit
	geoCache := map[string]string{}
	var geoCalls int
	accept := func(e *Entry) bool { // returns true to keep scanning
		if q.Country != "" {
			if geo == nil {
				return true
			}
			c, ok := geoCache[e.Client]
			if !ok {
				if geoCalls > 50000 {
					return true
				}
				geoCalls++
				c = strings.ToLower(geo(e.Client))
				if len(geoCache) < 20000 {
					geoCache[e.Client] = c
				}
			}
			if c != q.Country {
				return true
			}
			e.Country = c
		}
		res.Matched++
		if skip > 0 {
			skip--
			return true
		}
		res.Entries = append(res.Entries, *e)
		if len(res.Entries) >= want {
			res.NextOffset = q.Offset + len(res.Entries)
			return false
		}
		return true
	}

	files := v.listSearchFiles(q.Source)
	for _, f := range files {
		if !q.From.IsZero() && f.modTime.Before(q.From) {
			continue // last write is before the range
		}
		if b.exceeded() {
			break
		}
		res.ScannedFiles++
		var cont bool
		if f.gz {
			cont = scanGz(f, q, b, accept)
		} else {
			cont = scanPlainReverse(f, q, b, accept)
		}
		if !cont {
			break
		}
	}
	res.ScannedBytes = b.bytes
	if b.reason != "" {
		res.Truncated = true
		res.TruncatedReason = b.reason
		if res.NextOffset == 0 {
			res.NextOffset = q.Offset + len(res.Entries)
		}
	}
	return res
}

func finishEntry(e *Entry, f logFileRef) {
	e.Source = f.source
	if e.Site == "" && f.source != "global" {
		e.Site = f.source
	}
}

// scanPlainReverse reads the file backwards in chunks and feeds parsed lines newest first
func scanPlainReverse(f logFileRef, q *Query, b *budget, accept func(*Entry) bool) bool {
	fh, err := os.Open(f.path)
	if err != nil {
		return true
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return true
	}
	pos := st.Size()
	const chunk = 64 << 10
	var carry []byte // incomplete line start carried from the later chunk
	buf := make([]byte, chunk)
	handle := func(line []byte) (stop bool, cont bool) {
		if len(line) == 0 || len(line) > MaxLineBytes {
			return false, true
		}
		e, ok := ParseLine(string(line))
		if !ok {
			return false, true
		}
		if !q.From.IsZero() && e.Time.Before(q.From) {
			return true, true // lines are chronological: everything before is older
		}
		finishEntry(&e, f)
		if !q.To.IsZero() && e.Time.After(q.To) {
			return false, true
		}
		if !q.Match(&e) {
			return false, true
		}
		return false, accept(&e)
	}
	for pos > 0 {
		if b.exceeded() {
			return false
		}
		n := int64(chunk)
		if pos < n {
			n = pos
		}
		pos -= n
		if _, err := fh.ReadAt(buf[:n], pos); err != nil && err != io.EOF {
			return true
		}
		b.bytes += n
		data := append(append([]byte{}, buf[:n]...), carry...)
		carry = nil
		end := len(data)
		for i := len(data) - 1; i >= 0; i-- {
			if data[i] == '\n' {
				if stop, cont := handle(data[i+1 : end]); !cont {
					return false
				} else if stop {
					return true
				}
				end = i
			}
		}
		carry = append([]byte{}, data[:end]...)
		if len(carry) > MaxLineBytes {
			carry = nil // oversize line: drop it; the remaining fragment will be rejected as malformed
		}
	}
	if len(carry) > 0 {
		if _, cont := handle(carry); !cont {
			return false
		}
	}
	return true
}

// scanGz streams a compressed file forward and yields its matches newest first
func scanGz(f logFileRef, q *Query, b *budget, accept func(*Entry) bool) bool {
	fh, err := os.Open(f.path)
	if err != nil {
		return true
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		return true
	}
	defer zr.Close()
	var matches []Entry
	br := bufio.NewReaderSize(zr, 64<<10)
	for {
		if b.exceeded() {
			break
		}
		line, tooLong, err := readLineLimited(br, MaxLineBytes)
		b.bytes += int64(len(line)) + 1
		if len(line) > 0 && !tooLong {
			if e, ok := ParseLine(string(line)); ok {
				finishEntry(&e, f)
				if q.Match(&e) && len(matches) < maxGzMatches {
					matches = append(matches, e)
				}
			}
		}
		if err != nil {
			break
		}
	}
	for i := len(matches) - 1; i >= 0; i-- {
		if !accept(&matches[i]) {
			return false
		}
	}
	return b.reason == ""
}

// readLineLimited reads one line; lines longer than max are consumed and flagged
func readLineLimited(br *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		part, isPrefix, e := br.ReadLine()
		if e != nil {
			return line, tooLong, e
		}
		if !tooLong {
			if len(line)+len(part) > max {
				tooLong = true
				line = nil
			} else {
				line = append(line, part...)
			}
		}
		if !isPrefix {
			return line, tooLong, nil
		}
	}
}

// ---- HTTP handlers ----

// HandleSearch serves GET /api/log/search
func (v *Viewer) HandleSearch(geo CountryResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q, err := ParseQuery(func(k string) string { return r.URL.Query().Get(k) })
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		res := v.Search(q, geo)
		js, _ := json.Marshal(res)
		utils.SendJSONResponse(w, string(js))
	}
}

// HandleSources serves GET /api/log/sources
func (v *Viewer) HandleSources(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(v.ListSources())
	utils.SendJSONResponse(w, string(js))
}

// HandleSearchDownload serves GET /api/log/searchExport?format=csv|json plus the search parameters.
// At most MaxExportRows rows are exported; X-Truncated tells when a scan bound or the row cap was hit.
func (v *Viewer) HandleSearchDownload(geo CountryResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		get := func(k string) string { return r.URL.Query().Get(k) }
		q, err := ParseQuery(get)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		format := get("format")
		if format != "csv" && format != "json" {
			utils.SendErrorResponse(w, "format must be csv or json")
			return
		}
		q.Offset = 0
		q.Limit = MaxExportRows
		res := v.Search(q, geo)
		truncated := res.Truncated || len(res.Entries) >= MaxExportRows
		w.Header().Set("X-Truncated", strconv.FormatBool(truncated))
		stamp := time.Now().Format("20060102-150405")
		if format == "json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=zoraxy-access-log-"+stamp+".json")
			json.NewEncoder(w).Encode(map[string]interface{}{"truncated": truncated, "truncatedReason": res.TruncatedReason, "entries": res.Entries})
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=zoraxy-access-log-"+stamp+".csv")
		cw := csv.NewWriter(w)
		cw.Write([]string{"time", "source", "origin", "client", "country", "method", "uri", "status", "class", "useragent"})
		for _, e := range res.Entries {
			cw.Write([]string{e.Time.Format(time.RFC3339Nano), e.Source, csvSafe(e.Origin), e.Client, e.Country, e.Method, csvSafe(e.URI), strconv.Itoa(e.Status), e.Class, csvSafe(e.Agent)})
		}
		if truncated {
			cw.Write([]string{"# truncated: " + res.TruncatedReason})
		}
		cw.Flush()
	}
}

// csvSafe neutralises spreadsheet formula injection in exported attacker-controlled fields
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
