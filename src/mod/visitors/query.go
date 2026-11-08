package visitors

import (
	"encoding/csv"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Filter narrows visitors / visits
type Filter struct {
	Q           string // case-insensitive substring of IP, country, host, user agent
	Host        string // exact host (lower case)
	Country     string // ISO code
	Via         string // direct | cloudflare | proxy
	BlockedOnly bool
	Since       int64 // unix seconds; only entries seen at or after this time
}

func (f Filter) matchVisit(v *Visit) bool {
	if f.Since > 0 && v.Time < f.Since {
		return false
	}
	if f.Host != "" && v.Host != f.Host {
		return false
	}
	if f.Country != "" && !strings.EqualFold(v.Country, f.Country) {
		return false
	}
	if f.Via != "" && v.Via != f.Via {
		return false
	}
	if f.BlockedOnly && !v.Blocked {
		return false
	}
	if f.Q != "" {
		q := strings.ToLower(f.Q)
		if !strings.Contains(strings.ToLower(v.IP), q) && !strings.Contains(strings.ToLower(v.Host), q) &&
			!strings.Contains(strings.ToLower(v.UA), q) && !strings.Contains(strings.ToLower(v.Path), q) &&
			!strings.EqualFold(v.Country, q) {
			return false
		}
	}
	return true
}

func (f Filter) matchVisitor(v *Visitor) bool {
	if f.Since > 0 && v.LastSeen < f.Since {
		return false
	}
	if f.Host != "" {
		if _, ok := v.Hosts[f.Host]; !ok {
			return false
		}
	}
	if f.Country != "" && !strings.EqualFold(v.Country, f.Country) {
		return false
	}
	if f.Via != "" && v.Via != f.Via {
		return false
	}
	if f.BlockedOnly && v.Blocked == 0 {
		return false
	}
	if f.Q != "" {
		q := strings.ToLower(f.Q)
		if strings.Contains(strings.ToLower(v.IP), q) || strings.EqualFold(v.Country, q) ||
			strings.Contains(strings.ToLower(v.LastUA), q) || strings.Contains(strings.ToLower(v.LastPath), q) {
			return true
		}
		for h := range v.Hosts {
			if strings.Contains(h, q) {
				return true
			}
		}
		return false
	}
	return true
}

// ListQuery selects a page of visitors
type ListQuery struct {
	Filter
	Sort string // ip | country | first | last | hits | blocked | hosts | via (default last)
	Desc bool
	Page int // 0 based
	Size int // default 50, max 500
}

// ListResult is one page of visitors
type ListResult struct {
	Total int       `json:"total"`
	Page  int       `json:"page"`
	Size  int       `json:"size"`
	Items []Visitor `json:"items"`
}

// ValidSort reports whether s is a sort key List understands
func ValidSort(s string) bool {
	switch s {
	case "", "ip", "country", "first", "last", "hits", "blocked", "hosts", "via":
		return true
	}
	return false
}

// List returns a filtered, sorted page. The returned items are copies.
func (t *Tracker) List(q ListQuery) ListResult {
	if q.Size <= 0 {
		q.Size = 50
	}
	if q.Size > 500 {
		q.Size = 500
	}
	if q.Page < 0 {
		q.Page = 0
	}
	t.mu.RLock()
	matched := make([]*Visitor, 0, 256)
	for _, v := range t.visitors {
		if q.matchVisitor(v) {
			matched = append(matched, v)
		}
	}
	less := func(a, b *Visitor) bool { return a.LastSeen < b.LastSeen }
	switch q.Sort {
	case "ip":
		less = func(a, b *Visitor) bool { return a.IP < b.IP }
	case "country":
		less = func(a, b *Visitor) bool { return a.Country < b.Country }
	case "first":
		less = func(a, b *Visitor) bool { return a.FirstSeen < b.FirstSeen }
	case "hits":
		less = func(a, b *Visitor) bool { return a.Hits < b.Hits }
	case "blocked":
		less = func(a, b *Visitor) bool { return a.Blocked < b.Blocked }
	case "hosts":
		less = func(a, b *Visitor) bool { return len(a.Hosts) < len(b.Hosts) }
	case "via":
		less = func(a, b *Visitor) bool { return a.Via < b.Via }
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if q.Desc {
			if less(matched[j], matched[i]) {
				return true
			}
			if less(matched[i], matched[j]) {
				return false
			}
		} else {
			if less(matched[i], matched[j]) {
				return true
			}
			if less(matched[j], matched[i]) {
				return false
			}
		}
		return matched[i].IP < matched[j].IP // stable, deterministic order for ties
	})
	res := ListResult{Total: len(matched), Page: q.Page, Size: q.Size, Items: []Visitor{}}
	from := q.Page * q.Size
	if from < len(matched) {
		to := from + q.Size
		if to > len(matched) {
			to = len(matched)
		}
		for _, v := range matched[from:to] {
			c := cloneVisitor(v)
			c.Paths, c.Daily = nil, nil // detail only
			res.Items = append(res.Items, *c)
		}
	}
	t.mu.RUnlock()
	return res
}

// All returns copies of every visitor matching the filter, newest first (export)
func (t *Tracker) All(f Filter) []Visitor {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Visitor, 0, len(t.visitors))
	for _, v := range t.visitors {
		if f.matchVisitor(v) {
			c := cloneVisitor(v)
			c.Daily = nil
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	return out
}

// Summary are the numbers for the top of the page
type Summary struct {
	IPs         int            `json:"ips"`
	Active24h   int            `json:"active24h"`
	New1h       int            `json:"new1h"`
	New24h      int            `json:"new24h"`
	BlockedIPs  int            `json:"blockedIPs"`
	TopCountry  []CountryCount `json:"topCountries"`
	Via         map[string]int `json:"via"`
	Hosts       []string       `json:"hosts"`
	Countries   []string       `json:"countries"`
	OldestFirst int64          `json:"oldest"`
}

// CountryCount is a country and its number of IPs
type CountryCount struct {
	Country string `json:"country"`
	IPs     int    `json:"ips"`
}

// Summary computes the headline numbers
func (t *Tracker) Summary(now time.Time) Summary {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := Summary{IPs: len(t.visitors), Via: map[string]int{}}
	d, h := now.Add(-24*time.Hour).Unix(), now.Add(-time.Hour).Unix()
	cc := map[string]int{}
	hosts := map[string]int{}
	for _, v := range t.visitors {
		if v.LastSeen >= d {
			s.Active24h++
		}
		if v.FirstSeen >= h {
			s.New1h++
		}
		if v.FirstSeen >= d {
			s.New24h++
		}
		if v.Blocked > 0 {
			s.BlockedIPs++
		}
		if v.Country != "" {
			cc[v.Country]++
		}
		s.Via[v.Via]++
		for host := range v.Hosts {
			hosts[host]++
		}
		if s.OldestFirst == 0 || v.FirstSeen < s.OldestFirst {
			s.OldestFirst = v.FirstSeen
		}
	}
	for c, n := range cc {
		s.TopCountry = append(s.TopCountry, CountryCount{c, n})
		s.Countries = append(s.Countries, c)
	}
	sort.Slice(s.TopCountry, func(i, j int) bool {
		if s.TopCountry[i].IPs != s.TopCountry[j].IPs {
			return s.TopCountry[i].IPs > s.TopCountry[j].IPs
		}
		return s.TopCountry[i].Country < s.TopCountry[j].Country
	})
	if len(s.TopCountry) > 5 {
		s.TopCountry = s.TopCountry[:5]
	}
	sort.Strings(s.Countries)
	for host := range hosts {
		s.Hosts = append(s.Hosts, host)
	}
	sort.Slice(s.Hosts, func(i, j int) bool {
		if hosts[s.Hosts[i]] != hosts[s.Hosts[j]] {
			return hosts[s.Hosts[i]] > hosts[s.Hosts[j]]
		}
		return s.Hosts[i] < s.Hosts[j]
	})
	if len(s.Hosts) > 200 {
		s.Hosts = s.Hosts[:200]
	}
	return s
}

// CSVSafe neutralises spreadsheet formula injection: a cell that starts with = + - @ tab or CR
// would be executed by Excel / LibreOffice, so it gets a leading apostrophe.
func CSVSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		return "'" + s
	}
	return s
}

func ts(u int64) string {
	if u <= 0 {
		return ""
	}
	return time.Unix(u, 0).UTC().Format(time.RFC3339)
}

// WriteVisitorsCSV writes visitors as CSV
func WriteVisitorsCSV(w io.Writer, items []Visitor) error {
	cw := csv.NewWriter(w)
	cw.Write([]string{"ip", "country", "first_seen", "last_seen", "hits", "blocked", "via", "via_header", "hosts", "last_host", "last_path", "last_status", "user_agent"})
	for _, v := range items {
		hosts := make([]string, 0, len(v.Hosts))
		for h := range v.Hosts {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		cw.Write([]string{CSVSafe(v.IP), CSVSafe(v.Country), ts(v.FirstSeen), ts(v.LastSeen), strconv.FormatUint(v.Hits, 10),
			strconv.FormatUint(v.Blocked, 10), CSVSafe(v.Via), CSVSafe(v.ViaHeader), CSVSafe(strings.Join(hosts, " ")),
			CSVSafe(v.LastHost), CSVSafe(v.LastPath), strconv.Itoa(v.LastStatus), CSVSafe(v.LastUA)})
	}
	cw.Flush()
	return cw.Error()
}

// WriteVisitsCSV writes individual visits as CSV
func WriteVisitsCSV(w io.Writer, items []Visit) error {
	cw := csv.NewWriter(w)
	cw.Write([]string{"time", "ip", "country", "host", "method", "path", "status", "via", "blocked", "user_agent"})
	for _, v := range items {
		cw.Write([]string{ts(v.Time), CSVSafe(v.IP), CSVSafe(v.Country), CSVSafe(v.Host), CSVSafe(v.Method), CSVSafe(v.Path),
			strconv.Itoa(v.Status), CSVSafe(v.Via), strconv.FormatBool(v.Blocked), CSVSafe(v.UA)})
	}
	cw.Flush()
	return cw.Error()
}
