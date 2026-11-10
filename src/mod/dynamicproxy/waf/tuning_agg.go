package waf

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

/*
	tuning_agg.go

	WAF tuning assistant, part 2: aggregate the stored events by (rule, endpoint, variable) and propose the
	narrowest exclusion for each group. Nothing here changes any configuration.
*/

// TuningSuggestion is the proposed exclusion for one group. Kind says which kind of exclusion it becomes:
//
//	variable   TargetExclusion{RuleIDs, Target, Path, Exact}  (the rule keeps inspecting everything else)
//	path-rule  PathExclusion{Path, Exact, RuleIDs}            (only when the variable cannot be excluded on its own)
//	rule       ExcludedRuleIDs                                (last resort: no variable and no single path)
type TuningSuggestion struct {
	Kind    string   `json:"kind"`
	RuleIDs []string `json:"rule_ids"`
	Target  string   `json:"target,omitempty"`
	Path    string   `json:"path,omitempty"`
	Exact   bool     `json:"exact,omitempty"`
	Summary string   `json:"summary"` // one line a human can read before confirming
}

// TuningSample is one example event of a group, with nothing the event does not already store
type TuningSample struct {
	Time          time.Time `json:"time"`
	TransactionID string    `json:"txid"`
	Path          string    `json:"path"`
	Variable      string    `json:"variable,omitempty"` // as Coraza reported it, e.g. REQUEST_COOKIES:ph_phc_x_posthog
	Data          string    `json:"data,omitempty"`     // matched data, already truncated by the engine
}

// TuningItem is one (rule, endpoint, variable) group
type TuningItem struct {
	Key             string           `json:"key"` // stable identifier, used by the UI to remember "ignore"
	RuleID          int              `json:"rule_id"`
	Message         string           `json:"message"`
	Severity        string           `json:"severity"`
	Category        string           `json:"category,omitempty"`
	Endpoint        string           `json:"endpoint"`
	Variable        string           `json:"variable"`   // normalised, e.g. REQUEST_COOKIES:ph_*_posthog ("" = unknown)
	Collection      string           `json:"collection"` // REQUEST_COOKIES
	Count           int              `json:"count"`
	Clients         int              `json:"clients"`
	WouldBlock      int              `json:"would_block"` // events that would be (or were) blocked
	FirstSeen       time.Time        `json:"first_seen"`
	LastSeen        time.Time        `json:"last_seen"`
	Paths           []string         `json:"paths"` // up to 5
	PathCount       int              `json:"path_count"`
	Shapes          int              `json:"payload_shapes"` // structurally different payloads
	Sample          TuningSample     `json:"sample"`
	Suggestion      TuningSuggestion `json:"suggestion"`
	Risk            string           `json:"risk"` // low, medium, high
	RiskNote        string           `json:"risk_note"`
	LooksLikeAttack bool             `json:"looksLikeAttack"`
}

// TuningReport is the answer of the tuning API
type TuningReport struct {
	Hours         int          `json:"hours"`
	Endpoint      string       `json:"endpoint,omitempty"`
	EventsScanned int          `json:"events_scanned"`
	Items         []TuningItem `json:"items"`
}

const maxTuningItems = 200

// Rules that only evaluate the anomaly score, never a detection of their own: the blocking
// evaluation (949xxx inbound), the outbound evaluation (959xxx) and the correlation/reporting rules
// (980xxx). Excluding one of them disables blocking, so no tuning path may do it.
func isScoreRule(id int) bool {
	return id == anomalyEvaluationRuleID || (id >= 949000 && id < 950000) || (id >= 959000 && id < 960000) || (id >= 980000 && id < 981000)
}

// IsScoreRule is the exported form of isScoreRule for callers that build exclusions (the AI
// assistant, the tuning apply endpoint).
func IsScoreRule(id int) bool { return isScoreRule(id) }

// SpecTouchesScoreRule reports whether a rule ID specification ("949110" or a range "949000-949999")
// names or covers a score rule. Unparsable specs report true: they are refused.
func SpecTouchesScoreRule(spec string) bool {
	spec = strings.TrimSpace(spec)
	lo, hi := spec, spec
	if i := strings.IndexByte(spec, '-'); i >= 0 {
		lo, hi = spec[:i], spec[i+1:]
	}
	a, err1 := strconv.Atoi(lo)
	b, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil || a < 0 || b < a {
		return true
	}
	for _, r := range [][2]int{{949000, 949999}, {959000, 959999}, {980000, 980999}} {
		if a <= r[1] && b >= r[0] {
			return true
		}
	}
	return false
}

// Variable name families whose names rotate per site or per visitor. display is shown, rx is the selector.
var nameFamilies = []struct {
	re      *regexp.Regexp
	display string
	rx      string
}{
	{regexp.MustCompile(`^ph_.+_posthog$`), "ph_*_posthog", `^ph_.+_posthog$`},
	{regexp.MustCompile(`^ph_.+_window_id$`), "ph_*_window_id", `^ph_.+_window_id$`},
	{regexp.MustCompile(`^_ga_.+$`), "_ga_*", `^_ga_.+$`},
	{regexp.MustCompile(`^_gcl_.+$`), "_gcl_*", `^_gcl_.+$`},
	{regexp.MustCompile(`^_hj.+$`), "_hj*", `^_hj.+$`},
	{regexp.MustCompile(`^mp_.+_mixpanel$`), "mp_*_mixpanel", `^mp_.+_mixpanel$`},
	{regexp.MustCompile(`^ajs_.+$`), "ajs_*", `^ajs_.+$`},
	{regexp.MustCompile(`^amplitude_.+$`), "amplitude_*", `^amplitude_.+$`},
	{regexp.MustCompile(`^_pk_.+$`), "_pk_*", `^_pk_.+$`},
	{regexp.MustCompile(`^_uet.+$`), "_uet*", `^_uet.+$`},
	{regexp.MustCompile(`^_tt_.+$`), "_tt_*", `^_tt_.+$`},
}

var (
	reUUID   = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reHexTok = regexp.MustCompile(`[0-9a-f]{12,}`)
	reIndex  = regexp.MustCompile(`(^|[.\[])[0-9]+($|[.\]])`)
)

// wildcard is a placeholder rune for a collapsed part of a name, with the regex that stands for it
type namePart struct {
	lit string // literal text (when rx is empty)
	rx  string // regex fragment
}

// normalizeName collapses the parts of a variable name that obviously rotate (analytics cookie families,
// array indexes of JSON paths, UUIDs and long hex tokens) and returns the display form, the selector to use in
// an exclusion and whether anything was collapsed. name must already be lower case.
func normalizeName(coll, name string) (display, selector string, collapsed bool) {
	if strings.HasPrefix(coll, "REQUEST_COOKIES") {
		for _, f := range nameFamilies {
			if f.re.MatchString(name) {
				return f.display, "/" + f.rx + "/", true
			}
		}
	}
	var parts []namePart
	rest := name
	// array indexes: json.a.0.b -> json.a.*.b, items[3] -> items[*]
	for {
		loc := reIndex.FindStringIndex(rest)
		if loc == nil {
			break
		}
		m := reIndex.FindStringSubmatch(rest)
		digitsStart := loc[0] + len(m[1])
		digitsEnd := loc[1] - len(m[2])
		parts = append(parts, namePart{lit: rest[:digitsStart]}, namePart{rx: `\d+`})
		rest = rest[digitsEnd:]
		collapsed = true
	}
	parts = append(parts, namePart{lit: rest})
	// uuids and long hex tokens inside the literal parts
	var split []namePart
	for _, p := range parts {
		if p.rx != "" {
			split = append(split, p)
			continue
		}
		lit := p.lit
		for lit != "" {
			loc := reUUID.FindStringIndex(lit)
			rx := `[0-9a-f-]+`
			if loc == nil {
				loc = reHexTok.FindStringIndex(lit)
				rx = `[0-9a-f]+`
			}
			if loc == nil {
				break
			}
			split = append(split, namePart{lit: lit[:loc[0]]}, namePart{rx: rx})
			lit = lit[loc[1]:]
			collapsed = true
		}
		split = append(split, namePart{lit: lit})
	}
	// build display and selector; characters that cannot appear in a selector become "."
	var disp, rx strings.Builder
	unsafe := false
	for _, p := range split {
		if p.rx != "" {
			disp.WriteString("*")
			rx.WriteString(p.rx)
			continue
		}
		for _, c := range p.lit {
			if c < 0x80 && safeNamePattern.MatchString(string(c)) {
				disp.WriteRune(c)
				rx.WriteString(regexp.QuoteMeta(string(c)))
			} else {
				disp.WriteString("?")
				rx.WriteString(".")
				unsafe = true
			}
		}
	}
	if !collapsed && !unsafe {
		return name, name, false
	}
	pat := "^" + rx.String() + "$"
	if len(pat) > maxTargetRegexLen {
		// too long to be a readable exclusion: keep the exact name when it is expressible, else the prefix
		if !unsafe {
			return name, name, false
		}
		pat = pat[:maxTargetRegexLen-2] + ".*$"
	}
	return disp.String(), "/" + pat + "/", true
}

// splitVarNorm splits "COLLECTION:name" (as stored in RuleHit.VarNorm)
func splitVarNorm(v string) (coll, name string) {
	coll, name, _ = SplitTarget(v)
	return
}

// groupVariable returns the display variable and the exclusion target for a hit
func groupVariable(h RuleHit) (display, target, coll string) {
	if h.VarNorm == "" {
		return "", "", ""
	}
	coll, name := splitVarNorm(h.VarNorm)
	if name == "" {
		display, target = coll, coll
		if targetCollections[coll] {
			return display, "", coll // a collection that needs a name: never exclude all of it
		}
	} else {
		d, sel, _ := normalizeName(coll, name)
		display = coll + ":" + d
		target = coll + ":" + sel
	}
	if allowSel, ok := targetCollections[coll]; !ok || (!allowSel && name != "") {
		return display, "", coll // known variable that cannot be excluded on its own
	}
	if ValidateTarget(target) != nil {
		return display, "", coll
	}
	return display, target, coll
}

// payloadShape reduces a matched value to its punctuation structure, so ids and timestamps of otherwise
// identical payloads (an analytics cookie) collapse while genuinely different attack strings do not.
func payloadShape(s string) string {
	var b strings.Builder
	var last rune
	for _, c := range strings.ToLower(s) {
		var o rune
		switch {
		case c >= '0' && c <= '9':
			o = '0'
		case c >= 'a' && c <= 'z' || c > 0x7f:
			o = 'a'
		case c == ' ' || c == '\t':
			o = ' '
		default:
			o = c
		}
		if (o == '0' || o == 'a' || o == ' ') && o == last {
			continue
		}
		b.WriteRune(o)
		last = o
	}
	return b.String()
}

// attackFamily reports CRS rule families that are almost never false positives: path traversal / LFI,
// RFI, command injection, PHP / Java code injection, SSRF-style generic attacks, scanners and protocol attacks
func attackFamily(id int) string {
	switch {
	case id >= 930000 && id < 931000:
		return "path traversal / local file inclusion"
	case id >= 931000 && id < 932000:
		return "remote file inclusion"
	case id >= 932000 && id < 933000:
		return "remote command execution"
	case id >= 933000 && id < 934000:
		return "PHP injection"
	case id >= 934000 && id < 935000:
		return "generic application attack"
	case id >= 944000 && id < 945000:
		return "Java injection"
	case id >= 913000 && id < 914000:
		return "scanner / bot detection"
	case id >= 921000 && id < 922000:
		return "protocol attack"
	}
	return ""
}

type tuningGroup struct {
	item    TuningItem
	clients map[string]bool
	paths   map[string]int
	shapes  map[string]bool
	datas   map[string]bool
	target  string
	pathsOK bool
}

// Tuning aggregates the buffered events into tuning suggestions
func (m *Manager) Tuning(since time.Time, endpoint string, hours int) TuningReport {
	evs := m.QueryEvents(EventFilter{Since: since, Endpoint: endpoint})
	return BuildTuningReport(evs, endpoint, hours)
}

// BuildTuningReport is Tuning on an explicit event list (newest first or any order)
func BuildTuningReport(evs []Event, endpoint string, hours int) TuningReport {
	groups := map[string]*tuningGroup{}
	for _, ev := range evs {
		seenInEvent := map[string]bool{}
		for _, h := range ev.Rules {
			if isScoreRule(h.ID) {
				continue
			}
			display, target, coll := groupVariable(h)
			key := ev.Endpoint + "|" + itoa(h.ID) + "|" + display
			g := groups[key]
			if g == nil {
				g = &tuningGroup{clients: map[string]bool{}, paths: map[string]int{}, shapes: map[string]bool{}, datas: map[string]bool{}}
				g.item = TuningItem{
					Key: key, RuleID: h.ID, Message: h.Message, Severity: h.Severity, Endpoint: ev.Endpoint,
					Variable: display, Collection: coll, FirstSeen: ev.Time, LastSeen: ev.Time,
					Sample: TuningSample{Time: ev.Time, TransactionID: ev.TransactionID, Path: truncate(ev.Path, 200), Variable: h.Variable, Data: truncate(h.Data, 120)},
				}
				if ri, ok := LookupRule(h.ID); ok {
					g.item.Category = ri.Category
				}
				g.target = target
				groups[key] = g
			}
			g.item.Count++
			if ev.WouldBlock || ev.Action == "blocked" {
				g.item.WouldBlock++
			}
			if ev.Time.Before(g.item.FirstSeen) {
				g.item.FirstSeen = ev.Time
			}
			if ev.Time.After(g.item.LastSeen) {
				g.item.LastSeen = ev.Time
				// the sample is the newest event
				g.item.Sample = TuningSample{Time: ev.Time, TransactionID: ev.TransactionID, Path: truncate(ev.Path, 200), Variable: h.Variable, Data: truncate(h.Data, 120)}
			}
			g.clients[ev.ClientIP] = true
			if !seenInEvent[key] && len(g.paths) < 64 {
				g.paths[ev.Path]++
			}
			seenInEvent[key] = true
			if len(g.shapes) < 32 {
				g.shapes[payloadShape(h.Data)] = true
			}
			if len(g.datas) < 64 {
				g.datas[h.Data] = true
			}
		}
	}
	rep := TuningReport{Hours: hours, Endpoint: endpoint, EventsScanned: len(evs), Items: []TuningItem{}}
	for _, g := range groups {
		it := g.item
		it.Clients = len(g.clients)
		it.PathCount = len(g.paths)
		for p := range g.paths {
			it.Paths = append(it.Paths, p)
		}
		sort.Strings(it.Paths)
		if len(it.Paths) > 5 {
			it.Paths = it.Paths[:5]
		}
		it.Shapes = len(g.shapes)
		g.finish(&it)
		rep.Items = append(rep.Items, it)
	}
	sort.Slice(rep.Items, func(i, j int) bool {
		a, b := rep.Items[i], rep.Items[j]
		if a.LooksLikeAttack != b.LooksLikeAttack {
			return !a.LooksLikeAttack // likely false positives first
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Key < b.Key
	})
	if len(rep.Items) > maxTuningItems {
		rep.Items = rep.Items[:maxTuningItems]
	}
	return rep
}

// pathScopable: cookies and headers travel with every request, so a path scope would only hide the problem
func pathScopable(coll string) bool {
	return !strings.HasPrefix(coll, "REQUEST_COOKIES") && !strings.HasPrefix(coll, "REQUEST_HEADERS")
}

// finish fills in the risk assessment and the suggestion
func (g *tuningGroup) finish(it *TuningItem) {
	sev := strings.ToLower(it.Severity)
	family := attackFamily(it.RuleID)
	serious := sev == "critical" || sev == "error" || sev == "emergency" || sev == "alert"

	var reasons []string
	attack := false
	if family != "" && (serious || family == "scanner / bot detection") {
		attack = true
		reasons = append(reasons, "rule family: "+family+" (rarely a false positive)")
	}
	if it.Clients >= 3 && it.Shapes >= 3 {
		attack = true
		reasons = append(reasons, itoa(it.Clients)+" distinct clients sent "+itoa(it.Shapes)+" structurally different payloads")
	}
	it.LooksLikeAttack = attack

	// the single path all hits share (only meaningful when the variable is path specific)
	path := ""
	if len(g.paths) == 1 {
		for p := range g.paths {
			path = p
		}
		if (TargetExclusion{RuleIDs: []string{"1"}, Target: "ARGS", Path: path}).validate() != nil {
			path = ""
		}
	}

	rid := []string{itoa(it.RuleID)}
	s := TuningSuggestion{RuleIDs: rid}
	switch {
	case g.target != "":
		s.Kind = "variable"
		s.Target = g.target
		if path != "" && pathScopable(it.Collection) {
			s.Path, s.Exact = path, true
		}
		s.Summary = "Rule " + rid[0] + " stops inspecting " + g.target
		if s.Path != "" {
			s.Summary += " on " + s.Path
		} else {
			s.Summary += " on every path"
		}
	case path != "":
		s.Kind = "path-rule"
		s.Path, s.Exact = path, true
		s.Summary = "Rule " + rid[0] + " is switched off on " + path + " (this variable cannot be excluded on its own)"
	default:
		s.Kind = "rule"
		s.Summary = "Rule " + rid[0] + " is switched off completely (no variable and no single path known)"
	}
	it.Suggestion = s

	switch {
	case attack:
		it.Risk = "high"
	case s.Kind == "rule":
		it.Risk = "high"
		reasons = append(reasons, "switches the whole rule off")
	case s.Kind == "path-rule":
		it.Risk = "medium"
		reasons = append(reasons, "no variable known: the rule is off for the whole request on that path")
	case serious && it.Clients <= 2 && it.Count <= 2:
		it.Risk = "medium"
		reasons = append(reasons, "only "+itoa(it.Count)+" hit(s): make sure it was your own traffic")
	default:
		it.Risk = "low"
	}
	if len(reasons) == 0 {
		if s.Kind == "variable" {
			reasons = append(reasons, "only this variable is excluded; the rule still inspects everything else")
		}
	}
	it.RiskNote = strings.Join(reasons, "; ")
	if attack {
		it.RiskNote = "Probably a real attack. " + it.RiskNote
	}
}

// TargetForVariable builds a safe exclusion target from a variable as stored in an event ("ARGS:q",
// "REQUEST_COOKIES:ph_phc_x_posthog"). Rotating names are collapsed to a regular expression only when collapse is
// set; otherwise the exact name is used. ok is false when the variable cannot be excluded on its own.
func TargetForVariable(variable string, collapse bool) (target string, ok bool) {
	coll, name, _ := SplitTarget(variable)
	coll = normCollection(coll)
	allowSel, known := targetCollections[coll]
	if !known {
		return "", false
	}
	if name == "" {
		return coll, true
	}
	if !allowSel {
		return "", false
	}
	lower := strings.ToLower(name)
	d, sel, collapsed := normalizeName(coll, lower)
	_ = d
	if collapsed && !collapse {
		// exact name, if it can be written literally
		if safeNamePattern.MatchString(lower) && len(lower) <= maxTargetNameLen {
			sel = lower
		}
	}
	t := coll + ":" + sel
	if ValidateTarget(t) != nil {
		return "", false
	}
	return t, true
}
