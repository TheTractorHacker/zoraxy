package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/captcha"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	"Why was this blocked?" (Statistics > Blocked)

	GET  /api/blocked/lookup?ref=ZX-XXXX-XXXX | ?ip=...   find blocked requests by the reference ID the visitor saw, or by address
	GET  /api/blocked/explain?seq=N | ?ref=               plain text, link to the rule and the fixes that can be offered
	POST /api/blocked/fix     {seq, fixId, previewId, allSites?}   apply one fix, answers {undoToken, ...}
	POST /api/blocked/undo    {undoToken}                          put the previous value back

	Only fixes with a clean existing write path are offered (see buildBlockFixes); every other
	reason gets the link to its rule only. Nothing here is automatic: a fix is previewed by explain,
	applied by one POST that must carry the previewId of that preview (so what is applied is exactly what was shown;
	a configuration that changed since is refused), scoped to the one site unless the fix is global by nature (then
	it needs allSites=true), and never widens access on its own. The undo token lives in memory for 24 hours.
	Applying and undoing are mutating admin API calls, so the change history records them
	("Fix applied via the Blocked drawer") and read-only accounts are refused twice (router and handler).
*/

const (
	blockUndoTTL = 24 * time.Hour
	blockUndoMax = 200
)

type fixChange struct {
	What   string `json:"what"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// fixOption is what the admin sees before applying: the preview line and the exact change
type fixOption struct {
	ID               string      `json:"id"`
	Label            string      `json:"label"`
	Preview          string      `json:"preview"`
	Scope            string      `json:"scope"` // site | access-rule | all
	Risk             string      `json:"risk"`  // low | medium | high
	Site             string      `json:"site,omitempty"`
	Changes          []fixChange `json:"changes"`
	RequiresAllSites bool        `json:"requiresAllSites,omitempty"` // global by nature: the request must say allSites=true
	PreviewID        string      `json:"previewId"`
}

type fixCandidate struct {
	fixOption
	apply func() (undo func() error, err error)
}

func (c *fixCandidate) seal() {
	c.PreviewID = ""
	js, _ := json.Marshal(c.fixOption)
	sum := sha256.Sum256(js)
	c.PreviewID = hex.EncodeToString(sum[:8])
}

type ruleLink struct {
	Tab   string `json:"tab"`
	Sec   string `json:"sec,omitempty"`
	Label string `json:"label"`
	Rule  string `json:"rule,omitempty"` // the machine key that fired
	Site  string `json:"site,omitempty"`
}

type blockExplanation struct {
	Seq         uint64              `json:"seq"`
	Ref         string              `json:"ref,omitempty"` // as the visitor saw it, ZX-XXXX-XXXX
	Entry       blocklog.Entry      `json:"entry"`
	Reason      blocklog.ReasonInfo `json:"reason"`
	PlainText   string              `json:"plainText"`
	Facts       map[string]string   `json:"facts"`
	RuleLink    ruleLink            `json:"ruleLink"`
	CanFix      bool                `json:"canFix"`
	Fixes       []fixOption         `json:"fixes"`
	NoFixReason string              `json:"noFixReason,omitempty"`
}

/* ---------- undo tokens (memory only) ---------- */

type blockUndoEntry struct {
	label   string
	site    string
	expires time.Time
	undo    func() error
}

var blockUndos = struct {
	sync.Mutex
	m map[string]*blockUndoEntry
}{m: map[string]*blockUndoEntry{}}

func blockUndoAdd(e *blockUndoEntry) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b[:])
	blockUndos.Lock()
	defer blockUndos.Unlock()
	now := time.Now()
	for k, v := range blockUndos.m {
		if now.After(v.expires) {
			delete(blockUndos.m, k)
		}
	}
	for len(blockUndos.m) >= blockUndoMax { //drop the oldest
		var oldest string
		for k, v := range blockUndos.m {
			if oldest == "" || v.expires.Before(blockUndos.m[oldest].expires) {
				oldest = k
			}
		}
		delete(blockUndos.m, oldest)
	}
	e.expires = now.Add(blockUndoTTL)
	blockUndos.m[tok] = e
	return tok
}

/* ---------- helpers ---------- */

func blockViewer(r *http.Request) bool {
	return authAgent != nil && authAgent.RequestRole(r) == auth.RoleViewer
}

// blockEntryFromRequest finds the entry named by seq or ref
func blockEntryFromRequest(w http.ResponseWriter, seqStr, ref string) (blocklog.Entry, bool) {
	var e blocklog.Entry
	var ok bool
	switch {
	case ref != "":
		e, ok = blockLog.GetByRef(ref)
	case seqStr != "":
		n, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			utils.SendErrorResponse(w, "invalid seq")
			return e, false
		}
		e, ok = blockLog.Get(n)
	default:
		utils.SendErrorResponse(w, "seq or ref required")
		return e, false
	}
	if !ok {
		utils.SendErrorResponse(w, "this entry is no longer in the blocked request log")
		return e, false
	}
	return e, true
}

// siteOf returns the live proxy rule a blocked request went through
func siteOf(e blocklog.Entry) *dynamicproxy.ProxyEndpoint {
	if dynamicProxyRouter == nil || e.Rule == "" {
		return nil
	}
	ep, err := dynamicProxyRouter.LoadProxy(e.Rule)
	if err != nil {
		return nil
	}
	return ep
}

// botDecisionOf returns the category or rule that fired for a bot block (from the rule key, or for
// entries written before it existed from the first word of the detail)
func botDecisionOf(e blocklog.Entry) string {
	if strings.HasPrefix(e.RuleID, "bot:") {
		return strings.TrimPrefix(e.RuleID, "bot:")
	}
	d := e.Detail
	if i := strings.IndexAny(d, " ("); i > 0 {
		d = d[:i]
	}
	if d == "challenge" || d == "challenge-unavailable" || d == "connection" {
		return ""
	}
	return d
}

func botCategory(id string) (botrules.Category, bool) {
	for _, c := range botrules.Categories() {
		if c.ID == id {
			return c, true
		}
	}
	return botrules.Category{}, false
}

func sitesUsingAccessRule(id string) int {
	n := 0
	if dynamicProxyRouter == nil {
		return 0
	}
	dynamicProxyRouter.ProxyEndpoints.Range(func(_, v interface{}) bool {
		if ep, ok := v.(*dynamicproxy.ProxyEndpoint); ok {
			rid := ep.AccessFilterUUID
			if rid == "" {
				rid = "default"
			}
			if rid == id {
				n++
			}
		}
		return true
	})
	return n
}

func joinFirst(items []string, n int) string {
	if len(items) > n {
		items = items[:n]
	}
	return strings.Join(items, ", ")
}

/* ---------- plain text ---------- */

func describeBlock(e blocklog.Entry) (string, map[string]string) {
	facts := map[string]string{"reason": e.Reason, "host": e.Host, "ip": e.IP, "ua": e.UA, "rule": e.RuleID}
	info := blocklog.ReasonInfo{}
	for _, ri := range blocklog.Reasons() {
		if ri.Key == e.Reason {
			info = ri
		}
	}
	ruleName := e.RuleID
	if i := strings.Index(ruleName, ":"); i >= 0 {
		ruleName = ruleName[i+1:]
	}
	switch e.Reason {
	case blocklog.ReasonBot:
		id := botDecisionOf(e)
		facts["category"] = id
		var text string
		switch {
		case id == "fake-bot":
			text = fmt.Sprintf("The User-Agent %s claims to be a trusted search bot, but the address did not pass the reverse DNS check.", quoteUA(e.UA))
		case id == "empty-ua":
			text = "The request has no User-Agent header and the bot rules refuse those."
		case strings.HasPrefix(id, "custom:"):
			text = fmt.Sprintf("The User-Agent %s matched the custom bot rule %q.", quoteUA(e.UA), strings.TrimPrefix(id, "custom:"))
		default:
			if cat, ok := botCategory(id); ok {
				facts["categoryTitle"] = cat.Title
				text = fmt.Sprintf("The User-Agent %s matched the bot category %s", quoteUA(e.UA), cat.Title)
				if id != "ai_crawler" {
					text += " (matches " + joinFirst(cat.Items, 5) + ")"
				}
				text += "."
			} else {
				text = fmt.Sprintf("The User-Agent %s matched a bot rule.", quoteUA(e.UA))
			}
		}
		switch {
		case strings.Contains(e.Detail, "no CAPTCHA"):
			facts["challengeUnavailable"] = "true"
			text += " Its action is Challenge, but this site has no CAPTCHA, so it was blocked."
		case strings.Contains(e.Detail, "(challenge)") || e.Detail == "challenge":
			text += " Its action is Challenge and the visitor was shown the CAPTCHA."
		case strings.Contains(e.Detail, "connection dropped"):
			text += " Its action is Drop, so the connection was closed without an answer."
		default:
			text += " Its action is Block."
		}
		return text, facts
	case blocklog.ReasonBlacklist:
		return fmt.Sprintf("The address %s, or its country, is on the blacklist of the access rule %q.", e.IP, ruleName), facts
	case blocklog.ReasonWhitelist:
		return fmt.Sprintf("The access rule %q only admits addresses on its allow list, and %s is not on it.", ruleName, e.IP), facts
	case blocklog.ReasonCountryChallenge:
		if strings.Contains(e.Detail, "no CAPTCHA") {
			facts["challengeUnavailable"] = "true"
			return fmt.Sprintf("The country of %s has to solve a CAPTCHA (access rule %q), but this site has no CAPTCHA, so the request was blocked.", e.IP, ruleName), facts
		}
		return fmt.Sprintf("The country of %s has to solve a CAPTCHA first (access rule %q).", e.IP, ruleName), facts
	case blocklog.ReasonWAF:
		d := e.Detail
		if i := strings.Index(d, " [tx "); i > 0 {
			d = d[:i]
		}
		return "A web application firewall rule matched this request: " + d + ".", facts
	case blocklog.ReasonRule:
		name := ruleName
		if name == "" {
			name = e.Detail
		}
		if strings.Contains(e.Detail, "no CAPTCHA") {
			facts["challengeUnavailable"] = "true"
			return fmt.Sprintf("The rule %q asks for a CAPTCHA, but this site has no CAPTCHA, so the request was blocked.", name), facts
		}
		return fmt.Sprintf("The rule %q of the rules engine blocked, limited or challenged this request.", name), facts
	}
	t := info.Why
	if e.Detail != "" {
		t += " (" + e.Detail + ")"
	}
	return t, facts
}

func quoteUA(ua string) string {
	if ua == "" {
		return "(empty)"
	}
	return ua
}

/* ---------- fixes ---------- */

// buildBlockFixes lists the fixes that have a clean write path for this entry, as they would apply
// right now. Each carries a PreviewID over its exact content.
func buildBlockFixes(e blocklog.Entry) ([]fixCandidate, string) {
	ep := siteOf(e)
	if ep == nil {
		return nil, "The site this request went to no longer exists, so there is nothing to change from here."
	}
	site := ep.RootOrMatchingDomain
	var out []fixCandidate
	ipOK := false
	if a, err := netip.ParseAddr(e.IP); err == nil {
		ipOK = true
		e.IP = a.String()
	}

	switch e.Reason {
	case blocklog.ReasonBot:
		out = append(out, botFixes(e, ep, site)...)
	case blocklog.ReasonWhitelist, blocklog.ReasonBlacklist:
		if ipOK {
			out = append(out, accessFixes(e, ep, site)...)
		}
	}
	// A path / address exemption of the CAPTCHA, where the block was a CAPTCHA that got served
	if (e.Reason == blocklog.ReasonCaptcha || e.Reason == blocklog.ReasonCountryChallenge || e.Reason == blocklog.ReasonBot) &&
		!strings.Contains(e.Detail, "no CAPTCHA") && ep.CaptchaConfig != nil && ep.CaptchaConfig.IsConfigured() {
		if e.Reason != blocklog.ReasonBot || strings.Contains(e.Detail, "challenge") {
			out = append(out, captchaFixes(e, ep, site, ipOK)...)
		}
	}
	for i := range out {
		out[i].seal()
	}
	if len(out) == 0 {
		return nil, "No change can be made from here for this kind of block. Use the link to open its rule."
	}
	return out, ""
}

func botFixes(e blocklog.Entry, ep *dynamicproxy.ProxyEndpoint, site string) []fixCandidate {
	var out []fixCandidate
	if ep.BotPolicy != "off" {
		prev := ep.BotPolicy
		out = append(out, fixCandidate{
			fixOption: fixOption{
				ID: "bot-site-off", Label: "Turn bot rules off for " + site, Scope: "site", Risk: "medium", Site: site,
				Preview: fmt.Sprintf("After this: no bot rule applies on %s, for any User-Agent. Other sites unchanged.", site),
				Changes: []fixChange{{What: "Bot rules policy of " + site, Before: botPolicyName(prev), After: botPolicyName("off")}},
			},
			apply: func() (func() error, error) {
				if err := applyNetworkingChange(site, func(x *dynamicproxy.ProxyEndpoint) error { x.BotPolicy = "off"; return nil }); err != nil {
					return nil, err
				}
				return func() error {
					cur, err := dynamicProxyRouter.LoadProxy(site)
					if err != nil {
						return errors.New("the site no longer exists")
					}
					if cur.BotPolicy != "off" {
						return errors.New("the bot rules setting of this site was changed after the fix; use the change history to restore an older version")
					}
					return applyNetworkingChange(site, func(x *dynamicproxy.ProxyEndpoint) error { x.BotPolicy = prev; return nil })
				}, nil
			},
		})
	}
	// The category action is global by nature (one list for every site): offered, but only with allSites=true
	id := botDecisionOf(e)
	if cat, ok := botCategory(id); ok {
		cfg := getBotEngine().Config()
		cc, has := cfg.Categories[id]
		if has && cc.Enabled && cc.Action != botrules.ActionLog {
			prev := cc
			out = append(out, fixCandidate{
				fixOption: fixOption{
					ID: "bot-category-log", Label: "Only log the category " + cat.Title + ", on all sites", Scope: "all", Risk: "high", RequiresAllSites: true,
					Preview: fmt.Sprintf("After this: requests of the category %s are logged but let through on EVERY site that uses the global bot rules.", cat.Title),
					Changes: []fixChange{{What: "Action of the bot category " + id + " (all sites)", Before: prev.Action, After: botrules.ActionLog}},
				},
				apply: func() (func() error, error) {
					if err := setBotCategory(id, botrules.CategoryCfg{Enabled: prev.Enabled, Action: botrules.ActionLog}, nil); err != nil {
						return nil, err
					}
					return func() error {
						want := botrules.CategoryCfg{Enabled: prev.Enabled, Action: botrules.ActionLog}
						return setBotCategory(id, prev, &want)
					}, nil
				},
			})
		}
	}
	return out
}

// setBotCategory writes one category of the bot rules; expect (if set) is the value it must have now
func setBotCategory(id string, v botrules.CategoryCfg, expect *botrules.CategoryCfg) error {
	eng := getBotEngine()
	cfg := eng.Config()
	cats := make(map[string]botrules.CategoryCfg, len(cfg.Categories)+1)
	for k, c := range cfg.Categories {
		cats[k] = c
	}
	if expect != nil && cats[id] != *expect {
		return errors.New("this bot category was changed after the fix; use the change history to restore an older version")
	}
	cats[id] = v
	cfg.Categories = cats
	return eng.SetConfig(cfg)
}

func botPolicyName(p string) string {
	switch p {
	case "on":
		return "on (always apply)"
	case "off":
		return "off for this site"
	}
	return "follow the global switch"
}

func accessFixes(e blocklog.Entry, ep *dynamicproxy.ProxyEndpoint, site string) []fixCandidate {
	if accessController == nil {
		return nil
	}
	rid := ep.AccessFilterUUID
	if rid == "" {
		rid = "default"
	}
	rule, err := accessController.GetAccessRuleByID(rid)
	if err != nil || rule == nil {
		return nil
	}
	// the rule that blocked must still be the one the site uses
	if k := dynamicproxy.AccessRuleKey(rule); e.RuleID != "" && k != e.RuleID {
		return nil
	}
	ip := e.IP
	n := sitesUsingAccessRule(rid)
	shared := fmt.Sprintf("the access rule %q (used by %d site%s)", rule.Name, n, map[bool]string{true: "", false: "s"}[n == 1])
	comment := "added from the Blocked requests page"
	switch e.Reason {
	case blocklog.ReasonWhitelist:
		if rule.WhiteListIP == nil {
			return nil
		}
		if _, has := (*rule.WhiteListIP)[ip]; has {
			return nil
		}
		return []fixCandidate{{
			fixOption: fixOption{
				ID: "access-ip-allow", Label: "Allow " + ip + " in " + rule.Name, Scope: "access-rule", Risk: "medium", Site: site,
				Preview: fmt.Sprintf("After this: %s is on the allow list of %s. Other addresses unchanged.", ip, shared),
				Changes: []fixChange{{What: "Allow list of " + rule.Name, Before: "(not listed)", After: ip}},
			},
			apply: func() (func() error, error) {
				rule.AddIPToWhiteList(ip, comment)
				return func() error {
					c, has := (*rule.WhiteListIP)[ip]
					if !has || c != comment {
						return errors.New("the entry was changed or removed after the fix")
					}
					rule.RemoveIPFromWhiteList(ip)
					return nil
				}, nil
			},
		}}
	case blocklog.ReasonBlacklist:
		if rule.BlackListIP == nil {
			return nil
		}
		prev, has := (*rule.BlackListIP)[ip]
		if !has { // blocked through a range or a country: not a single entry we can take out
			return nil
		}
		return []fixCandidate{{
			fixOption: fixOption{
				ID: "access-ip-unblock", Label: "Remove " + ip + " from the blacklist of " + rule.Name, Scope: "access-rule", Risk: "medium", Site: site,
				Preview: fmt.Sprintf("After this: %s is no longer on the blacklist of %s. Other addresses unchanged.", ip, shared),
				Changes: []fixChange{{What: "Blacklist of " + rule.Name, Before: ip, After: "(removed)"}},
			},
			apply: func() (func() error, error) {
				rule.RemoveIPFromBlackList(ip)
				return func() error {
					if _, still := (*rule.BlackListIP)[ip]; still {
						return errors.New("the address is on the blacklist again")
					}
					rule.AddIPToBlackList(ip, prev)
					return nil
				}, nil
			},
		}}
	}
	return nil
}

func captchaFixes(e blocklog.Entry, ep *dynamicproxy.ProxyEndpoint, site string, ipOK bool) []fixCandidate {
	var out []fixCandidate
	path := e.Path
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	mk := func(id, label, preview, what, value string, spec captchaExceptionSpec) fixCandidate {
		return fixCandidate{
			fixOption: fixOption{
				ID: id, Label: label, Scope: "site", Risk: "medium", Site: site, Preview: preview,
				Changes: []fixChange{{What: what, Before: "(no exception)", After: value}},
			},
			apply: func() (func() error, error) {
				if err := mutateCaptchaException(site, spec, addCaptchaExceptionRule); err != nil {
					return nil, err
				}
				return func() error { return mutateCaptchaException(site, spec, removeCaptchaExceptionRule) }, nil
			},
		}
	}
	if path != "" && path != "/" && len(path) <= 200 && strings.HasPrefix(path, "/") {
		spec := captchaExceptionSpec{Type: EXCEPTION_TYPE_PATH, Value: path, Mode: "exact"}
		if !hasCaptchaException(ep, spec) {
			out = append(out, mk("captcha-path-exempt", "Do not challenge "+path+" on "+site,
				fmt.Sprintf("After this: the path %s on %s is not challenged for anyone. Other paths and sites unchanged.", path, site),
				"CAPTCHA exceptions of "+site, "path "+path+" (exact)", spec))
		}
	}
	if ipOK {
		spec := captchaExceptionSpec{Type: EXCEPTION_TYPE_IP, Value: e.IP}
		if !hasCaptchaException(ep, spec) {
			out = append(out, mk("captcha-ip-exempt", "Do not challenge "+e.IP+" on "+site,
				fmt.Sprintf("After this: %s is not challenged on %s. Other addresses and sites unchanged.", e.IP, site),
				"CAPTCHA exceptions of "+site, "address "+e.IP, spec))
		}
	}
	return out
}

func hasCaptchaException(ep *dynamicproxy.ProxyEndpoint, spec captchaExceptionSpec) bool {
	t, v, mode, err := normalizeCaptchaException(spec)
	if err != nil || ep.CaptchaConfig == nil {
		return true // invalid: do not offer
	}
	for _, rule := range ep.CaptchaConfig.ExceptionRules {
		if captchaRuleMatches(rule, t, v, mode, false) {
			return true
		}
	}
	return false
}

// mutateCaptchaException is the body of /api/proxy/captcha/exceptions/add|delete for one site
func mutateCaptchaException(site string, spec captchaExceptionSpec, mutate func(cfg *captcha.Config, spec captchaExceptionSpec) error) error {
	ep, err := dynamicProxyRouter.LoadProxy(site)
	if err != nil {
		return err
	}
	if ep.CaptchaConfig == nil {
		return errors.New("CAPTCHA is not configured for this site")
	}
	if err := mutate(ep.CaptchaConfig, spec); err != nil {
		return err
	}
	ep.UpdateToRuntime()
	return SaveReverseProxyConfig(ep)
}

/* ---------- handlers ---------- */

type blockLookupOut struct {
	Kind     string           `json:"kind"` // ref | ip
	Query    string           `json:"query"`
	Found    bool             `json:"found"`
	Entries  []blocklog.Entry `json:"entries"`
	Total    int              `json:"total"`
	Kept     int              `json:"kept"`     // entries the log holds
	Capacity int              `json:"capacity"` // entries it can hold
	Enabled  bool             `json:"enabled"`  // false = logging is off
}

// HandleBlockedLookup finds blocked requests by reference ID (what the visitor was shown) or by IP
func HandleBlockedLookup(w http.ResponseWriter, r *http.Request) {
	if !blockLogReady(w) {
		return
	}
	q := r.URL.Query()
	out := blockLookupOut{Entries: []blocklog.Entry{}}
	text := strings.TrimSpace(q.Get("ref"))
	out.Kind = "ref"
	if text == "" {
		text = strings.TrimSpace(q.Get("ip"))
		out.Kind = "ip"
	}
	if text == "" {
		text = strings.TrimSpace(q.Get("q")) //a typed value: reference or address
		if blocklog.NormalizeRef(text) == "" {
			out.Kind = "ip"
		}
	}
	if text == "" || len(text) > 64 {
		utils.SendErrorResponse(w, "ref or ip required")
		return
	}
	out.Query = text
	if out.Kind == "ref" {
		if blocklog.NormalizeRef(text) == "" {
			utils.SendErrorResponse(w, "not a reference ID (expected ZX-XXXX-XXXX)")
			return
		}
		if e, ok := blockLog.GetByRef(text); ok {
			out.Entries, out.Total, out.Found = []blocklog.Entry{e}, 1, true
		}
	} else {
		a, err := netip.ParseAddr(text)
		if err != nil {
			utils.SendErrorResponse(w, "invalid ip")
			return
		}
		res := blockLog.List(blocklog.Filter{IP: a.String()}, 0, 50)
		out.Entries, out.Total, out.Found = res.Items, res.Total, res.Total > 0
	}
	s := blockLog.Summarize(blocklog.Filter{}, time.Now())
	out.Kept, out.Capacity, out.Enabled = s.Kept, s.Capacity, s.Enabled
	visitorJSON(w, out)
}

// HandleBlockedExplain says in plain words why a request was blocked and which fixes can be offered
func HandleBlockedExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !blockLogReady(w) {
		return
	}
	q := r.URL.Query()
	e, ok := blockEntryFromRequest(w, q.Get("seq"), q.Get("ref"))
	if !ok {
		return
	}
	text, facts := describeBlock(e)
	ex := blockExplanation{Seq: e.Seq, Ref: blocklog.FormatRef(e.Ref), Entry: e, PlainText: text, Facts: facts,
		Fixes: []fixOption{}, CanFix: !blockViewer(r)}
	for _, ri := range blocklog.Reasons() {
		if ri.Key == e.Reason {
			ex.Reason = ri
		}
	}
	ex.RuleLink = ruleLink{Tab: ex.Reason.Tab, Sec: ex.Reason.Sec, Label: ex.Reason.Where, Rule: e.RuleID, Site: e.Rule}
	if ex.CanFix {
		cands, why := buildBlockFixes(e)
		for _, c := range cands {
			ex.Fixes = append(ex.Fixes, c.fixOption)
		}
		ex.NoFixReason = why
	}
	visitorJSON(w, ex)
}

type blockFixRequest struct {
	Seq       uint64 `json:"seq"`
	Ref       string `json:"ref"`
	FixID     string `json:"fixId"`
	PreviewID string `json:"previewId"`
	AllSites  bool   `json:"allSites"`
	UndoToken string `json:"undoToken"`
}

func readBlockFixRequest(w http.ResponseWriter, r *http.Request) (blockFixRequest, bool) {
	var req blockFixRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
			utils.SendErrorResponse(w, "invalid JSON body")
			return req, false
		}
		return req, true
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
	if err := r.ParseForm(); err != nil {
		utils.SendErrorResponse(w, "invalid request")
		return req, false
	}
	req.Seq, _ = strconv.ParseUint(r.PostFormValue("seq"), 10, 64)
	req.Ref, req.FixID, req.PreviewID = r.PostFormValue("ref"), r.PostFormValue("fixId"), r.PostFormValue("previewId")
	req.AllSites = r.PostFormValue("allSites") == "true"
	req.UndoToken = r.PostFormValue("undoToken")
	return req, true
}

func blockAdminOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if blockViewer(r) {
		http.Error(w, "403 - Read-only account (viewer role)", http.StatusForbidden)
		return false
	}
	return true
}

// blockFixMu serialises applying and undoing fixes (they read and write several stores)
var blockFixMu sync.Mutex

// HandleBlockedFix applies one fix. The request must carry the previewId of the preview the admin saw.
func HandleBlockedFix(w http.ResponseWriter, r *http.Request) {
	if !blockAdminOnly(w, r) || !blockLogReady(w) {
		return
	}
	req, ok := readBlockFixRequest(w, r)
	if !ok {
		return
	}
	seqStr := ""
	if req.Seq != 0 {
		seqStr = strconv.FormatUint(req.Seq, 10)
	}
	e, ok := blockEntryFromRequest(w, seqStr, req.Ref)
	if !ok {
		return
	}
	if req.FixID == "" {
		utils.SendErrorResponse(w, "fixId required")
		return
	}
	if req.PreviewID == "" {
		utils.SendErrorResponse(w, "preview first: the request must carry the previewId of the preview that was shown")
		return
	}
	blockFixMu.Lock()
	defer blockFixMu.Unlock()
	cands, _ := buildBlockFixes(e)
	var c *fixCandidate
	for i := range cands {
		if cands[i].ID == req.FixID {
			c = &cands[i]
		}
	}
	if c == nil {
		utils.SendErrorResponse(w, "this fix is not available (any more) for this entry")
		return
	}
	if c.PreviewID != req.PreviewID {
		utils.SendErrorResponse(w, "the configuration changed since the preview; open the entry again")
		return
	}
	if c.RequiresAllSites && !req.AllSites {
		utils.SendErrorResponse(w, "this fix changes every site; confirm with allSites=true")
		return
	}
	undo, err := c.apply()
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	tok := blockUndoAdd(&blockUndoEntry{label: c.Label, site: c.Site, undo: undo})
	if tok == "" {
		undo() //cannot offer an undo: do not leave a change that cannot be reverted from here
		utils.SendErrorResponse(w, "unable to create the undo token")
		return
	}
	visitorJSON(w, map[string]interface{}{
		"ok": true, "undoToken": tok, "label": c.Label, "site": c.Site, "scope": c.Scope,
		"changes": c.Changes, "undoExpires": time.Now().Add(blockUndoTTL).Unix(),
		"history": "Recorded in the change history as: via Blocked drawer",
	})
}

// HandleBlockedUndo puts back what a fix changed
func HandleBlockedUndo(w http.ResponseWriter, r *http.Request) {
	if !blockAdminOnly(w, r) {
		return
	}
	req, ok := readBlockFixRequest(w, r)
	if !ok {
		return
	}
	blockFixMu.Lock()
	defer blockFixMu.Unlock()
	blockUndos.Lock()
	ent, found := blockUndos.m[req.UndoToken]
	if found && time.Now().After(ent.expires) {
		delete(blockUndos.m, req.UndoToken)
		found = false
	}
	blockUndos.Unlock()
	if !found || req.UndoToken == "" {
		utils.SendErrorResponse(w, "this undo is unknown or expired (undo links last 24 hours and are lost on restart); use the change history")
		return
	}
	if err := ent.undo(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	blockUndos.Lock()
	delete(blockUndos.m, req.UndoToken)
	blockUndos.Unlock()
	visitorJSON(w, map[string]interface{}{"ok": true, "label": ent.label, "site": ent.site})
}

// registerBlockedFixAPIs is called by RegisterBlockedAPIs
func registerBlockedFixAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/blocked/lookup", HandleBlockedLookup)
	authRouter.HandleFunc("/api/blocked/explain", HandleBlockedExplain)
	authRouter.HandleFunc("/api/blocked/fix", HandleBlockedFix)
	authRouter.HandleFunc("/api/blocked/undo", HandleBlockedUndo)
}
