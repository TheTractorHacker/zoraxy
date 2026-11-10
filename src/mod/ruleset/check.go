package ruleset

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

/*
	check.go

	The two operations behind the rule editor that never change anything: Validate (parse errors, the
	normalised text and tree, the fields used, warnings) and Test (run a described request through the saved
	rules and report which matched and why, without performing a single action).
*/

// ValidateInput is a candidate expression (text or tree) and optionally an action
type ValidateInput struct {
	Expression string    `json:"expression"`
	Tree       *TreeNode `json:"tree"`
	Action     *Action   `json:"action"`
}

// ValidateResult is the outcome of Validate
type ValidateResult struct {
	OK          bool      `json:"ok"`
	Errors      []Error   `json:"errors,omitempty"`
	ActionError string    `json:"action_error,omitempty"`
	Text        string    `json:"text,omitempty"`
	Tree        *TreeNode `json:"tree,omitempty"`
	Fields      []string  `json:"fields,omitempty"`
	Lists       []string  `json:"lists,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
}

func (e *Engine) currentLists() map[string]*List {
	e.mu.Lock()
	defer e.mu.Unlock()
	return listMap(e.st.lists)
}

// parseCandidate parses text or tree against the current lists
func (e *Engine) parseCandidate(expr string, tree *TreeNode) (*Expr, *Error) {
	var x *Expr
	var err *Error
	switch {
	case expr != "" && tree != nil:
		return nil, &Error{Msg: "give either expression or tree, not both"}
	case expr != "":
		x, err = Parse(expr)
	case tree != nil:
		x, err = FromTree(tree)
	default:
		return nil, &Error{Msg: "give an expression or a tree"}
	}
	if err != nil {
		return nil, err
	}
	if err := x.Link(e.currentLists()); err != nil {
		return nil, err
	}
	return x, nil
}

// Validate checks a candidate rule without saving it
func (e *Engine) Validate(in ValidateInput) ValidateResult {
	var res ValidateResult
	x, err := e.parseCandidate(in.Expression, in.Tree)
	if err != nil {
		res.Errors = []Error{*err}
	} else {
		res.Text, res.Tree, res.Fields, res.Lists, res.Warnings = x.Text(), x.Tree(), x.Fields, x.Lists, x.Warnings
	}
	if in.Action != nil {
		if aerr := in.Action.Validate(); aerr != nil {
			res.ActionError = aerr.Error()
		}
	}
	res.OK = err == nil && res.ActionError == ""
	return res
}

// TestInput describes a request for the tester
type TestInput struct {
	Site       string            `json:"site"`
	Method     string            `json:"method"`
	URL        string            `json:"url"` // absolute (https://host/path?x=1) or a path (then Host comes from headers)
	Headers    map[string]string `json:"headers"`
	ClientIP   string            `json:"client_ip"`
	Country    string            `json:"country"` // optional override of the GeoIP lookup
	BodySize   *int64            `json:"body_size"`
	TLSVersion string            `json:"tls_version"` // TLSv1.2 / TLSv1.3 (only for https)
	SNI        string            `json:"sni"`
	Expression string            `json:"expression"` // optional: test this candidate alone instead of the saved rules
	Tree       *TreeNode         `json:"tree"`
}

// TestRule is the verdict for one rule
type TestRule struct {
	Scope     string       `json:"scope"` // global | site
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	DryRun    bool         `json:"dry_run"`
	Action    string       `json:"action"`
	Evaluated bool         `json:"evaluated"`
	Matched   bool         `json:"matched"`
	Note      string       `json:"note,omitempty"`
	Trace     []TraceEntry `json:"trace,omitempty"`
}

// TestResult is the outcome of Test. Nothing was performed.
type TestResult struct {
	Fields     map[string]string `json:"fields"`
	Rules      []TestRule        `json:"rules"`
	Decision   string            `json:"decision"` // none | allow | block | challenge | redirect | rate_limit
	DecidedBy  *TestRule         `json:"decided_by,omitempty"`
	Effect     string            `json:"effect"`
	Tags       []string          `json:"tags,omitempty"`
	Skips      []string          `json:"skips,omitempty"`
	ReqHeaders []string          `json:"request_header_changes,omitempty"`
	RespHeader []string          `json:"response_header_changes,omitempty"`
	Error      string            `json:"error,omitempty"`
}

func (e *Engine) buildTestRequest(in TestInput) (*http.Request, error) {
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = "GET"
	}
	if !validToken(method) {
		return nil, fmt.Errorf("invalid method")
	}
	raw := strings.TrimSpace(in.URL)
	if raw == "" {
		raw = "/"
	}
	if len(raw) > 8192 {
		return nil, fmt.Errorf("the url is too long")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, fmt.Errorf("the test URL is not valid. Use a path such as /login, or a full address such as https://example.com/login")
	}
	r := &http.Request{Method: method, URL: u, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}, RequestURI: u.RequestURI(), ContentLength: 0}
	if len(in.Headers) > 100 {
		return nil, fmt.Errorf("too many headers")
	}
	for k, v := range in.Headers {
		if !validToken(k) || len(v) > 8192 || strings.ContainsAny(v, "\r\n\x00") {
			return nil, fmt.Errorf("invalid header %q", k)
		}
		r.Header.Add(k, v)
	}
	r.Host = u.Host
	if r.Host == "" {
		r.Host = r.Header.Get("Host")
	}
	r.Header.Del("Host")
	if u.Scheme == "https" {
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: strings.ToLower(in.SNI)}
		switch in.TLSVersion {
		case "TLSv1.0":
			r.TLS.Version = tls.VersionTLS10
		case "TLSv1.1":
			r.TLS.Version = tls.VersionTLS11
		case "TLSv1.2":
			r.TLS.Version = tls.VersionTLS12
		}
		if r.TLS.ServerName == "" {
			h := r.Host
			if i := strings.LastIndexByte(h, ':'); i > 0 {
				h = h[:i]
			}
			r.TLS.ServerName = strings.ToLower(h)
		}
	}
	if in.BodySize != nil {
		r.ContentLength = *in.BodySize
	} else if cl := r.Header.Get("Content-Length"); cl != "" {
		fmt.Sscan(cl, &r.ContentLength)
	}
	return r, nil
}

func (e *Engine) testEnv(in TestInput, r *http.Request) *Env {
	env := &Env{R: r, ClientIP: strings.TrimSpace(in.ClientIP)}
	if c := strings.ToUpper(strings.TrimSpace(in.Country)); c != "" {
		env.Country = func(string) string { return c }
	} else {
		env.Country = e.Country
	}
	return env
}

func fieldSnapshot(env *Env) map[string]string {
	out := map[string]string{}
	for _, f := range fieldDefs {
		if f.Indexed {
			continue
		}
		switch f.Type {
		case TString:
			v, _ := env.strValue(f, "")
			out[f.Name] = clip(v)
		case TInt:
			out[f.Name] = fmt.Sprint(env.intValue(f))
		case TBool:
			out[f.Name] = fmt.Sprint(env.boolValue(f))
		case TIP:
			out[f.Name] = env.Addr().String()
		}
	}
	return out
}

// Test runs the described request through the saved rules of site (global first), or through one candidate
// expression, and reports the verdict of every rule it reached. Counters are not touched.
func (e *Engine) Test(in TestInput) TestResult {
	res := TestResult{Decision: "none", Effect: "The request would be forwarded unchanged."}
	r, err := e.buildTestRequest(in)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	env := e.testEnv(in, r)
	res.Fields = fieldSnapshot(env)

	if in.Expression != "" || in.Tree != nil {
		x, perr := e.parseCandidate(in.Expression, in.Tree)
		if perr != nil {
			res.Error = perr.Error()
			return res
		}
		b := &budget{left: e.ruleBudget}
		tr := &trace{}
		m := evalExpr(x.Root, env, b, tr)
		tt := TestRule{Scope: "draft", Name: "draft expression", Evaluated: true, Matched: m && !b.exceeded, Trace: tr.entries}
		if b.exceeded {
			tt.Note = "the evaluation budget was exhausted"
		}
		res.Rules = append(res.Rules, tt)
		return res
	}

	// rules that are not active are listed so the tester explains why they did not apply
	all := e.listAll(in.Site)
	reqLeft := e.reqBudget
	stopped := false
	tags := map[string]bool{}
	skips := map[string]bool{}
	for _, c := range all {
		tr := TestRule{Scope: "global", ID: c.ID, Name: c.Name, DryRun: c.DryRun, Action: c.Action.Describe()}
		if c.site != "" {
			tr.Scope = "site"
		}
		switch {
		case !c.Enabled:
			tr.Note = "disabled"
		case c.err != "":
			tr.Note = "inactive: " + c.err
		case stopped:
			tr.Note = "not reached"
		}
		if tr.Note != "" {
			res.Rules = append(res.Rules, tr)
			continue
		}
		b := &budget{left: e.ruleBudget}
		if b.left > reqLeft {
			b.left = reqLeft
		}
		start := b.left
		t := &trace{}
		m := evalExpr(c.expr.Root, env, b, t)
		reqLeft -= start - b.left
		tr.Evaluated, tr.Trace = true, t.entries
		if b.exceeded {
			tr.Note = "aborted: the evaluation budget was exhausted (the rule does not match)"
			res.Rules = append(res.Rules, tr)
			continue
		}
		tr.Matched = m
		if m {
			a := &c.Action
			switch {
			case c.DryRun:
				tr.Note = "log-only: counted, the action is not performed"
			case a.Type == ActAllow:
				stopped = true
				setDecision(&res, &tr, "allow", "The request is let through; no later rule runs.")
			case a.Type == ActBlock:
				stopped = true
				setDecision(&res, &tr, "block", fmt.Sprintf("The request would be answered with status %d.", a.StatusOr(403)))
			case a.Type == ActRedirect:
				stopped = true
				setDecision(&res, &tr, "redirect", fmt.Sprintf("The request would be redirected (%d) to %s", a.StatusOr(302), a.RedirectTarget(r)))
			case a.Type == ActChallenge:
				stopped = true
				setDecision(&res, &tr, "challenge", "The visitor would get the CAPTCHA unless they already hold a valid pass (without a CAPTCHA provider on the site the request is blocked).")
			case a.Type == ActRateLimit:
				tr.Note = fmt.Sprintf("limits the client to %d requests/second; blocks only when over the limit (the tester does not count requests)", a.Rate)
			case a.Type == ActSkip:
				_, rules := a.SkipMask()
				for _, n := range a.Skip {
					skips[n] = true
				}
				if rules {
					stopped = true
					tr.Note = "no later rule runs"
				}
			case a.Type == ActTag:
				tags[a.Tag] = true
			case a.Type == ActSetReqH:
				res.ReqHeaders = append(res.ReqHeaders, "set "+a.Name+": "+a.Value)
			case a.Type == ActDelReqH:
				res.ReqHeaders = append(res.ReqHeaders, "remove "+a.Name)
			case a.Type == ActSetRespH:
				res.RespHeader = append(res.RespHeader, "set "+a.Name+": "+a.Value)
			case a.Type == ActDelRespH:
				res.RespHeader = append(res.RespHeader, "remove "+a.Name)
			}
		}
		res.Rules = append(res.Rules, tr)
		if reqLeft <= 0 {
			stopped = true
		}
	}
	for t := range tags {
		res.Tags = append(res.Tags, t)
	}
	for t := range skips {
		res.Skips = append(res.Skips, t)
	}
	sort.Strings(res.Tags)
	sort.Strings(res.Skips)
	return res
}

func setDecision(res *TestResult, tr *TestRule, decision, effect string) {
	if res.Decision == "none" {
		res.Decision, res.Effect = decision, effect
		cp := *tr
		res.DecidedBy = &cp
	}
}

// listAll returns every rule in evaluation order (global, then the site's), including inactive ones
func (e *Engine) listAll(site string) []*compiledRule {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.snap.Load()
	var out []*compiledRule
	for _, r := range e.st.global {
		if c := s.byKey[statKey("", r.ID)]; c != nil {
			out = append(out, c)
		}
	}
	if site != "" {
		for _, r := range e.st.sites[site] {
			if c := s.byKey[statKey(site, r.ID)]; c != nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// Limiter is a tiny token bucket that bounds how often the validate / test endpoints run
type Limiter struct {
	rate, burst float64
	tokens      float64
	last        time.Time
	mu          chan struct{}
}

// NewLimiter allows rate operations per second with bursts up to burst
func NewLimiter(rate, burst float64) *Limiter {
	l := &Limiter{rate: rate, burst: burst, tokens: burst, last: time.Now(), mu: make(chan struct{}, 1)}
	return l
}

// Allow consumes a token
func (l *Limiter) Allow() bool {
	l.mu <- struct{}{}
	defer func() { <-l.mu }()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
