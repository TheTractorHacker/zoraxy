package posture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

/*
	Actions ("Apply recommended protection")

	An action is a plan: a list of Changes (setting key, current value, new value). Preview shows the plan,
	Apply runs the very same plan function again on fresh state and executes exactly those changes through the
	Backend, which calls the internal functions the normal admin APIs use. Because both go through Plan,
	a preview cannot disagree with what is applied; a hash of the plan guards against the state changing in between.

	Safety rules every action must keep (see DEVELOPMENT.md):
	  1. Idempotent: planning on an already fixed system gives no changes.
	  2. Nothing that could block real traffic is ever turned on in blocking mode: WAF = detection-only, never block.
	  3. Preconditions are checked in Plan; a failing precondition is a Refusal, never a partial apply.
	  4. Settings an administrator set on purpose (a rule's WAF explicitly off, a stored threshold) are not overwritten.
	  5. Every apply is audited and reported change by change; no action runs without the caller naming it.
*/

// Change is one setting that an action changes
type Change struct {
	Key    string `json:"key"`    // setting key understood by the Backend, e.g. "waf.enabled"
	Label  string `json:"label"`  // human readable, e.g. "WAF master switch"
	Target string `json:"target"` // what it applies to ("central WAF policy", a proxy rule, ...)
	From   string `json:"from"`
	To     string `json:"to"`
	Prev   string `json:"prev"` // raw previous value used to undo; defaults to From
}

// Plan is what an action would do right now
type Plan struct {
	Changes []Change
	Refusal string   // non-empty: preconditions are not met, nothing may be changed
	Notes   []string // facts that explain the plan (rules left alone, ...)
	// Title and Description replace the action's static texts when what the action does right now
	// differs from what its name says (e.g. the WAF is already on, only its baseline values are missing)
	Title, Description string
}

// Backend reads and writes settings; implemented by the host with the same internal functions the admin APIs use.
type Backend interface {
	// Get returns the current value of a setting key
	Get(key string) (string, bool)
	// Set changes a setting key. It must validate and persist exactly like the admin API for that setting.
	Set(key, value string) error
	// Managed returns a reason when local changes are not allowed (cluster follower, fleet node), else ""
	Managed() string
}

// Action is one entry of the action registry
type Action struct {
	ID          string
	Title       string
	Description string   // one or two sentences
	Covers      []string // check ids that this action improves
	// Preselected actions are ticked in "Apply recommended protection". Only actions that cannot block traffic and can be undone.
	Preselected bool
	// MayBlock marks actions that can reject real clients later (e.g. auto-ban). Never preselected.
	MayBlock bool
	// Sticky marks changes that clients remember after the setting is switched off again (HSTS). No undo is offered.
	Sticky bool
	Plan   func(f *Facts, b Backend) Plan `json:"-"`
}

// Reversible: the engine can restore the previous values
func (a Action) Reversible() bool { return !a.Sticky }

// ActionRegistry holds the actions
type ActionRegistry struct{ list []Action }

// NewActionRegistry returns an empty registry
func NewActionRegistry() *ActionRegistry { return &ActionRegistry{} }

// Register adds an action; ids are unique
func (r *ActionRegistry) Register(a Action) error {
	if a.ID == "" || a.Title == "" || a.Plan == nil {
		return fmt.Errorf("posture: invalid action %q", a.ID)
	}
	if a.Preselected && (a.MayBlock || a.Sticky) {
		return fmt.Errorf("posture: action %s may not be preselected (it may block traffic or is sticky)", a.ID)
	}
	for _, x := range r.list {
		if x.ID == a.ID {
			return fmt.Errorf("posture: duplicate action id %s", a.ID)
		}
	}
	r.list = append(r.list, a)
	return nil
}

// MustRegister is Register for init functions
func (r *ActionRegistry) MustRegister(a Action) {
	if err := r.Register(a); err != nil {
		panic(err)
	}
}

// All returns the actions in registration order
func (r *ActionRegistry) All() []Action { return append([]Action(nil), r.list...) }

// Get finds an action
func (r *ActionRegistry) Get(id string) (Action, bool) {
	for _, a := range r.list {
		if a.ID == id {
			return a, true
		}
	}
	return Action{}, false
}

// Hash identifies a plan so apply can verify that it still is what the user previewed
func (p Plan) Hash() string {
	b, _ := json.Marshal(struct {
		C []Change
		R string
	}{p.Changes, p.Refusal})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// ActionInfo is the API description of an action together with its current availability
type ActionInfo struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Covers      []string `json:"covers"`
	Preselected bool     `json:"preselected"`
	MayBlock    bool     `json:"mayBlock"`
	Sticky      bool     `json:"sticky"`
	Reversible  bool     `json:"reversible"`
	State       string   `json:"state"`            // available | done | refused
	Reason      string   `json:"reason,omitempty"` // why refused / what is done
	Changes     int      `json:"changes"`
	Undoable    bool     `json:"undoable"` // a previous apply can be undone
}

// Preview is the answer of the preview API for one action
type Preview struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Hash        string   `json:"hash"`
	Changes     []Change `json:"changes"`
	Refusal     string   `json:"refusal,omitempty"`
	Notes       []string `json:"notes,omitempty"`
	NoOp        bool     `json:"noop"`
	MayBlock    bool     `json:"mayBlock"`
	Sticky      bool     `json:"sticky"`
	Reversible  bool     `json:"reversible"`
	Description string   `json:"description"`
}

// Result of applying (or undoing) one action
type ActionResult struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Status     string   `json:"status"` // applied | nothing-to-do | refused | failed | changed | undone
	Applied    []Change `json:"applied,omitempty"`
	Error      string   `json:"error,omitempty"`
	RolledBack bool     `json:"rolledBack,omitempty"`
	Skipped    []string `json:"skipped,omitempty"`
}

func describe(changes []Change) string {
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		parts = append(parts, fmt.Sprintf("%s [%s]: %s -> %s", c.Label, c.Target, c.From, c.To))
	}
	s := strings.Join(parts, "; ")
	if len(s) > 600 {
		s = s[:600] + "..."
	}
	return s
}

// ---- built-in actions ----

// DefaultActions is the action registry used by Zoraxy
var DefaultActions = NewActionRegistry()

func init() {
	for _, a := range builtinActions() {
		DefaultActions.MustRegister(a)
	}
}

func get(b Backend, key string) string {
	v, _ := b.Get(key)
	return v
}

func builtinActions() []Action {
	return []Action{
		{
			ID: "waf.baseline", Title: "Turn on the WAF in detection-only mode",
			Description: "Enables the central WAF policy at paranoia level 1 for every proxy rule that follows it. Detection-only logs what it would block and never rejects a request.",
			Covers:      []string{"waf.active"}, Preselected: true,
			Plan: func(f *Facts, b Backend) Plan {
				var p Plan
				if f.WAF == nil {
					p.Refusal = "the central WAF policy could not be read"
					return p
				}
				target := "central WAF policy"
				mode := get(b, "waf.mode")
				newMode := mode
				if mode == "" || mode == "off" {
					newMode = "detection_only"
				}
				enabled := get(b, "waf.enabled") == "on"
				if enabled {
					p.Title = "Fill in the WAF baseline values"
					p.Description = "The WAF is already on and its mode (" + modeLabel(mode) + ") is not changed. This only sets the paranoia level and the anomaly threshold that are still at their defaults, so the rules have something to score against."
				}
				if !enabled && mode == "block" {
					// enabling the master switch with a stored block mode would start rejecting requests
					newMode = "detection_only"
					p.Notes = append(p.Notes, "The stored default mode is Block. It is set to detection-only so that switching the WAF on cannot reject any request; switch to Block on the WAF page when you are ready.")
				}
				if !enabled {
					p.Changes = append(p.Changes, Change{"waf.enabled", "WAF master switch", target, "off", "on", ""})
				}
				if newMode != mode {
					p.Changes = append(p.Changes, Change{"waf.mode", "Default mode", target, orDash(mode), newMode, mode})
				}
				if get(b, "waf.paranoia") == "0" || get(b, "waf.paranoia") == "" {
					p.Changes = append(p.Changes, Change{"waf.paranoia", "Paranoia level", target, "0 (default)", "1", "0"})
				}
				if get(b, "waf.threshold") == "0" || get(b, "waf.threshold") == "" {
					p.Changes = append(p.Changes, Change{"waf.threshold", "Inbound anomaly threshold", target, "0 (default)", "5", "0"})
				}
				if f.Proxy != nil {
					off := 0
					for _, r := range f.Proxy.HostRules() {
						if r.WAFOrigin == "off" {
							off++
						}
					}
					if off > 0 {
						p.Notes = append(p.Notes, fmt.Sprintf("%d proxy %s set to \"off\" on purpose stay off.", off, plural(off, "rule is", "rules are")))
					}
				}
				return p
			},
		},
		{
			ID: "waf.cookies", Title: "Skip analytics cookie values in the WAF",
			Description: "Stops the WAF from inspecting the long encoded values of analytics cookies (Google Analytics, PostHog), a common source of false positives. Other cookies are still inspected.",
			Covers:      []string{"waf.analytics_cookies"}, Preselected: true,
			Plan: func(f *Facts, b Backend) Plan {
				var p Plan
				if f.WAF == nil {
					p.Refusal = "the central WAF policy could not be read"
					return p
				}
				if get(b, "waf.cookies") != "on" {
					p.Changes = append(p.Changes, Change{"waf.cookies", "Ignore analytics cookie values", "central WAF policy", "off", "on", ""})
				}
				return p
			},
		},
		{
			ID: "autoban.enable", Title: "Turn on auto-ban for attack signatures",
			Description: "Bans an address for a while (one hour, doubling for repeat offenders) after it repeatedly triggers WAF blocks, the exploit filter, bot rules or failed admin logins, using the thresholds shown on the Auto-ban tab. The noisier detectors (401, 403, 404, 429 responses) stay off. Private, loopback and trusted proxy addresses are never banned.",
			Covers:      []string{"abuse.autoban"}, MayBlock: true,
			Plan: func(f *Facts, b Backend) Plan {
				var p Plan
				if f.Abuse == nil {
					p.Refusal = "the auto-ban configuration could not be read"
					return p
				}
				if get(b, "autoban.enabled") != "on" {
					p.Changes = append(p.Changes, Change{"autoban.enabled", "Automatic banning", "auto-ban", "off", "on", ""})
				}
				for _, k := range []string{"waf_block", "exploit_block", "bot_block", "login_fail"} {
					key := "autoban.detector." + k
					if get(b, key) != "on" {
						p.Changes = append(p.Changes, Change{key, "Detector: " + detectorLabel(k), "auto-ban", "off", "on", ""})
					}
				}
				return p
			},
		},
		{
			ID: "https.redirect", Title: "Redirect plain HTTP to HTTPS",
			Description: "Sends visitors who open http:// to the encrypted site. Offered only when every proxy rule has a valid, trusted certificate, so no site changes from working to a certificate warning.",
			Covers:      []string{"tls.https_redirect"}, Preselected: true,
			Plan: func(f *Facts, b Backend) Plan {
				var p Plan
				if f.Proxy == nil || f.Certs == nil {
					p.Refusal = "the proxy settings or certificates could not be read"
					return p
				}
				if get(b, "https.redirect") == "on" {
					return p
				}
				if !f.Proxy.UseTLS {
					p.Refusal = "the proxy does not serve TLS"
					return p
				}
				if !f.Proxy.ListenOnPort80 {
					p.Refusal = "no plain HTTP listener is running, there is nothing to redirect"
					return p
				}
				if f.Proxy.Port == 80 {
					p.Refusal = "the proxy listens on port 80 itself"
					return p
				}
				if f.Certs.Skipped > 0 {
					p.Refusal = fmt.Sprintf("%d wildcard or IP host %s cannot be verified to have a certificate", f.Certs.Skipped, plural(f.Certs.Skipped, "name", "names"))
					return p
				}
				var missing []string
				for _, h := range f.Certs.Hosts {
					if h.State != "ok" {
						missing = append(missing, h.Host+" ("+h.State+")")
					}
				}
				if len(missing) > 0 {
					p.Refusal = "these host names have no valid, trusted certificate: " + listNames(missing, 6)
					return p
				}
				if len(f.Certs.Hosts) == 0 {
					p.Refusal = "there are no host names with a certificate to redirect"
					return p
				}
				p.Changes = append(p.Changes, Change{"https.redirect", "Redirect HTTP to HTTPS", "proxy listener", "off", "on", ""})
				return p
			},
		},
		{
			ID: "uptime.enable", Title: "Watch every proxy rule with the uptime monitor",
			Description: "Turns the uptime monitor on for the proxy rules that have it off. It sends a small request to each upstream every few minutes and feeds the notification centre.",
			Covers:      []string{"ops.uptime"}, Preselected: true,
			Plan: func(f *Facts, b Backend) Plan {
				var p Plan
				if f.Proxy == nil {
					p.Refusal = "the proxy rules could not be read"
					return p
				}
				for _, r := range f.Proxy.HostRules() {
					if get(b, "uptime."+r.Name) == "off" {
						p.Changes = append(p.Changes, Change{"uptime." + r.Name, "Uptime monitor", r.Name, "off", "on", ""})
					}
				}
				return p
			},
		},
		{
			ID: "hsts.enable", Title: "Turn on HSTS where it is safe",
			Description: "Sends a one-year Strict-Transport-Security header for the proxy rules that have a valid, trusted certificate with at least 30 days left. Browsers remember it, so it cannot be fully undone: for a year they refuse plain HTTP to those sites.",
			Covers:      []string{"tls.hsts"}, Sticky: true,
			Plan: func(f *Facts, b Backend) Plan {
				var p Plan
				if f.Proxy == nil || f.Certs == nil {
					p.Refusal = "the proxy settings or certificates could not be read"
					return p
				}
				if !f.Proxy.UseTLS {
					p.Refusal = "the proxy does not serve TLS"
					return p
				}
				certs := map[string]HostCert{}
				for _, h := range f.Certs.Hosts {
					certs[strings.ToLower(h.Host)] = h
				}
				var skipped []string
				for _, r := range f.Proxy.HostRules() {
					cur, known := b.Get("hsts." + r.Name)
					if known && cur != "0" {
						continue // already on
					}
					if !known {
						skipped = append(skipped, r.Name+": its header settings could not be read")
						continue
					}
					c, ok := certs[strings.ToLower(r.Name)]
					switch {
					case r.Wildcard:
						skipped = append(skipped, r.Name+": wildcard host name")
					case !ok:
						skipped = append(skipped, r.Name+": certificate not checked")
					case c.State != "ok":
						skipped = append(skipped, r.Name+": "+certStateText(c.State))
					case c.DaysLeft < 30:
						skipped = append(skipped, fmt.Sprintf("%s: certificate has only %d days left", r.Name, c.DaysLeft))
					default:
						p.Changes = append(p.Changes, Change{"hsts." + r.Name, "HSTS max-age (seconds)", r.Name, "0 (off)", "31536000", "0"})
					}
				}
				sort.Strings(skipped)
				for _, s := range skipped {
					p.Notes = append(p.Notes, "Skipped "+s)
				}
				if len(p.Changes) == 0 && len(skipped) > 0 {
					p.Refusal = "no proxy rule qualifies (see the notes)"
				}
				return p
			},
		},
	}
}

// detectorLabel is the name the Auto-ban tab shows for a detector id
func detectorLabel(id string) string {
	switch id {
	case "waf_block":
		return "WAF blocks"
	case "exploit_block":
		return "exploit filter hits"
	case "bot_block":
		return "bot rule hits"
	case "login_fail":
		return "failed admin logins"
	}
	return id
}

// certStateText says in words what a certificate check state means for a host name
func certStateText(state string) string {
	switch state {
	case "missing":
		return "no certificate found"
	case "fallback":
		return "no certificate matches, the built-in localhost certificate would be served"
	case "mismatch":
		return "the certificate that would be served does not cover this name"
	case "expired":
		return "the certificate has expired"
	case "selfsigned":
		return "the certificate is self-signed"
	}
	return "certificate state: " + state
}

func modeLabel(mode string) string {
	switch mode {
	case "block":
		return "Block"
	case "detection_only":
		return "detection-only"
	case "", "off":
		return "off"
	}
	return mode
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
