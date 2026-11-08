package notify

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

/*
Event catalogue (schema) of the notification centre.

Every event is a notify.Event (see event.go). Names are "<area>.<what>". The fields
used per event are listed below; anything else goes into Event.Extra (string values only).
Sources in other packages only need:

	notify.Emit(notify.Event{Event: notify.EventAutoBan, Source: "security",
		Subject: "203.0.113.7", Extra: map[string]string{"reason": "...", "duration": "1h"}})

Emit is safe to call before the notification centre is initialised (it is a no-op) and
never blocks.

Event             Severity  Source     Subject            Extra keys
uptime.down       critical  uptime     target name        url, status_code, failures
uptime.up         info      uptime     target name        url, downtime
certificate.issued          info     certificate  store name   (see event.go)
certificate.renewal_failed  critical certificate  store name   (see event.go)
certificate.expiring        warning  certificate  store name   (see event.go)
waf.spike         warning   waf        rule / host        blocks, window_seconds
security.autoban  warning   security   banned address     reason, duration, rule
cluster.node_offline  critical  cluster  node name         node_id, last_seen
cluster.node_online   info      cluster  node name         node_id
admin.login_failed    warning   auth     user name         ip
admin.login_new_ip    warning   auth     user name         ip
updater.available     info      updater  version tag       current, channel, url
*/
const (
	EventUptimeDown     = "uptime.down"
	EventUptimeUp       = "uptime.up"
	EventWAFSpike       = "waf.spike"
	EventAutoBan        = "security.autoban"
	EventNodeOffline    = "cluster.node_offline"
	EventNodeOnline     = "cluster.node_online"
	EventAdminLoginFail = "admin.login_failed"
	EventAdminLoginNew  = "admin.login_new_ip"
	EventUpdateAvail    = "updater.available"
	EventDigest         = "notify.digest"
)

// Severity levels, ordered
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevCritical = "critical"
)

// EventInfo describes one event type for the UI
type EventInfo struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// Catalog lists every event the notification centre knows (certificate events included)
var Catalog = []EventInfo{
	{EventUptimeDown, SevCritical, "Upstream is down"},
	{EventUptimeUp, SevInfo, "Upstream recovered"},
	{EventCertIssued, SevInfo, "Certificate issued / renewed"},
	{EventCertRenewFailed, SevCritical, "Certificate renewal failed"},
	{EventCertExpiring, SevWarning, "Certificate expires soon"},
	{EventWAFSpike, SevWarning, "WAF block spike"},
	{EventAutoBan, SevWarning, "Address banned automatically"},
	{EventNodeOffline, SevCritical, "Fleet node offline"},
	{EventNodeOnline, SevInfo, "Fleet node back online"},
	{EventAdminLoginFail, SevWarning, "Admin login failed"},
	{EventAdminLoginNew, SevWarning, "Admin login from a new address"},
	{EventUpdateAvail, SevInfo, "Update available"},
}

// AllEvents are the event names that can be subscribed to
func AllEvents() []string {
	out := make([]string, 0, len(Catalog))
	for _, c := range Catalog {
		out = append(out, c.Name)
	}
	return out
}

// IsKnownEvent reports whether name can be used in a subscription
func IsKnownEvent(name string) bool {
	for _, c := range Catalog {
		if c.Name == name {
			return true
		}
	}
	return false
}

// SeverityOf returns the severity of an event type (info for unknown ones)
func SeverityOf(name string) string {
	for _, c := range Catalog {
		if c.Name == name {
			return c.Severity
		}
	}
	return SevInfo
}

func sevRank(s string) int {
	switch s {
	case SevCritical:
		return 2
	case SevWarning:
		return 1
	}
	return 0
}

// ---- process wide entry point ----

var defaultManager atomic.Pointer[Manager]

// SetDefault installs the manager that the package level Emit uses
func SetDefault(m *Manager) { defaultManager.Store(m) }

// Emit sends an event through the default manager; a no-op until SetDefault was called.
// This is the stable entry point for event sources in other packages.
func Emit(ev Event) {
	if m := defaultManager.Load(); m != nil {
		m.Emit(ev)
	}
}

// ---- text rendering ----

// cleanText removes control characters and bounds the length of attacker influenced strings
func cleanText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
		if n >= max {
			b.WriteString("...")
			break
		}
	}
	return b.String()
}

// Describe renders a human readable title and body for an event. It never includes secrets:
// events carry none, and channel configuration is not part of it.
func Describe(ev Event) (title string, lines []string) {
	subj := cleanText(ev.Subject, 120)
	x := func(k string) string { return cleanText(ev.Extra[k], 200) }
	switch ev.Event {
	case EventUptimeDown:
		title = "DOWN: " + subj
		lines = append(lines, "Upstream "+subj+" failed "+x("failures")+" consecutive health checks.")
		if x("url") != "" {
			lines = append(lines, "URL: "+x("url"))
		}
		if x("status_code") != "" {
			lines = append(lines, "Last status code: "+x("status_code"))
		}
	case EventUptimeUp:
		title = "RECOVERED: " + subj
		lines = append(lines, "Upstream "+subj+" is reachable again.")
		if x("downtime") != "" {
			lines = append(lines, "Downtime: "+x("downtime"))
		}
	case EventCertIssued:
		title = "Certificate issued: " + subj
	case EventCertRenewFailed:
		title = "Certificate renewal FAILED: " + subj
	case EventCertExpiring:
		title = "Certificate expiring: " + subj
		if ev.DaysLeft != nil {
			lines = append(lines, fmt.Sprintf("%d day(s) left", *ev.DaysLeft))
		}
	case EventWAFSpike:
		title = "WAF block spike: " + subj
		lines = append(lines, x("blocks")+" blocked requests in "+x("window_seconds")+" seconds.")
	case EventAutoBan:
		title = "Address banned: " + subj
		if x("reason") != "" {
			lines = append(lines, "Reason: "+x("reason"))
		}
		if x("duration") != "" {
			lines = append(lines, "Duration: "+x("duration"))
		}
	case EventNodeOffline:
		title = "Fleet node offline: " + subj
		if x("last_seen") != "" {
			lines = append(lines, "Last seen: "+x("last_seen"))
		}
	case EventNodeOnline:
		title = "Fleet node online: " + subj
	case EventAdminLoginFail:
		title = "Admin login failed: " + subj
		lines = append(lines, "From address: "+x("ip"))
	case EventAdminLoginNew:
		title = "Admin login from a new address: " + subj
		lines = append(lines, "From address: "+x("ip"))
	case EventUpdateAvail:
		title = "Zoraxy update available: " + subj
		if x("current") != "" {
			lines = append(lines, "Running: "+x("current"))
		}
		if x("url") != "" {
			lines = append(lines, x("url"))
		}
	case EventDigest:
		title = "Zoraxy digest: " + x("count") + " event(s)"
		for _, l := range strings.Split(ev.Extra["lines"], "\n") {
			if l != "" {
				lines = append(lines, cleanText(l, 200))
			}
		}
	case EventTest:
		title = "Zoraxy test notification"
		lines = append(lines, "If you can read this, the channel works.")
	default:
		title = cleanText(ev.Event, 80)
		if subj != "" {
			title += ": " + subj
		}
	}
	if ev.Error != "" {
		lines = append(lines, "Error: "+cleanText(ev.Error, 300))
	}
	if len(ev.Domains) > 0 && ev.Event != EventDigest {
		lines = append(lines, "Domains: "+cleanText(strings.Join(ev.Domains, ", "), 300))
	}
	return title, lines
}

// plain joins title and lines for channels with a single text field
func plain(ev Event) string {
	t, l := Describe(ev)
	if len(l) == 0 {
		return t
	}
	return t + "\n" + strings.Join(l, "\n")
}

func nowOr(f func() time.Time) time.Time {
	if f != nil {
		return f()
	}
	return time.Now()
}
