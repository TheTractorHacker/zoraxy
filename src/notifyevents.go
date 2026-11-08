package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/cluster"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/notify"
	"imuslab.com/zoraxy/mod/uptime"
)

/*
	notifyevents.go

	Wires the event sources of the notification centre (mod/notify) into the rest of
	Zoraxy: uptime up/down (debounced), WAF block spikes, fleet node offline, admin login
	failures / logins from a new address and "update available".
	Certificate events live in certhooks.go; auto-ban events are emitted by their own
	module with notify.Emit (see mod/notify/events_ext.go for the schema).
*/

const (
	knownIPTable   = "notifyknownip"
	maxKnownIPs    = 20
	fleetPollEvery = time.Minute
)

func initNotifyCenter() {
	if notifyManager == nil {
		return
	}
	notify.SetDefault(notifyManager)
	notifyManager.StartCenter()
	sysdb.NewTable(knownIPTable)

	dynamicproxy.BlockObserver = func(site string, _ string) { notifyManager.ObserveWAFBlock(site) }

	go watchFleetNodes()
}

// uptimeNotifyObserver is the uptime monitor's per-check callback
func uptimeNotifyObserver(t *uptime.Target, rec uptime.Record) {
	if notifyManager == nil || t == nil {
		return
	}
	notifyManager.ObserveUptime(t.ID, t.Name, rec.URL, rec.Online, rec.StatusCode)
}

// watchFleetNodes reports enrolled fleet nodes that go offline (and come back).
// The first scan only records the current state so a restart is quiet.
func watchFleetNodes() {
	prev := map[string]string{}
	first := true
	for {
		time.Sleep(fleetPollEvery)
		if clusterMgr == nil || notifyManager == nil {
			continue
		}
		for _, n := range clusterMgr.FleetNodeStates() {
			old, seen := prev[n.ID]
			prev[n.ID] = n.Status
			if first || !seen || old == n.Status {
				continue
			}
			if n.Status == cluster.NodeStatusOffline {
				notifyManager.Emit(notify.Event{Event: notify.EventNodeOffline, Source: "cluster", Subject: n.Name, Extra: map[string]string{"node_id": n.ID}})
			} else if old == cluster.NodeStatusOffline && n.Status == cluster.NodeStatusOnline {
				notifyManager.Emit(notify.Event{Event: notify.EventNodeOnline, Source: "cluster", Subject: n.Name, Extra: map[string]string{"node_id": n.ID}})
			}
		}
		first = false
	}
}

// capture tees (the first part of) a response body while passing everything through
type capture struct {
	http.ResponseWriter
	buf    bytes.Buffer
	status int
	limit  int
}

func (c *capture) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *capture) Write(p []byte) (int, error) {
	if c.buf.Len() < c.limit {
		room := c.limit - c.buf.Len()
		if len(p) < room {
			room = len(p)
		}
		c.buf.Write(p[:room])
	}
	return c.ResponseWriter.Write(p)
}

var knownIPMu sync.Mutex

// notifyLoginWrap reports failed admin logins and successful ones from an address
// that has not been seen for that user before (the first login only learns the address).
func notifyLoginWrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &capture{ResponseWriter: w, limit: 512}
		next(c, r)
		if notifyManager == nil || r.Method != http.MethodPost {
			return
		}
		user := strings.TrimSpace(r.PostFormValue("username"))
		ip := callerIP(r)
		body := strings.TrimSpace(c.buf.String())
		switch {
		case body == `"ok"`:
			noteLoginAddress(user, ip)
		case strings.Contains(body, `"error"`):
			notifyManager.Emit(notify.Event{Event: notify.EventAdminLoginFail, Source: "auth", Subject: user, Extra: map[string]string{"ip": ip}})
		}
	}
}

func noteLoginAddress(user, ip string) {
	if user == "" || ip == "" {
		return
	}
	if len(user) > 64 {
		user = user[:64]
	}
	key := "ips/" + strings.NewReplacer("/", "_", "\\", "_").Replace(user)
	knownIPMu.Lock()
	defer knownIPMu.Unlock()
	var ips []string
	if sysdb.KeyExists(knownIPTable, key) {
		sysdb.Read(knownIPTable, key, &ips)
	}
	for _, k := range ips {
		if k == ip {
			return
		}
	}
	learning := len(ips) == 0
	ips = append(ips, ip)
	if len(ips) > maxKnownIPs {
		ips = ips[len(ips)-maxKnownIPs:]
	}
	sysdb.Write(knownIPTable, key, ips)
	if !learning {
		notifyManager.Emit(notify.Event{Event: notify.EventAdminLoginNew, Source: "auth", Subject: user, Extra: map[string]string{"ip": ip}})
	}
}

// notifyUpdaterCheckWrap emits updater.available when an administrator's update check finds a
// release (Zoraxy never checks on its own, so this stays event driven). Each tag is announced once.
func notifyUpdaterCheckWrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &capture{ResponseWriter: w, limit: 256 << 10}
		next(c, r)
		if notifyManager == nil || (c.status != 0 && c.status != http.StatusOK) {
			return
		}
		var res struct {
			Result struct {
				Available bool   `json:"update_available"`
				Channel   string `json:"channel"`
				Current   struct {
					Version string `json:"version"`
				} `json:"current"`
				Latest *struct {
					Tag string `json:"tag"`
					URL string `json:"url"`
				} `json:"latest"`
			} `json:"result"`
		}
		if json.Unmarshal(c.buf.Bytes(), &res) != nil || !res.Result.Available || res.Result.Latest == nil || res.Result.Latest.Tag == "" {
			return
		}
		var last string
		if sysdb.KeyExists(knownIPTable, "lastUpdateTag") {
			sysdb.Read(knownIPTable, "lastUpdateTag", &last)
		}
		if last == res.Result.Latest.Tag {
			return
		}
		sysdb.Write(knownIPTable, "lastUpdateTag", res.Result.Latest.Tag)
		notifyManager.Emit(notify.Event{Event: notify.EventUpdateAvail, Source: "updater", Subject: res.Result.Latest.Tag,
			Extra: map[string]string{"current": res.Result.Current.Version, "channel": res.Result.Channel, "url": res.Result.Latest.URL}})
	}
}
