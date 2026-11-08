package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type captured struct {
	path, query string
	header      http.Header
	body        string
}

// channelReceiver is a TLS receiver capturing requests; loopback needs AllowPrivate on the channel.
func channelReceiver(t *testing.T, status int) (*httptest.Server, *[]captured, *sync.Mutex) {
	var mu sync.Mutex
	var got []captured
	srv, _ := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, captured{r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)})
		mu.Unlock()
		w.WriteHeader(status)
	})
	return srv, &got, &mu
}

func sinkFor(t *testing.T, srv *httptest.Server, c ChannelConfig) *ChannelSink {
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig
	s := &ChannelSink{Cfg: c, Attempts: 1, tlsConfig: pool}
	s.Cfg.Enabled = true
	return s
}

func TestChannelPayloadsPerType(t *testing.T) {
	ev := Event{Event: EventUptimeDown, Time: time.Now(), Source: "uptime", Subject: "api.example <@everyone>", Extra: map[string]string{"failures": "3", "url": "https://api.example/"}}
	srv, got, mu := channelReceiver(t, 200)
	base := srv.URL
	cases := []struct {
		cfg   ChannelConfig
		apiBs string
		check func(c captured) string
	}{
		{ChannelConfig{Type: ChanDiscord, Settings: map[string]string{"url": base + "/api/webhooks/1/secrettoken"}}, "", func(c captured) string {
			if !strings.Contains(c.body, `"allowed_mentions":{"parse":[]}`) || !strings.Contains(c.body, "DOWN") {
				return "discord body " + c.body
			}
			return ""
		}},
		{ChannelConfig{Type: ChanSlack, Settings: map[string]string{"url": base + "/services/T/B/X"}}, "", func(c captured) string {
			var j map[string]string
			json.Unmarshal([]byte(c.body), &j)
			if !strings.Contains(j["text"], "&lt;@everyone&gt;") {
				return "slack not escaped: " + c.body
			}
			return ""
		}},
		{ChannelConfig{Type: ChanTelegram, Settings: map[string]string{"token": "123:ABCtoken", "chat_id": "42"}}, base, func(c captured) string {
			if c.path != "/bot123:ABCtoken/sendMessage" || !strings.Contains(c.body, `"chat_id":"42"`) {
				return "telegram " + c.path + c.body
			}
			return ""
		}},
		{ChannelConfig{Type: ChanNtfy, Settings: map[string]string{"server": base, "topic": "alerts", "token": "tk_x"}}, "", func(c captured) string {
			if c.path != "/alerts" || c.header.Get("Authorization") != "Bearer tk_x" || c.header.Get("Priority") != "5" || !strings.HasPrefix(c.header.Get("Title"), "DOWN") {
				return "ntfy " + c.path + " " + c.header.Get("Priority")
			}
			return ""
		}},
		{ChannelConfig{Type: ChanGotify, Settings: map[string]string{"server": base, "token": "gtok"}}, "", func(c captured) string {
			if c.path != "/message" || c.header.Get("X-Gotify-Key") != "gtok" || !strings.Contains(c.body, `"priority":8`) {
				return "gotify " + c.path + c.body
			}
			return ""
		}},
		{ChannelConfig{Type: ChanPushover, Settings: map[string]string{"token": "ptok", "user": "uk"}}, base, func(c captured) string {
			f, _ := url.ParseQuery(c.body)
			if c.path != "/1/messages.json" || f.Get("token") != "ptok" || f.Get("user") != "uk" || f.Get("priority") != "1" {
				return "pushover " + c.body
			}
			return ""
		}},
	}
	for _, tc := range cases {
		mu.Lock()
		*got = nil
		mu.Unlock()
		tc.cfg.Name, tc.cfg.AllowPrivate = tc.cfg.Type, true
		s := sinkFor(t, srv, tc.cfg)
		s.apiBase = tc.apiBs
		if err := s.Deliver(context.Background(), ev); err != nil {
			t.Errorf("%s: %v", tc.cfg.Type, err)
			continue
		}
		mu.Lock()
		if len(*got) != 1 {
			t.Errorf("%s: %d requests", tc.cfg.Type, len(*got))
			mu.Unlock()
			continue
		}
		if msg := tc.check((*got)[0]); msg != "" {
			t.Errorf("%s: %s", tc.cfg.Type, msg)
		}
		mu.Unlock()
	}
}

func TestChannelSSRFRefusalTable(t *testing.T) {
	bad := []ChannelConfig{
		{Type: ChanDiscord, Settings: map[string]string{"url": "https://127.0.0.1/hook"}},
		{Type: ChanDiscord, Settings: map[string]string{"url": "http://discord.example/hook"}},
		{Type: ChanSlack, Settings: map[string]string{"url": "https://169.254.169.254/latest"}},
		{Type: ChanSlack, Settings: map[string]string{"url": "https://[::1]/x"}},
		{Type: ChanNtfy, Settings: map[string]string{"server": "https://10.0.0.5", "topic": "t"}},
		{Type: ChanNtfy, Settings: map[string]string{"server": "https://localhost", "topic": "t"}},
		{Type: ChanGotify, Settings: map[string]string{"server": "https://192.168.1.2", "token": "x"}},
		{Type: ChanGotify, Settings: map[string]string{"server": "https://user:pw@gotify.example", "token": "x"}},
		{Type: ChanSMTP, Settings: map[string]string{"host": "127.0.0.1", "port": "25", "from": "a@b.example", "to": "c@d.example"}},
		{Type: ChanSMTP, Settings: map[string]string{"host": "localhost", "port": "25", "from": "a@b.example", "to": "c@d.example"}},
	}
	for i, c := range bad {
		c.Name = "x"
		if err := c.Validate(); err == nil {
			t.Errorf("case %d (%s) accepted: %v", i, c.Type, c.Settings)
		}
	}
	// the explicit toggle permits them
	ok := ChannelConfig{Name: "lan", Type: ChanGotify, AllowPrivate: true, Settings: map[string]string{"server": "http://192.168.1.2:8080", "token": "x"}}
	if err := ok.Validate(); err != nil {
		t.Errorf("allowPrivate must permit LAN gotify: %v", err)
	}
	// connect-time guard even if validation were bypassed (DNS rebinding)
	s := &ChannelSink{Cfg: ChannelConfig{Name: "n", Type: ChanDiscord, Enabled: true, Settings: map[string]string{"url": "https://localhost.invalid/x"}}, Attempts: 1}
	s.dialer = nil
	srv, _, _ := channelReceiver(t, 200)
	s.Cfg.Settings["url"] = srv.URL + "/x" // loopback literal, AllowPrivate false
	if err := s.Deliver(context.Background(), Event{Event: EventTest}); err == nil {
		t.Error("loopback must be refused without the toggle")
	}
	// SMTP DNS check
	sm := &ChannelSink{Cfg: ChannelConfig{Name: "s", Type: ChanSMTP, Enabled: true, Settings: map[string]string{"host": "mail.example", "port": "25", "from": "a@b.example", "to": "c@d.example"}},
		Attempts: 1, lookupHost: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.1.1.1")}, nil },
		smtpSend: func(ChannelConfig, string, string, string) error { t.Error("must not send"); return nil }}
	if err := sm.Deliver(context.Background(), Event{Event: EventTest}); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("smtp host resolving to private address must be refused: %v", err)
	}
}

func TestChannelSecretsMaskedAndScrubbed(t *testing.T) {
	m := newTestManager(t)
	id, err := m.SaveChannel(ChannelConfig{Name: "tg", Type: ChanTelegram, Enabled: true, Settings: map[string]string{"token": "999:SUPERSECRET", "chat_id": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(m.CenterView())
	if strings.Contains(string(js), "SUPERSECRET") || !strings.Contains(string(js), SecretMask) {
		t.Fatalf("secret leaked in view: %s", js)
	}
	// saving the masked view back keeps the stored secret
	v := m.CenterView()["channels"].([]ChannelConfig)[0]
	v.Name = "tg2"
	if _, err := m.SaveChannel(v); err != nil {
		t.Fatal(err)
	}
	if m.cfg.Channels[0].Settings["token"] != "999:SUPERSECRET" || m.cfg.Channels[0].Name != "tg2" {
		t.Fatal("masked secret overwrote the stored one")
	}
	// the type cannot change; new channel with a mask is not a secret
	v.Type = ChanSlack
	if _, err := m.SaveChannel(v); err == nil {
		t.Fatal("type change accepted")
	}
	// error text is scrubbed
	s := &ChannelSink{Cfg: m.cfg.Channels[0], Attempts: 1}
	s.Cfg.Enabled = true
	s.dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}
	s.apiBase = "https://telegram.test"
	err = s.Deliver(context.Background(), Event{Event: EventTest})
	if err == nil || strings.Contains(err.Error(), "SUPERSECRET") {
		t.Fatalf("error must not contain the token: %v", err)
	}
	// config file is 0600 and delivery log holds no secret
	st, _ := os.Stat(m.path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %o", st.Mode().Perm())
	}
	m.TestChannel(id)
	for _, r := range m.center.log.snapshot() {
		if strings.Contains(r.Error, "SUPERSECRET") {
			t.Fatal("secret in delivery log")
		}
	}
}

func TestSMTPChannel(t *testing.T) {
	var sent []string
	var mu sync.Mutex
	c := ChannelConfig{Name: "mail", Type: ChanSMTP, Enabled: true, AllowPrivate: true,
		Settings: map[string]string{"host": "mail.example", "port": "587", "from": "zoraxy@example.com", "to": "a@example.com, b@example.com", "password": "s3cretpw"}}
	s := &ChannelSink{Cfg: c, Attempts: 1, smtpSend: func(cc ChannelConfig, to, subj, body string) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, to+"|"+subj+"|"+body)
		return nil
	}}
	ev := Event{Event: EventUptimeDown, Subject: "evil\r\nBcc: x@y.z <script>", Extra: map[string]string{"failures": "3"}}
	if err := s.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || strings.ContainsAny(sent[0], "\r") || strings.Contains(strings.SplitN(sent[0], "|", 3)[1], "\n") || strings.Contains(strings.SplitN(sent[0], "|", 3)[2], "<script>") {
		t.Fatalf("smtp: %q", sent)
	}
	// failure is retried then reported without the password
	calls := 0
	s.smtpSend = func(cc ChannelConfig, to, subj, body string) error {
		calls++
		return errors.New("auth failed for s3cretpw")
	}
	s.Attempts, s.Backoff = 2, time.Millisecond
	err := s.Deliver(context.Background(), ev)
	if err == nil || strings.Contains(err.Error(), "s3cretpw") || calls < 4 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestChannelRetryAndPermanentFailure(t *testing.T) {
	var n int32
	srv, _ := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	})
	s := sinkFor(t, srv, ChannelConfig{Name: "d", Type: ChanDiscord, AllowPrivate: true, Settings: map[string]string{"url": srv.URL + "/h"}})
	s.Attempts, s.Backoff = 4, time.Millisecond
	if err := s.Deliver(context.Background(), Event{Event: EventTest}); err != nil || n != 3 {
		t.Fatalf("err=%v calls=%d", err, n)
	}
	atomic.StoreInt32(&n, 0)
	srv2, _ := newReceiver(t, func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&n, 1); w.WriteHeader(400) })
	s2 := sinkFor(t, srv2, ChannelConfig{Name: "d", Type: ChanDiscord, AllowPrivate: true, Settings: map[string]string{"url": srv2.URL + "/h"}})
	s2.Attempts, s2.Backoff = 4, time.Millisecond
	if err := s2.Deliver(context.Background(), Event{Event: EventTest}); err == nil || n != 1 {
		t.Fatalf("400 must not retry: err=%v calls=%d", err, n)
	}
}

func TestSubscriptionsAndSeverity(t *testing.T) {
	s := &ChannelSink{Cfg: ChannelConfig{Enabled: true, Events: []string{EventUptimeDown}}}
	if !s.Wants(EventUptimeDown) || s.Wants(EventUptimeUp) {
		t.Fatal("subscription filter")
	}
	s = &ChannelSink{Cfg: ChannelConfig{Enabled: true, MinSeverity: SevWarning}}
	if s.Wants(EventUptimeUp) || !s.Wants(EventWAFSpike) || !s.Wants(EventUptimeDown) {
		t.Fatal("min severity")
	}
	s.Cfg.Enabled = false
	if s.Wants(EventUptimeDown) {
		t.Fatal("disabled channel")
	}
}

func TestFlapSuppressionStateMachine(t *testing.T) {
	f := NewFlapTracker(func() int { return 3 }, func() int { return 2 })
	t0 := time.Unix(1000, 0)
	step := func(ok bool, sec int) *Transition { return f.Observe("a", ok, t0.Add(time.Duration(sec)*time.Second)) }
	if step(false, 0) != nil || step(false, 1) != nil {
		t.Fatal("down before threshold")
	}
	if step(true, 2) != nil { // blip resets the failure streak
		t.Fatal("transition on blip")
	}
	if step(false, 3) != nil || step(false, 4) != nil {
		t.Fatal("streak must restart after a success")
	}
	tr := step(false, 5)
	if tr == nil || !tr.Down || tr.Failures != 3 {
		t.Fatalf("expected down, got %+v", tr)
	}
	if step(false, 6) != nil || step(false, 7) != nil {
		t.Fatal("duplicate down")
	}
	if step(true, 8) != nil {
		t.Fatal("recovery needs 2 successes")
	}
	if step(false, 9) != nil || step(true, 10) != nil {
		t.Fatal("failure during recovery resets the success streak without events")
	}
	tr = step(true, 65)
	if tr == nil || tr.Down || tr.Downtime != 60*time.Second {
		t.Fatalf("expected recovery after 60s, got %+v", tr)
	}
	if step(true, 66) != nil {
		t.Fatal("duplicate recovery")
	}
	// independent targets
	if f.Observe("b", false, t0) != nil {
		t.Fatal("targets share state")
	}
	// threshold 1 = immediate
	f1 := NewFlapTracker(func() int { return 1 }, func() int { return 1 })
	if tr := f1.Observe("x", false, t0); tr == nil || !tr.Down {
		t.Fatal("threshold 1")
	}
}

func TestSpikeDetector(t *testing.T) {
	d := NewSpikeDetector(func() (int, time.Duration, time.Duration) { return 5, 10 * time.Second, time.Minute })
	t0 := time.Unix(0, 0)
	raised := 0
	for i := 0; i < 5; i++ {
		if d.Hit("s", t0.Add(time.Duration(i)*time.Second)) > 0 {
			raised++
		}
	}
	if raised != 1 {
		t.Fatalf("raised=%d", raised)
	}
	for i := 5; i < 20; i++ { // inside the cooldown: no second spike
		if d.Hit("s", t0.Add(time.Duration(i)*time.Second)) > 0 {
			t.Fatal("spike during cooldown")
		}
	}
	// slow trickle never spikes
	for i := 0; i < 30; i++ {
		if d.Hit("slow", t0.Add(time.Duration(i)*5*time.Second)) > 0 {
			t.Fatal("trickle raised spike")
		}
	}
	// disabled
	d0 := NewSpikeDetector(func() (int, time.Duration, time.Duration) { return 0, 0, 0 })
	if d0.Hit("x", t0) != 0 {
		t.Fatal("disabled")
	}
	// bounded keys
	for i := 0; i < 2000; i++ {
		d.Hit("k"+itoa(i), t0)
	}
	if len(d.hits) > d.limit {
		t.Fatalf("keys=%d", len(d.hits))
	}
}

func TestGateDedupeRateQuietDigest(t *testing.T) {
	g := newGate()
	r := DefaultRules()
	r.DedupeSeconds, r.RatePerHour = 60, 3
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)
	ev := func(sub string) Event { return Event{Event: EventWAFSpike, Subject: sub} }
	if g.check(r, "c1", ev("a"), t0) != DecSend || g.check(r, "c1", ev("a"), t0.Add(30*time.Second)) != DecDedupe {
		t.Fatal("dedupe")
	}
	if g.check(r, "c2", ev("a"), t0.Add(30*time.Second)) != DecSend {
		t.Fatal("dedupe is per channel")
	}
	if g.check(r, "c1", ev("a"), t0.Add(61*time.Second)) != DecSend {
		t.Fatal("window expired")
	}
	if g.check(r, "c1", ev("b"), t0.Add(62*time.Second)) != DecSend {
		t.Fatal("third send")
	}
	if g.check(r, "c1", ev("c"), t0.Add(63*time.Second)) != DecRate {
		t.Fatal("rate limit")
	}
	if g.check(r, "c1", ev("d"), t0.Add(61*time.Minute)) != DecSend {
		t.Fatal("rate window slides")
	}
	if g.check(r, "c1", Event{Event: EventTest}, t0) != DecSend {
		t.Fatal("test events bypass")
	}

	// quiet hours across midnight, critical passes
	q := DefaultRules()
	q.Quiet = QuietHours{Enabled: true, Start: "22:00", End: "07:00", CriticalPass: true}
	night := time.Date(2026, 1, 1, 23, 30, 0, 0, time.Local)
	morning := time.Date(2026, 1, 2, 7, 1, 0, 0, time.Local)
	g2 := newGate()
	if g2.check(q, "c", Event{Event: EventWAFSpike, Subject: "x"}, night) != DecHeld {
		t.Fatal("hold at night")
	}
	if g2.check(q, "c", Event{Event: EventUptimeDown, Subject: "x"}, night) != DecSend {
		t.Fatal("critical passes quiet hours")
	}
	if g2.takeHeld(q, "c", night) != nil {
		t.Fatal("no flush during quiet hours")
	}
	d := g2.takeHeld(q, "c", morning)
	if d == nil || d.Event != EventDigest || d.Extra["count"] != "1" {
		t.Fatalf("digest after quiet: %+v", d)
	}
	if g2.takeHeld(q, "c", morning) != nil {
		t.Fatal("buffer emptied")
	}
	if !q.Quiet.InQuiet(time.Date(2026, 1, 1, 3, 0, 0, 0, time.Local)) || q.Quiet.InQuiet(time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)) {
		t.Fatal("InQuiet")
	}

	// digest mode: non-critical held, flushed after the interval
	dg := DefaultRules()
	dg.Digest = Digest{Enabled: true, IntervalMinutes: 10}
	g3 := newGate()
	g3.check(dg, "c", Event{Event: EventWAFSpike, Subject: "1"}, t0)
	g3.check(dg, "c", Event{Event: EventUpdateAvail, Subject: "2"}, t0.Add(time.Minute))
	if g3.takeHeld(dg, "c", t0.Add(5*time.Minute)) != nil {
		t.Fatal("too early")
	}
	if e := g3.takeHeld(dg, "c", t0.Add(11*time.Minute)); e == nil || e.Extra["count"] != "2" {
		t.Fatalf("digest: %+v", e)
	}
	// buffer is bounded
	g4 := newGate()
	for i := 0; i < 500; i++ {
		g4.check(dg, "c", Event{Event: EventWAFSpike, Subject: itoa(i)}, t0)
	}
	if len(g4.buf["c"]) > maxHeldPerChannel || g4.dropped["c"] == 0 {
		t.Fatal("held buffer unbounded")
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(filepath.Join(t.TempDir(), "notify.json"), false, nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManagerEndToEndGatingAndDeliveryLog(t *testing.T) {
	m := newTestManager(t)
	srv, got, mu := channelReceiver(t, 200)
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)
	var cmu sync.Mutex
	m.SetClock(func() time.Time { cmu.Lock(); defer cmu.Unlock(); return clock })
	m.SaveRules(Rules{DedupeSeconds: 600, RatePerHour: 100, FailThreshold: 2, RecoverThreshold: 1, WAFSpikeBlocks: 3, WAFSpikeWindow: 60, WAFSpikeCooldown: 600})
	// patch the sink factory: channels point at the TLS test server via AllowPrivate; trust its cert through the transport seam
	id, err := m.SaveChannel(ChannelConfig{Name: "n1", Type: ChanNtfy, Enabled: true, AllowPrivate: true, Events: []string{EventUptimeDown, EventUptimeUp, EventWAFSpike},
		Settings: map[string]string{"server": srv.URL, "topic": "t"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = id
	testTLS = srv.Client().Transport.(*http.Transport).TLSClientConfig
	defer func() { testTLS = nil }()

	m.ObserveUptime("t1", "api", "https://api", false, 500)
	m.Emit(Event{Event: EventCertIssued}) // not subscribed
	m.ObserveUptime("t1", "api", "https://api", false, 500)
	m.ObserveUptime("t1", "api", "https://api", false, 500) // already down
	m.Dispatcher.Wait()
	mu.Lock()
	n := len(*got)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("expected one DOWN notification, got %d", n)
	}
	m.ObserveUptime("t1", "api", "https://api", true, 200)
	m.Dispatcher.Wait()
	mu.Lock()
	n = len(*got)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("expected recovery notification, got %d", n)
	}
	for i := 0; i < 3; i++ {
		m.ObserveWAFBlock("shop.example")
	}
	m.Dispatcher.Wait()
	// dedupe: same spike event again
	m.Emit(Event{Event: EventWAFSpike, Subject: "shop.example"})
	m.Dispatcher.Wait()
	statuses := map[string]int{}
	for _, r := range m.center.log.snapshot() {
		statuses[r.Status]++
	}
	if statuses["sent"] != 3 || statuses["suppressed:dedupe"] != 1 {
		t.Fatalf("delivery log: %v", statuses)
	}
	if snap := m.center.log.snapshot(); snap[0].Channel != "n1" {
		t.Fatalf("newest first: %+v", snap[0])
	}
}

func TestTemplateRendering(t *testing.T) {
	ev := Event{Event: EventUptimeDown, Time: time.Unix(0, 0), Subject: `a"b`, Extra: map[string]string{"failures": "3"}}
	out, err := RenderTemplate(`{"text": {{json .Text}}, "who": {{json .Subject}}, "n": {{json .Extra.failures}}}`, ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if json.Unmarshal(out, &m) != nil || m["who"] != `a"b` || m["n"] != "3" {
		t.Fatalf("%s", out)
	}
	for _, bad := range []string{`{"x": {{.Subject}}}`, `{{`, `{"x": {{.Nope.deeper.thing}}}`, strings.Repeat("x", maxTemplateBytes+1)} {
		if _, err := RenderTemplate(bad, ev); err == nil {
			t.Errorf("accepted bad template %q", bad)
		}
	}
	if err := ValidateTemplate(`{"a":{{json .Event}}}`); err != nil {
		t.Fatal(err)
	}
	// webhook honours the template
	srv, got, mu := channelReceiver(t, 200)
	ws := &WebhookSink{Cfg: WebhookConfig{Name: "w", URL: srv.URL, Enabled: true, Template: `{"msg": {{json .Title}}}`}, AllowPrivate: true, Attempts: 1,
		tlsConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig}
	if err := ws.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 || !strings.Contains((*got)[0].body, `"msg"`) {
		t.Fatalf("template body: %+v", *got)
	}
}

func TestCenterAPIAndPersistence(t *testing.T) {
	m := newTestManager(t)
	post := func(body string) string {
		rec := httptest.NewRecorder()
		m.HandleCenter(rec, httptest.NewRequest("POST", "/api/notify/center", strings.NewReader(body)))
		return rec.Body.String()
	}
	out := post(`{"op":"saveChannel","channel":{"name":"disc","type":"discord","enabled":true,"settings":{"url":"https://discord.com/api/webhooks/1/tok"}}}`)
	if !strings.Contains(out, `"id"`) {
		t.Fatalf("save: %s", out)
	}
	if out := post(`{"op":"saveChannel","channel":{"name":"bad","type":"discord","settings":{"url":"https://127.0.0.1/x"}}}`); !strings.Contains(out, "error") {
		t.Fatalf("SSRF target accepted: %s", out)
	}
	if out := post(`{"op":"saveRules","rules":{"quiet":{"enabled":true,"start":"25:00","end":"07:00"}}}`); !strings.Contains(out, "error") {
		t.Fatalf("bad quiet hours accepted: %s", out)
	}
	if out := post(`{"op":"saveRules","rules":{"dedupeSeconds":120,"ratePerHour":10,"failThreshold":4}}`); strings.Contains(out, "error") {
		t.Fatalf("rules: %s", out)
	}
	// reload from disk
	m2, err := NewManager(m.path, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.cfg.Channels) != 1 || m2.Rules().FailThreshold != 4 || m2.Rules().DedupeSeconds != 120 {
		t.Fatalf("not persisted: %+v", m2.cfg)
	}
	rec := httptest.NewRecorder()
	m2.HandleCenter(rec, httptest.NewRequest("GET", "/api/notify/center", nil))
	if strings.Contains(rec.Body.String(), "webhooks/1/tok") {
		t.Fatalf("secret in GET: %s", rec.Body.String())
	}
	id := m2.cfg.Channels[0].ID
	if out := post(`{"op":"deleteChannel","id":"` + id + `"}`); strings.Contains(out, "error") {
		t.Fatalf("delete: %s", out)
	}
	if out := post(`{"op":"nope"}`); !strings.Contains(out, "error") {
		t.Fatal("unknown op")
	}
}

func TestDefaultEmitIsSafeAndConcurrent(t *testing.T) {
	SetDefault(nil)
	Emit(Event{Event: EventAutoBan, Subject: "1.2.3.4"}) // no manager: no-op
	m := newTestManager(t)
	SetDefault(m)
	defer SetDefault(nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				Emit(Event{Event: EventAutoBan, Subject: itoa(j)})
				m.ObserveUptime(itoa(i), "t", "u", j%3 != 0, 200)
				m.ObserveWAFBlock("s")
				m.center.log.snapshot()
				if j == 10 {
					m.SaveChannel(ChannelConfig{Name: "c" + itoa(i), Type: ChanNtfy, Settings: map[string]string{"server": "https://ntfy.sh", "topic": "t" + itoa(i)}})
				}
			}
		}(i)
	}
	wg.Wait()
	m.Dispatcher.Wait()
}

func TestDescribeNeverLeaksControlChars(t *testing.T) {
	title, lines := Describe(Event{Event: EventAdminLoginFail, Subject: "adm\x00in\n@everyone", Extra: map[string]string{"ip": "1.2.3.4\r\nX: y"}})
	all := title + strings.Join(lines, "|")
	if strings.ContainsAny(all, "\x00\r\n") && strings.Contains(title, "\n") {
		t.Fatalf("control chars: %q", all)
	}
	for _, c := range Catalog {
		if tt, _ := Describe(Event{Event: c.Name, Subject: "s"}); tt == "" {
			t.Errorf("no title for %s", c.Name)
		}
		if !IsKnownEvent(c.Name) {
			t.Errorf("catalog entry %s unknown", c.Name)
		}
	}
}
