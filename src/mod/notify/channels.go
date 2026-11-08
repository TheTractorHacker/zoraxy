package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/email"
)

/*
	Notification channels

	A channel is a named destination of a given type (Discord, Slack, Telegram, ntfy,
	Gotify, Pushover, SMTP) plus its subscriptions. All HTTP channels go through the same
	SSRF-safe client as the generic webhook (webhook.go): connect-time address check,
	no redirects, no environment proxy. A channel can only reach private, loopback or
	link-local addresses (or use plain http) when its own "allowPrivate" toggle is set.

	Secrets (bot tokens, webhook URLs that embed a secret, passwords) live in
	ChannelConfig.Settings, are masked in every API response, and are scrubbed from
	error messages before they reach the delivery log or the system log.
*/

// Channel types
const (
	ChanDiscord  = "discord"
	ChanSlack    = "slack"
	ChanTelegram = "telegram"
	ChanNtfy     = "ntfy"
	ChanGotify   = "gotify"
	ChanPushover = "pushover"
	ChanSMTP     = "smtp"
)

// ChannelConfig is one configured channel (persisted in notify.json, mode 0600)
type ChannelConfig struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Enabled      bool              `json:"enabled"`
	Events       []string          `json:"events"`      // subscriptions; empty = every event
	MinSeverity  string            `json:"minSeverity"` // "", info, warning, critical
	AllowPrivate bool              `json:"allowPrivate"`
	Settings     map[string]string `json:"settings"`
}

type fieldSpec struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret,omitempty"`
	Required bool   `json:"required,omitempty"`
	Hint     string `json:"hint,omitempty"`
}

// ChannelTypes describes the settings of every channel type (served to the UI)
var ChannelTypes = map[string][]fieldSpec{
	ChanDiscord:  {{"url", "Webhook URL", true, true, "https://discord.com/api/webhooks/..."}},
	ChanSlack:    {{"url", "Incoming webhook URL", true, true, "https://hooks.slack.com/services/..."}},
	ChanTelegram: {{"token", "Bot token", true, true, ""}, {"chat_id", "Chat ID", false, true, ""}},
	ChanNtfy:     {{"server", "Server URL", false, false, "https://ntfy.sh (default)"}, {"topic", "Topic", false, true, ""}, {"token", "Access token (optional)", true, false, ""}},
	ChanGotify:   {{"server", "Server URL", false, true, "https://gotify.example.com"}, {"token", "Application token", true, true, ""}},
	ChanPushover: {{"token", "Application token", true, true, ""}, {"user", "User key", true, true, ""}},
	ChanSMTP: {{"host", "SMTP host", false, true, ""}, {"port", "Port", false, true, "587"}, {"username", "Username", false, false, ""},
		{"password", "Password", true, false, ""}, {"from", "From address", false, true, ""}, {"to", "Recipients (comma separated)", false, true, ""}},
}

func (c *ChannelConfig) secretKeys() map[string]bool {
	out := map[string]bool{}
	for _, f := range ChannelTypes[c.Type] {
		if f.Secret {
			out[f.Key] = true
		}
	}
	return out
}

// Masked returns a copy with secret settings replaced by SecretMask
func (c ChannelConfig) Masked() ChannelConfig {
	out := c
	out.Settings = map[string]string{}
	sec := c.secretKeys()
	for k, v := range c.Settings {
		if sec[k] && v != "" {
			v = SecretMask
		}
		out.Settings[k] = v
	}
	return out
}

// secrets lists the secret values (and URLs embedding them) of a channel for error scrubbing
func (c ChannelConfig) secrets() []string {
	var out []string
	for k := range c.secretKeys() {
		if v := c.Settings[k]; v != "" {
			out = append(out, v)
			if u, err := url.Parse(v); err == nil && u.Path != "" && len(u.Path) > 8 {
				out = append(out, u.Path)
			}
		}
	}
	return out
}

func scrub(msg string, secrets []string) string {
	for _, s := range secrets {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	return msg
}

// Validate checks a channel; allowPrivate is the channel's own toggle
func (c *ChannelConfig) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || len(c.Name) > 64 {
		return errors.New("name is required (max 64 characters)")
	}
	specs, ok := ChannelTypes[c.Type]
	if !ok {
		return errors.New("unknown channel type")
	}
	if c.Settings == nil {
		c.Settings = map[string]string{}
	}
	known := map[string]bool{}
	for _, f := range specs {
		known[f.Key] = true
		v := strings.TrimSpace(c.Settings[f.Key])
		if len(v) > 1024 {
			return errors.New(f.Label + " is too long")
		}
		if f.Required && v == "" {
			return errors.New(f.Label + " is required")
		}
		c.Settings[f.Key] = v
	}
	for k := range c.Settings {
		if !known[k] {
			delete(c.Settings, k)
		}
	}
	for _, e := range c.Events {
		if !IsKnownEvent(e) {
			return errors.New("unknown event " + e)
		}
	}
	switch c.MinSeverity {
	case "", SevInfo, SevWarning, SevCritical:
	default:
		return errors.New("invalid minimum severity")
	}
	switch c.Type {
	case ChanDiscord, ChanSlack:
		return ValidateWebhookURL(c.Settings["url"], c.AllowPrivate)
	case ChanNtfy:
		if c.Settings["server"] == "" {
			c.Settings["server"] = "https://ntfy.sh"
		}
		if strings.ContainsAny(c.Settings["topic"], "/?#\\ ") {
			return errors.New("invalid topic")
		}
		return ValidateWebhookURL(c.Settings["server"], c.AllowPrivate)
	case ChanGotify:
		return ValidateWebhookURL(c.Settings["server"], c.AllowPrivate)
	case ChanTelegram:
		if strings.ContainsAny(c.Settings["token"], "/?# ") {
			return errors.New("invalid bot token")
		}
	case ChanSMTP:
		if p, err := strconv.Atoi(c.Settings["port"]); err != nil || p < 1 || p > 65535 {
			return errors.New("invalid port")
		}
		if strings.ContainsAny(c.Settings["host"], "/ \r\n") {
			return errors.New("invalid host")
		}
		if _, err := mail.ParseAddress(c.Settings["from"]); err != nil {
			return errors.New("invalid from address")
		}
		if len(splitRecipients(c.Settings["to"])) == 0 {
			return errors.New("invalid recipients")
		}
		if !c.AllowPrivate {
			if ip, err := netip.ParseAddr(c.Settings["host"]); err == nil && IsBlockedAddr(ip) {
				return errors.New("SMTP host is a private, loopback or link-local address")
			}
			if h := strings.ToLower(c.Settings["host"]); h == "localhost" || strings.HasSuffix(h, ".localhost") {
				return errors.New("SMTP host is a private, loopback or link-local address")
			}
		}
	}
	return nil
}

func splitRecipients(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if a, err := mail.ParseAddress(p); err == nil {
			out = append(out, a.Address)
		} else {
			return nil
		}
	}
	return out
}

// ChannelSink delivers events to one channel with retry and backoff
type ChannelSink struct {
	Cfg     ChannelConfig
	Offline func() bool

	Attempts       int
	Backoff        time.Duration
	RequestTimeout time.Duration

	// test seams
	tlsConfig   *tls.Config
	dialer      func(ctx context.Context, network, address string) (net.Conn, error)
	apiBase     string // replaces the fixed API host of Telegram / Pushover
	smtpSend    func(c ChannelConfig, to, subject, body string) error
	lookupHost  func(host string) ([]net.IP, error)
	forceNoSSRF bool
}

func (s *ChannelSink) Name() string { return "channel:" + s.Cfg.Name }

func (s *ChannelSink) Wants(eventType string) bool {
	if !s.Cfg.Enabled {
		return false
	}
	if sevRank(SeverityOf(eventType)) < sevRank(s.Cfg.MinSeverity) {
		return false
	}
	if len(s.Cfg.Events) == 0 {
		return true
	}
	for _, e := range s.Cfg.Events {
		if e == eventType {
			return true
		}
	}
	return false
}

func (s *ChannelSink) httpClient() *http.Client {
	ws := &WebhookSink{AllowPrivate: s.Cfg.AllowPrivate, RequestTimeout: s.RequestTimeout, tlsConfig: s.tlsConfig, dialer: s.dialer}
	return ws.client()
}

type chanRequest struct {
	url     string
	headers map[string]string
	body    []byte
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func sevColor(sev string) int {
	switch sev {
	case SevCritical:
		return 0xdb2828
	case SevWarning:
		return 0xf2711c
	}
	return 0x21ba45
}

// build assembles the HTTP request of an HTTP based channel
func (s *ChannelSink) build(ev Event) (*chanRequest, error) {
	set := s.Cfg.Settings
	title, lines := Describe(ev)
	text := plain(ev)
	sev := SeverityOf(ev.Event)
	js := func(v any) []byte { b, _ := json.Marshal(v); return b }
	jsonHdr := map[string]string{"Content-Type": "application/json"}
	switch s.Cfg.Type {
	case ChanDiscord:
		return &chanRequest{url: set["url"], headers: jsonHdr, body: js(map[string]any{
			"username":         "Zoraxy",
			"allowed_mentions": map[string]any{"parse": []string{}},
			"embeds": []any{map[string]any{"title": cleanText(title, 250), "description": cleanText(strings.Join(lines, "\n"), 3500),
				"color": sevColor(sev), "timestamp": ev.Time.UTC().Format(time.RFC3339)}},
		})}, nil
	case ChanSlack:
		return &chanRequest{url: set["url"], headers: jsonHdr, body: js(map[string]any{"text": slackEscape(text)})}, nil
	case ChanTelegram:
		base := "https://api.telegram.org"
		if s.apiBase != "" {
			base = s.apiBase
		}
		return &chanRequest{url: base + "/bot" + set["token"] + "/sendMessage", headers: jsonHdr, body: js(map[string]any{
			"chat_id": set["chat_id"], "text": cleanText(text, 3900), "disable_web_page_preview": true})}, nil
	case ChanNtfy:
		prio := map[string]string{SevCritical: "5", SevWarning: "4", SevInfo: "3"}[sev]
		h := map[string]string{"Title": asciiHeader(title), "Priority": prio, "Tags": sev, "Content-Type": "text/plain; charset=utf-8"}
		if t := set["token"]; t != "" {
			h["Authorization"] = "Bearer " + t
		}
		return &chanRequest{url: strings.TrimRight(set["server"], "/") + "/" + url.PathEscape(set["topic"]), headers: h, body: []byte(cleanText(strings.Join(lines, "\n"), 3900) + "\n")}, nil
	case ChanGotify:
		prio := map[string]int{SevCritical: 8, SevWarning: 5, SevInfo: 2}[sev]
		return &chanRequest{url: strings.TrimRight(set["server"], "/") + "/message", headers: map[string]string{"Content-Type": "application/json", "X-Gotify-Key": set["token"]},
			body: js(map[string]any{"title": cleanText(title, 200), "message": cleanText(strings.Join(lines, "\n")+" ", 3900), "priority": prio})}, nil
	case ChanPushover:
		api := "https://api.pushover.net/1/messages.json"
		if s.apiBase != "" {
			api = s.apiBase + "/1/messages.json"
		}
		prio := "0"
		if sev == SevCritical {
			prio = "1"
		}
		f := url.Values{"token": {set["token"]}, "user": {set["user"]}, "title": {cleanText(title, 250)}, "message": {cleanText(strings.Join(lines, "\n")+" ", 1000)}, "priority": {prio}}
		return &chanRequest{url: api, headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body: []byte(f.Encode())}, nil
	}
	return nil, errors.New("not an HTTP channel")
}

func asciiHeader(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}
	return b.String()
}

func (s *ChannelSink) Deliver(ctx context.Context, ev Event) error {
	if s.Offline != nil && s.Offline() {
		return errors.New("offline mode: notification not sent")
	}
	secrets := s.Cfg.secrets()
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	var err error
	if s.Cfg.Type == ChanSMTP {
		attempts, backoff := s.Attempts, s.Backoff
		if attempts <= 0 {
			attempts = 3
		}
		if backoff <= 0 {
			backoff = 2 * time.Second
		}
		for i := 0; i < attempts; i++ {
			if i > 0 {
				select {
				case <-ctx.Done():
					return errors.New(scrub(ctx.Err().Error()+" (last error: "+err.Error()+")", secrets))
				case <-time.After(backoff):
				}
				backoff *= 4
			}
			if err = s.deliverSMTP(ctx, ev); err == nil || strings.Contains(err.Error(), "refusing to connect") {
				break
			}
		}
	} else {
		err = s.deliverHTTP(ctx, ev)
	}
	if err != nil {
		return errors.New(scrub(err.Error(), secrets))
	}
	return nil
}

func (s *ChannelSink) deliverHTTP(ctx context.Context, ev Event) error {
	req, err := s.build(ev)
	if err != nil {
		return err
	}
	if s.apiBase == "" {
		if err := ValidateWebhookURL(req.url, s.Cfg.AllowPrivate); err != nil {
			return err
		}
	}
	attempts, backoff := s.Attempts, s.Backoff
	if attempts <= 0 {
		attempts = 4
	}
	if backoff <= 0 {
		backoff = time.Second
	}
	client := s.httpClient()
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w (last error: %v)", ctx.Err(), last)
			case <-time.After(backoff):
			}
			backoff *= 4
		}
		last = s.post(ctx, client, req)
		if last == nil {
			return nil
		}
		var perm *permanentError
		if errors.As(last, &perm) {
			return last
		}
	}
	return last
}

func (s *ChannelSink) post(ctx context.Context, client *http.Client, cr *chanRequest) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, cr.url, bytes.NewReader(cr.body))
	if err != nil {
		return &permanentError{errors.New("invalid request")}
	}
	r.Header.Set("User-Agent", "Zoraxy-Notify")
	for k, v := range cr.headers {
		r.Header.Set(k, v)
	}
	resp, err := client.Do(r)
	if err != nil {
		if strings.Contains(err.Error(), "refusing to connect") {
			return &permanentError{err}
		}
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("service answered HTTP %d", resp.StatusCode)
	default:
		return &permanentError{fmt.Errorf("service answered HTTP %d", resp.StatusCode)}
	}
}

// ---- SMTP ----

func crlfFree(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

func (s *ChannelSink) deliverSMTP(ctx context.Context, ev Event) error {
	set := s.Cfg.Settings
	host := set["host"]
	if !s.Cfg.AllowPrivate && !s.forceNoSSRF {
		lookup := s.lookupHost
		if lookup == nil {
			lookup = func(h string) ([]net.IP, error) { return net.LookupIP(h) }
		}
		ips, err := lookup(host)
		if err != nil {
			return errors.New("cannot resolve SMTP host")
		}
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok && IsBlockedAddr(a) {
				return errors.New("refusing to connect to private, loopback or link-local SMTP host")
			}
		}
	}
	title, lines := Describe(ev)
	var b strings.Builder
	b.WriteString("<p>" + html.EscapeString(title) + "</p>")
	for _, l := range lines {
		b.WriteString("<p>" + html.EscapeString(l) + "</p>")
	}
	subject := "[Zoraxy] " + crlfFree(title)
	send := s.smtpSend
	if send == nil {
		send = func(c ChannelConfig, to, subj, body string) error {
			port, _ := strconv.Atoi(c.Settings["port"])
			return email.NewEmailSender(c.Settings["host"], port, c.Settings["username"], c.Settings["password"], c.Settings["from"]).SendEmail(to, subj, body)
		}
	}
	rcpts := splitRecipients(set["to"])
	if len(rcpts) == 0 {
		return errors.New("no valid recipients")
	}
	done := make(chan error, 1)
	go func() {
		var first error
		for _, to := range rcpts {
			if err := send(s.Cfg, crlfFree(to), subject, b.String()); err != nil && first == nil {
				first = err
			}
		}
		done <- first
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
