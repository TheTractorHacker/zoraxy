package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// WebhookConfig is one outgoing webhook.
type WebhookConfig struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Secret  string   `json:"secret,omitempty"` // optional HMAC-SHA256 key
	Events  []string `json:"events"`           // empty = all events
	Enabled bool     `json:"enabled"`

	// Template, when set, renders the request body instead of the default Event JSON (see RenderTemplate)
	Template string `json:"template,omitempty"`
}

// Header names of the webhook request
const (
	HeaderSignature = "X-Zoraxy-Signature" // "sha256=<hex hmac of timestamp + '.' + body>", only when a secret is set
	HeaderTimestamp = "X-Zoraxy-Timestamp" // unix seconds, included in the signed material to stop replays
	HeaderEvent     = "X-Zoraxy-Event"
)

// IsBlockedAddr reports addresses an SSRF-safe webhook must not connect to: loopback, private (RFC1918, ULA),
// link-local (incl. cloud metadata 169.254.169.254), unspecified, multicast and CGNAT.
func IsBlockedAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 100 && b[1]&0xc0 == 64 { // 100.64.0.0/10 carrier grade NAT
			return true
		}
		if b[0] == 0 || b[0] >= 240 { // "this network", reserved
			return true
		}
	}
	return false
}

// ValidateWebhookURL checks scheme and host syntax. Literal blocked IPs are refused here as well (the
// connection-time check in the dialer is the real defence, this gives fast feedback in the UI).
func ValidateWebhookURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return errors.New("invalid webhook URL")
	}
	if u.User != nil {
		return errors.New("credentials in the webhook URL are not allowed")
	}
	if u.Scheme != "https" && !(allowPrivate && u.Scheme == "http") {
		return errors.New("webhook URL must use https")
	}
	if !allowPrivate {
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && IsBlockedAddr(ip) {
			return errors.New("webhook target is a private, loopback or link-local address")
		}
		if strings.EqualFold(u.Hostname(), "localhost") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".localhost") {
			return errors.New("webhook target is a private, loopback or link-local address")
		}
	}
	return nil
}

// WebhookSink delivers events to one webhook with retries.
type WebhookSink struct {
	Cfg WebhookConfig

	// AllowPrivate disables the SSRF guard (admin toggle "allow private targets")
	AllowPrivate bool
	// Offline, when it returns true, suppresses delivery (offline mode)
	Offline func() bool

	// Attempts and Backoff control retries: Attempts total tries, Backoff*4^n between them
	Attempts       int
	Backoff        time.Duration
	RequestTimeout time.Duration

	// test seams
	tlsConfig *tls.Config
	dialer    func(ctx context.Context, network, address string) (net.Conn, error)
}

func (s *WebhookSink) Name() string { return "webhook:" + s.Cfg.Name }

func (s *WebhookSink) Wants(eventType string) bool {
	if !s.Cfg.Enabled {
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

// ssrfControl runs after DNS resolution, right before connect(2), on the actual address, which defeats DNS
// rebinding and hostnames that resolve to internal addresses.
func ssrfControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("refusing to connect to %q", address)
	}
	if IsBlockedAddr(ip) {
		return fmt.Errorf("refusing to connect to private, loopback or link-local address %s", ip)
	}
	return nil
}

func (s *WebhookSink) client() *http.Client {
	timeout := s.RequestTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	if !s.AllowPrivate {
		d.Control = ssrfControl
	}
	dial := d.DialContext
	if s.dialer != nil {
		dial = s.dialer
	}
	tr := &http.Transport{
		DialContext:           dial,
		TLSClientConfig:       s.tlsConfig,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		Proxy:                 nil, // never route through an environment proxy: it would bypass the address check
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// Redirects could point to an internal host; the receiver must answer directly
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Sign returns the signature header value for a request body.
func Sign(secret string, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (s *WebhookSink) Deliver(ctx context.Context, ev Event) error {
	if s.Offline != nil && s.Offline() {
		return errors.New("offline mode: webhook not sent")
	}
	if err := ValidateWebhookURL(s.Cfg.URL, s.AllowPrivate); err != nil {
		return err
	}
	var body []byte
	var err error
	if s.Cfg.Template != "" {
		body, err = RenderTemplate(s.Cfg.Template, ev)
	} else {
		body, err = json.Marshal(ev)
	}
	if err != nil {
		return err
	}
	attempts := s.Attempts
	if attempts <= 0 {
		attempts = 4
	}
	backoff := s.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	client := s.client()
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w (last error: %v)", ctx.Err(), lastErr)
			case <-time.After(backoff):
			}
			backoff *= 4
		}
		lastErr = s.post(ctx, client, ev.Event, body)
		if lastErr == nil {
			return nil
		}
		var perm *permanentError
		if errors.As(lastErr, &perm) {
			return lastErr
		}
	}
	return lastErr
}

type permanentError struct{ error }

func (s *WebhookSink) post(ctx context.Context, client *http.Client, eventName string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(s.Cfg.URL), bytes.NewReader(body))
	if err != nil {
		return &permanentError{err}
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Zoraxy-Webhook")
	req.Header.Set(HeaderEvent, eventName)
	req.Header.Set(HeaderTimestamp, ts)
	if s.Cfg.Secret != "" {
		req.Header.Set(HeaderSignature, Sign(s.Cfg.Secret, ts, body))
	}
	resp, err := client.Do(req)
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
		return fmt.Errorf("receiver answered HTTP %d", resp.StatusCode)
	default:
		return &permanentError{fmt.Errorf("receiver answered HTTP %d", resp.StatusCode)}
	}
}
