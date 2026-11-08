package notify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsBlockedAddr(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.169.254", "fe80::1", "fd00::1",
		"0.0.0.0", "100.64.0.1", "::ffff:127.0.0.1", "224.0.0.1", "255.255.255.255"}
	for _, s := range blocked {
		if !IsBlockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "93.184.216.34"} {
		if IsBlockedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestValidateWebhookURL(t *testing.T) {
	bad := []string{"", "ftp://example.com/x", "http://example.com/x", "https://user:pw@example.com/", "https://127.0.0.1/x",
		"https://[::1]/x", "https://169.254.169.254/latest", "https://localhost/x", "https://foo.localhost/x", "not a url"}
	for _, u := range bad {
		if ValidateWebhookURL(u, false) == nil {
			t.Errorf("%q must be rejected", u)
		}
	}
	if err := ValidateWebhookURL("https://hooks.example.com/abc", false); err != nil {
		t.Errorf("valid URL rejected: %v", err)
	}
	if err := ValidateWebhookURL("http://127.0.0.1:8080/x", true); err != nil {
		t.Errorf("allow-private must permit http loopback: %v", err)
	}
}

// newReceiver starts a TLS receiver on loopback. Because loopback is a blocked target, it also proves
// the SSRF guard: delivery must fail unless AllowPrivate is set.
func newReceiver(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *tls.Config) {
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, &tls.Config{RootCAs: pool}
}

func TestWebhookRefusesLoopbackByDefault(t *testing.T) {
	var hits int32
	srv, cfg := newReceiver(t, func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1) })
	s := &WebhookSink{Cfg: WebhookConfig{Name: "t", URL: srv.URL, Enabled: true}, tlsConfig: cfg, Attempts: 1}
	err := s.Deliver(context.Background(), Event{Event: EventTest})
	if err == nil || atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("loopback target must be refused without the toggle (err=%v hits=%d)", err, hits)
	}
}

// DNS names that resolve to blocked addresses are caught at connect time, not only on literal IPs.
func TestWebhookSSRFGuardAppliesAtDialTime(t *testing.T) {
	if err := ssrfControl("tcp", "127.0.0.1:443", nil); err == nil {
		t.Fatal("dial-time guard must refuse loopback")
	}
	if err := ssrfControl("tcp", "[fd12::1]:443", nil); err == nil {
		t.Fatal("dial-time guard must refuse ULA")
	}
	if err := ssrfControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("public address refused: %v", err)
	}
}

func TestWebhookDeliveryRetrySignatureAndRedirect(t *testing.T) {
	var calls int32
	var gotSig, gotTS, gotBody string
	srv, cfg := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		b, _ := io.ReadAll(r.Body)
		gotBody, gotSig, gotTS = string(b), r.Header.Get(HeaderSignature), r.Header.Get(HeaderTimestamp)
		w.WriteHeader(204)
	})
	s := &WebhookSink{
		Cfg:          WebhookConfig{Name: "t", URL: srv.URL, Secret: "k3y", Enabled: true},
		AllowPrivate: true, tlsConfig: cfg, Attempts: 4, Backoff: time.Millisecond,
	}
	exp := time.Now().Add(48 * time.Hour).UTC()
	ev := Event{Event: EventCertIssued, Source: "certificate", Domains: []string{"a.example"}, Expiry: &exp, CA: "Let's Encrypt"}
	if err := s.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("expected 2 retries then success, calls=%d", calls)
	}
	if gotSig != Sign("k3y", gotTS, []byte(gotBody)) || !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("bad signature %q", gotSig)
	}
	var decoded Event
	if err := json.Unmarshal([]byte(gotBody), &decoded); err != nil || decoded.Event != EventCertIssued || decoded.Domains[0] != "a.example" || decoded.CA != "Let's Encrypt" {
		t.Fatalf("bad payload %s (%v)", gotBody, err)
	}

	// 4xx is permanent: no retry
	atomic.StoreInt32(&calls, 0)
	srv2, cfg2 := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "nope", 400)
	})
	s2 := &WebhookSink{Cfg: WebhookConfig{Name: "t", URL: srv2.URL, Enabled: true}, AllowPrivate: true, tlsConfig: cfg2, Attempts: 4, Backoff: time.Millisecond}
	if err := s2.Deliver(context.Background(), ev); err == nil || calls != 1 {
		t.Fatalf("4xx must fail without retry (err=%v calls=%d)", err, calls)
	}

	// redirects are not followed
	atomic.StoreInt32(&calls, 0)
	srv3, cfg3 := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			atomic.AddInt32(&calls, 100)
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	s3 := &WebhookSink{Cfg: WebhookConfig{Name: "t", URL: srv3.URL, Enabled: true}, AllowPrivate: true, tlsConfig: cfg3, Attempts: 1}
	if err := s3.Deliver(context.Background(), ev); err == nil || calls >= 100 {
		t.Fatalf("redirect must not be followed (err=%v)", err)
	}
}

func TestWebhookOfflineAndTimeout(t *testing.T) {
	s := &WebhookSink{Cfg: WebhookConfig{URL: "https://hooks.example.com/x", Enabled: true}, Offline: func() bool { return true }}
	dialed := false
	s.dialer = func(ctx context.Context, n, a string) (c net.Conn, err error) { dialed = true; return nil, io.EOF }
	if err := s.Deliver(context.Background(), Event{Event: EventTest}); err == nil || dialed {
		t.Fatalf("offline mode must not dial (err=%v dialed=%v)", err, dialed)
	}

	slow, cfg := newReceiver(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(500 * time.Millisecond) })
	s = &WebhookSink{Cfg: WebhookConfig{URL: slow.URL, Enabled: true}, AllowPrivate: true, tlsConfig: cfg, Attempts: 1, RequestTimeout: 50 * time.Millisecond}
	start := time.Now()
	if err := s.Deliver(context.Background(), Event{Event: EventTest}); err == nil || time.Since(start) > 400*time.Millisecond {
		t.Fatalf("request timeout not enforced: %v", err)
	}
}

func writeScript(t *testing.T, dir, body string) string {
	p := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCommandHookDisabledByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	script := writeScript(t, dir, "touch "+marker+"\n")
	s := &CommandSink{Cfg: CommandConfig{Enabled: true, Path: script}, Allowed: false}
	if s.Wants(EventCertIssued) {
		t.Fatal("a sink without -allow_hook_commands must not want events")
	}
	if _, err := s.Run(context.Background(), Event{Event: EventCertIssued}); err == nil {
		t.Fatal("Run must refuse when not allowed")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran although disabled")
	}
	m, _ := NewManager(filepath.Join(dir, "n.json"), false, nil, nil)
	if err := m.SetCommand(CommandConfig{Enabled: true, Path: script}); err == nil {
		t.Fatal("configuring a command without the flag must be refused")
	}
}

func TestCommandHookEnvNoShellTimeoutAndOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test")
	}
	dir := t.TempDir()
	t.Setenv("ZORAXY_TEST_PARENT_SECRET", "leak")
	script := writeScript(t, dir, `echo "event=$ZORAXY_EVENT domains=$ZORAXY_DOMAINS arg=$1 secret=[$ZORAXY_TEST_PARENT_SECRET]"`+"\n")
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s := &CommandSink{Cfg: CommandConfig{Enabled: true, Path: script, Args: []string{"$(touch " + filepath.Join(dir, "pwned") + ")"}}, Allowed: true}
	out, err := s.Run(context.Background(), Event{Event: EventCertIssued, Domains: []string{"a.example", "b.example"}, Expiry: &exp})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "event=certificate.issued domains=a.example,b.example") || !strings.Contains(out, "secret=[]") {
		t.Fatalf("unexpected output %q", out)
	}
	if !strings.Contains(out, "arg=$(touch") {
		t.Fatalf("args must be passed literally, got %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Fatal("shell expansion happened")
	}

	// timeout
	slow := writeScript(t, t.TempDir(), "sleep 5\n")
	s = &CommandSink{Cfg: CommandConfig{Enabled: true, Path: slow, Timeout: 1}, Allowed: true}
	start := time.Now()
	if _, err := s.Run(context.Background(), Event{Event: EventTest}); err == nil || time.Since(start) > 4*time.Second {
		t.Fatalf("timeout not enforced: %v", err)
	}

	// output cap
	big := writeScript(t, t.TempDir(), "yes x | head -c 100000\n")
	s = &CommandSink{Cfg: CommandConfig{Enabled: true, Path: big}, Allowed: true}
	out, _ = s.Run(context.Background(), Event{Event: EventTest})
	if len(out) > MaxCommandOutput {
		t.Fatalf("output not capped: %d", len(out))
	}

	// relative path rejected
	if ValidateCommandPath("hook.sh") == nil {
		t.Fatal("relative command path must be rejected")
	}
}

func TestDispatcherFiltersAndIsAsync(t *testing.T) {
	var got int32
	sink := &fnSink{wants: func(e string) bool { return e == EventCertIssued }, fn: func(Event) error {
		time.Sleep(100 * time.Millisecond)
		atomic.AddInt32(&got, 1)
		return nil
	}}
	d := NewDispatcher(func() []Sink { return []Sink{sink} })
	start := time.Now()
	d.Emit(Event{Event: EventCertIssued})
	d.Emit(Event{Event: EventCertExpiring})
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("Emit must not block on slow sinks")
	}
	d.Wait()
	if got != 1 {
		t.Fatalf("filter failed, delivered %d", got)
	}
}

type fnSink struct {
	wants func(string) bool
	fn    func(Event) error
}

func (f *fnSink) Name() string                             { return "fn" }
func (f *fnSink) Wants(e string) bool                      { return f.wants(e) }
func (f *fnSink) Deliver(_ context.Context, e Event) error { return f.fn(e) }

func TestManagerConfigRoundTripMasksSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.json")
	m, err := NewManager(path, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := m.SaveWebhook(WebhookConfig{Name: "ops", URL: "https://hooks.example.com/a", Secret: "topsecret", Enabled: true, Events: []string{EventCertIssued}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SaveWebhook(WebhookConfig{Name: "bad", URL: "https://10.0.0.5/x"}); err == nil {
		t.Fatal("private literal must be refused")
	}
	if _, err := m.SaveWebhook(WebhookConfig{Name: "bad", URL: "https://hooks.example.com/a", Events: []string{"nope"}}); err == nil {
		t.Fatal("unknown event must be refused")
	}
	js, _ := json.Marshal(m.View())
	if strings.Contains(string(js), "topsecret") {
		t.Fatalf("secret leaked: %s", js)
	}
	// masked update keeps the secret
	if _, err := m.SaveWebhook(WebhookConfig{ID: id, Name: "ops2", URL: "https://hooks.example.com/a", Secret: SecretMask, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m2, _ := NewManager(path, false, nil, nil)
	if m2.cfg.Webhooks[0].Secret != "topsecret" || m2.cfg.Webhooks[0].Name != "ops2" {
		t.Fatalf("not persisted: %+v", m2.cfg.Webhooks[0])
	}
	if st, _ := os.Stat(path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("config must be 0600, is %v", st.Mode().Perm())
	}
	if err := m2.DeleteWebhook(id); err != nil {
		t.Fatal(err)
	}
}

func makeCertPair(t *testing.T, dir, name string, notAfter time.Time) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name + ".example"},
		DNSNames: []string{name + ".example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	os.WriteFile(filepath.Join(dir, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(filepath.Join(dir, name+".key"), []byte("k"), 0o600)
}

func TestExpiryWatcher(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	makeCertPair(t, dir, "soon", now.Add(5*24*time.Hour))
	makeCertPair(t, dir, "later", now.Add(90*24*time.Hour))
	makeCertPair(t, dir, "gone", now.Add(-24*time.Hour))
	var evs []Event
	w := &ExpiryWatcher{CertDir: dir, WarnDays: func() int { return 14 }, Emit: func(e Event) { evs = append(evs, e) }, Now: func() time.Time { return now }}
	if n := w.CheckOnce(); n != 2 {
		t.Fatalf("expected soon + expired, got %d: %+v", n, evs)
	}
	for _, e := range evs {
		if e.Event != EventCertExpiring || e.Expiry == nil || e.DaysLeft == nil || len(e.Domains) == 0 {
			t.Fatalf("bad event %+v", e)
		}
	}
	if n := w.CheckOnce(); n != 0 {
		t.Fatalf("must not repeat within 24h, got %d", n)
	}
	now = now.Add(25 * time.Hour)
	if n := w.CheckOnce(); n != 2 {
		t.Fatalf("must repeat after 24h, got %d", n)
	}
}
