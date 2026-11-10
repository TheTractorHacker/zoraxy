package aiassist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCheckIP(t *testing.T) {
	always := []string{"169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "168.63.129.16", "0.0.0.0", "224.0.0.1", "::ffff:169.254.169.254", "0.1.2.3", "255.255.255.255"}
	local := []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "fd12::1", "100.64.0.1"}
	public := []string{"8.8.8.8", "160.79.104.10", "2606:4700::1111"}
	for _, a := range always {
		for _, allow := range []bool{false, true} {
			if checkIP(netip.MustParseAddr(a), allow) == nil {
				t.Errorf("%s must always be refused (allowLocal=%v)", a, allow)
			}
		}
	}
	for _, a := range local {
		if checkIP(netip.MustParseAddr(a), false) == nil {
			t.Errorf("%s must be refused without the local option", a)
		}
		if err := checkIP(netip.MustParseAddr(a), true); err != nil {
			t.Errorf("%s allowed with local option: %v", a, err)
		}
	}
	for _, a := range public {
		if err := checkIP(netip.MustParseAddr(a), false); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
}

func TestParseEndpoint(t *testing.T) {
	bad := []struct {
		u, prov string
		local   bool
	}{
		{"http://api.example.com", ProviderAnthropic, false},
		{"http://api.example.com", ProviderOpenAICompatible, false},
		{"http://127.0.0.1:11434/v1", ProviderAnthropic, true},
		{"http://127.0.0.1:11434/v1", ProviderOpenAICompatible, false},
		{"https://169.254.169.254/latest", ProviderOpenAICompatible, true},
		{"https://127.0.0.1", ProviderAnthropic, false},
		{"https://user:pw@api.example.com", ProviderAnthropic, false},
		{"ftp://x.example.com", ProviderAnthropic, false},
		{"https://api.example.com/?a=b", ProviderAnthropic, false},
		{"api.example.com", ProviderAnthropic, false},
	}
	for _, c := range bad {
		if _, err := ParseEndpoint(c.u, c.prov, c.local); err == nil {
			t.Errorf("%s (%s local=%v) accepted", c.u, c.prov, c.local)
		}
	}
	good := []struct {
		u, prov string
		local   bool
	}{
		{"https://api.anthropic.com", ProviderAnthropic, false},
		{"http://127.0.0.1:11434/v1", ProviderOpenAICompatible, true},
		{"http://192.168.1.20:1234/v1", ProviderOpenAICompatible, true},
		{"https://llm.example.com/v1", ProviderOpenAICompatible, false},
	}
	for _, c := range good {
		if _, err := ParseEndpoint(c.u, c.prov, c.local); err != nil {
			t.Errorf("%s: %v", c.u, err)
		}
	}
}

func get(t *testing.T, hc *http.Client, url string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func TestGuardedClientRefusesPrivateAndMetadataTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	// loopback test server: refused without the local option, reachable with it
	if err := get(t, newGuardedClient(false, 5*time.Second), srv.URL); err == nil {
		t.Fatal("loopback reachable without the local option")
	}
	if err := get(t, newGuardedClient(true, 5*time.Second), srv.URL); err != nil {
		t.Fatalf("loopback with local option: %v", err)
	}
	// metadata is refused even with the local option
	if err := get(t, newGuardedClient(true, 5*time.Second), "http://169.254.169.254/latest/meta-data/"); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("metadata: %v", err)
	}
	if err := get(t, newGuardedClient(true, 5*time.Second), "http://[fe80::1]/"); err == nil {
		t.Fatal("link-local reachable")
	}
}

func TestGuardedClientDNSNames(t *testing.T) {
	old := lookupIP
	defer func() { lookupIP = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	port := srv.Listener.Addr().(interface{ String() string }).String()
	port = port[strings.LastIndex(port, ":"):]

	lookupIP = func(ctx context.Context, h string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}
	if err := get(t, newGuardedClient(false, 3*time.Second), "http://internal.example.com"+port); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("name resolving to a private range: %v", err)
	}
	// a mixed answer (one public, one metadata) is refused as a whole
	lookupIP = func(ctx context.Context, h string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("169.254.169.254")}, nil
	}
	if err := get(t, newGuardedClient(true, 3*time.Second), "http://rebind.example.com"+port); err == nil {
		t.Fatal("mixed answer accepted")
	}
	// local option lets a name that resolves to loopback through
	lookupIP = func(ctx context.Context, h string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if err := get(t, newGuardedClient(true, 3*time.Second), "http://llm.lan"+port); err != nil {
		t.Fatalf("local name: %v", err)
	}
}

func TestGuardedClientDoesNotFollowRedirects(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()
	hc := newGuardedClient(true, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL, strings.NewReader("{}"))
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || hit {
		t.Fatalf("redirect followed: %d hit=%v", resp.StatusCode, hit)
	}
	// and the provider layer reports it as an error
	_, status, err := doJSON(ctx, hc, srv.URL, nil, map[string]string{"a": "b"})
	if err == nil || status != 302 {
		t.Fatalf("doJSON: %d %v", status, err)
	}
}
