package dynamicproxy

import (
	"net/http"
	"testing"
	"time"
)

func TestValidateHttpListenAddr(t *testing.T) {
	cases := []struct {
		addr, admin string
		proxy       int
		ok          bool
	}{
		{"", ":8000", 443, true},
		{":80", ":8000", 443, true},
		{":8080", ":8000", 443, true},
		{"127.0.0.1:8080", ":8000", 443, true},
		{"[::1]:8080", ":8000", 443, true},
		{"localhost:8080", "", 443, true},
		{":0", ":8000", 443, false},
		{":65536", ":8000", 443, false},
		{":-1", ":8000", 443, false},
		{":abc", ":8000", 443, false},
		{"8080", ":8000", 443, false},
		{"example.com:80", ":8000", 443, false},
		{"127.0.0.1", ":8000", 443, false},
		{":8000", ":8000", 443, false},                  //admin UI, wildcard
		{"127.0.0.1:8000", ":8000", 443, false},         //admin UI wildcard overlaps
		{"127.0.0.2:8000", "127.0.0.1:8000", 443, true}, //different host, same port
		{"127.0.0.1:8000", "127.0.0.1:8000", 443, false},
		{":443", ":8000", 443, false}, //proxy port
		{"10.0.0.1:443", ":8000", 443, false},
	}
	for _, c := range cases {
		err := ValidateHttpListenAddr(c.addr, c.admin, c.proxy)
		if (err == nil) != c.ok {
			t.Errorf("addr=%q admin=%q proxy=%d: ok=%v err=%v", c.addr, c.admin, c.proxy, c.ok, err)
		}
	}
}

func TestHttpListenAddrDefaultsAndFallback(t *testing.T) {
	r := &Router{Option: &RouterOption{}}
	if r.HttpListenAddr() != ":80" || r.HttpListenPort() != 80 {
		t.Fatalf("default should be :80, got %q %d", r.HttpListenAddr(), r.HttpListenPort())
	}
	r.Option.HttpListenAddr = "garbage"
	if r.HttpListenAddr() != ":80" || r.HttpListenPort() != 80 {
		t.Fatal("invalid value must fall back to :80")
	}
	r.Option.HttpListenAddr = "127.0.0.1:8081"
	if r.HttpListenAddr() != "127.0.0.1:8081" || r.HttpListenPort() != 8081 {
		t.Fatal("configured value not used")
	}
}

func TestHttpListenerBindsConfiguredAddr(t *testing.T) {
	router, sep, _ := newNonTLSTestRouter(t)
	router.ProxyEndpoints.Store("app.example.com", sep)
	router.Option.ForceHttpsRedirect = true
	router.Option.Port = 8443
	router.Option.ListenOnPort80 = true
	router.Option.HttpListenAddr = "127.0.0.1:0"

	router.startHttpListener()
	if router.tlsRedirectStop == nil || router.BoundHttpAddr() == "" {
		t.Fatal("listener did not start")
	}
	defer func() { router.tlsRedirectStop <- true; time.Sleep(50 * time.Millisecond) }()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", "http://"+router.BoundHttpAddr()+"/x?y=1", nil)
	req.Host = "app.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != "https://app.example.com:8443/x?y=1" {
		t.Fatalf("unexpected response %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestHttpListenerBindFailureDisablesListener(t *testing.T) {
	router, _, _ := newNonTLSTestRouter(t)
	router.Option.ListenOnPort80 = true
	router.Option.HttpListenAddr = "127.0.0.1:0"
	router.startHttpListener()
	defer func() { router.tlsRedirectStop <- true; time.Sleep(50 * time.Millisecond) }()

	// A second router asked to bind the exact busy address must disable itself, not panic
	other, _, _ := newNonTLSTestRouter(t)
	other.Option.ListenOnPort80 = true
	other.Option.HttpListenAddr = router.BoundHttpAddr()
	other.startHttpListener()
	if other.Option.ListenOnPort80 || other.tlsRedirectStop != nil {
		t.Fatal("bind failure should disable the plain HTTP listener")
	}
}
